#!/usr/bin/env python3
"""Bounded loopback frontend for Windows OpenSSH forwarding.

SOCKS/local forwards relay TCP unchanged. HTTP uses one strictly framed request
per client connection; HTTPS CONNECT becomes an opaque, bidirectional tunnel.
No destination is connected directly: HTTP destinations use the existing SSH
SOCKS backends and domain names remain unresolved on this computer.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import json
from pathlib import Path
import re
import signal
import socket
import sys
import time
import urllib.parse


LOOPBACK = '127.0.0.1'
MAX_CLIENTS = 128
HEADER_LIMIT = 65536
LINE_LIMIT = 8192
HEADER_COUNT = 100
BUFFER_SIZE = 32768
HEADER_TIMEOUT = 15
IO_TIMEOUT = 60
IDLE_TIMEOUT = 600
# OpenSSH application channels can legitimately be idle indefinitely (RDP,
# SSH, WebSocket, etc.). Keep these open; bound resources instead of lifetime.
RELAY_IDLE_TIMEOUT = None
CONNECT_TIMEOUT = 2
POOL_TIMEOUT = 8
BACKEND_COOLDOWN = 1
TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
TOKEN_RE = re.compile(TOKEN + rb'\Z')
CHUNK_RE = re.compile(rb'([0-9a-fA-F]{1,16})((?:[ \t]*;[ \t]*' + TOKEN +
                      rb'(?:[ \t]*=[ \t]*(?:' + TOKEN +
                      rb'|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"))?)*)[ \t]*\Z')
HOP_FIELDS = {b'connection', b'proxy-connection', b'keep-alive', b'te',
              b'trailer', b'transfer-encoding', b'upgrade', b'proxy-authorization',
              b'proxy-authenticate', b'proxy-authentication-info'}
CRITICAL_CONNECTION_FIELDS = {b'host', b'content-length', b'transfer-encoding', b'trailer'}


class ProtocolError(Exception):
    def __init__(self, status=400):
        super().__init__('Invalid proxy protocol message')
        self.status = status


class BackendError(Exception):
    pass


class DestinationError(BackendError):
    pass


class ClientBodyError(ProtocolError):
    pass


def ascii_text(value):
    try:
        return value.decode('ascii')
    except UnicodeError:
        raise ProtocolError()


def validate_config(value):
    if not isinstance(value, dict) or set(value) != {'schema', 'id', 'kind', 'listen_port', 'backend_ports'}:
        raise ValueError('Invalid frontend configuration')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Invalid frontend schema')
    if not isinstance(value['id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value['id']):
        raise ValueError('Invalid frontend identifier')
    if value['kind'] not in ('socks', 'http', 'local'):
        raise ValueError('Invalid frontend type')
    ports = value['backend_ports']
    if not isinstance(ports, list) or not 1 <= len(ports) <= 4:
        raise ValueError('Invalid frontend pool')
    all_ports = [value['listen_port']] + ports
    if (any(type(port) is not int or not 1024 <= port <= 65535 for port in all_ports)
            or len(set(all_ports)) != len(all_ports)):
        raise ValueError('Invalid frontend ports')
    return dict(value, backend_ports=list(ports))


def fatal(message):
    print(json.dumps({'component': 'windows-proxy', 'level': 'error', 'msg': message},
                     separators=(',', ':')), flush=True)


async def close_writer(writer):
    if writer is not None:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError, ConnectionError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1)


async def exact(reader, count, timeout=IO_TIMEOUT):
    return await asyncio.wait_for(reader.readexactly(count), timeout=timeout)


async def drain(writer):
    await asyncio.wait_for(writer.drain(), timeout=IO_TIMEOUT)


def parse_headers(lines):
    if len(lines) > HEADER_COUNT:
        raise ProtocolError(431)
    headers = []
    for line in lines:
        if not line or len(line) > LINE_LIMIT or line[:1] in (b' ', b'\t') or b':' not in line:
            raise ProtocolError()
        name, value = line.split(b':', 1)
        if not TOKEN_RE.fullmatch(name):
            raise ProtocolError()
        value = value.strip(b' \t')
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise ProtocolError()
        headers.append((name, value))
    for field in (b'host', b'content-length', b'transfer-encoding'):
        if sum(name.lower() == field for name, _ in headers) > 1:
            raise ProtocolError()
    return headers


def values(headers, field):
    return [value for name, value in headers if name.lower() == field]


def connection_fields(headers):
    fields = set()
    for value in values(headers, b'connection'):
        for token in value.split(b','):
            token = token.strip(b' \t').lower()
            if not TOKEN_RE.fullmatch(token):
                raise ProtocolError()
            fields.add(token)
    if fields & CRITICAL_CONNECTION_FIELDS:
        raise ProtocolError()
    return fields


def framing(headers, version):
    lengths, transfer = values(headers, b'content-length'), values(headers, b'transfer-encoding')
    if lengths and transfer:
        raise ProtocolError()
    if lengths:
        if not re.fullmatch(rb'[0-9]{1,19}', lengths[0]):
            raise ProtocolError()
        count = int(lengths[0])
        if count > 0x7fffffffffffffff:
            raise ProtocolError()
        return 'length', count
    if transfer:
        if version != b'HTTP/1.1' or transfer[0].lower() != b'chunked':
            raise ProtocolError()
        return 'chunked', None
    return 'none', 0


async def read_head(reader, timeout=HEADER_TIMEOUT):
    try:
        operation = reader.readuntil(b'\r\n\r\n')
        raw = await operation if timeout is None else await asyncio.wait_for(operation, timeout)
    except asyncio.LimitOverrunError:
        raise ProtocolError(431)
    except asyncio.IncompleteReadError as error:
        if error.partial:
            raise ProtocolError()
        raise
    if len(raw) > HEADER_LIMIT:
        raise ProtocolError(431)
    lines = raw[:-4].split(b'\r\n')
    if not lines or not lines[0] or len(lines[0]) > LINE_LIMIT:
        raise ProtocolError()
    return lines[0], parse_headers(lines[1:])


def authority(value, default_port=None):
    if (not value or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            or any(char in value for char in '\\/?#@%')):
        raise ProtocolError()
    try:
        parsed = urllib.parse.urlsplit('//' + value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ProtocolError()
    if not host or parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
        raise ProtocolError()
    if ':' in host:
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            raise ProtocolError()
        if not value.startswith('[') or ']' not in value:
            raise ProtocolError()
        suffix = value[value.index(']') + 1:]
        if suffix and not re.fullmatch(r':[0-9]+', suffix):
            raise ProtocolError()
        host = str(address)
    else:
        if '[' in value or ']' in value:
            raise ProtocolError()
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9.])?', host):
            raise ProtocolError()
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
               for label in host.rstrip('.').split('.')):
            raise ProtocolError()
    if port is None:
        if default_port is None or value.endswith(':'):
            raise ProtocolError()
        port = default_port
    if not 1 <= port <= 65535:
        raise ProtocolError()
    canonical = ('[' + host + ']' if ':' in host else host)
    if port != default_port or (value.rsplit(']', 1)[-1].startswith(':') if ':' in host else ':' in value):
        canonical += ':' + str(port)
    return host, port, canonical.encode('ascii')


def request(line, headers):
    parts = line.split(b' ')
    if (len(parts) != 3 or not TOKEN_RE.fullmatch(parts[0]) or len(parts[0]) > 32
            or parts[2] not in (b'HTTP/1.0', b'HTTP/1.1')):
        raise ProtocolError()
    method, target, version = parts
    if (not target or any(byte <= 32 or byte >= 127 for byte in target)
            or b'\\' in target or b'#' in target):
        raise ProtocolError()
    host_headers = values(headers, b'host')
    if version == b'HTTP/1.1' and len(host_headers) != 1:
        raise ProtocolError()
    if host_headers:
        authority(ascii_text(host_headers[0]), 80)
    fields = connection_fields(headers)
    body = framing(headers, version)
    if method == b'CONNECT':
        if body[0] != 'none' or values(headers, b'expect') or values(headers, b'upgrade'):
            raise ProtocolError()
        host, port, _ = authority(target.decode('ascii'))
        return method, host, port, None, body, False
    if values(headers, b'upgrade') or b'upgrade' in fields:
        raise ProtocolError(501)
    if target.startswith(b'/') and not target.startswith(b'//') or target == b'*' and method == b'OPTIONS':
        if not host_headers or b'#' in target or b'\\' in target:
            raise ProtocolError()
        host, port, host_value = authority(ascii_text(host_headers[0]), 80)
        path = target
    else:
        try:
            parsed = urllib.parse.urlsplit(target.decode('ascii'))
        except ValueError:
            raise ProtocolError()
        if parsed.scheme.lower() != 'http' or not parsed.netloc or parsed.fragment:
            raise ProtocolError()
        host, port, host_value = authority(parsed.netloc, 80)
        path = (parsed.path or '/').encode('ascii')
        if parsed.query:
            path += b'?' + parsed.query.encode('ascii')
    expect = values(headers, b'expect')
    if expect and (len(expect) != 1 or expect[0].lower() != b'100-continue'):
        raise ProtocolError(417)
    remove = HOP_FIELDS | fields | {b'host', b'content-length', b'expect'}
    outgoing = [(name, value) for name, value in headers if name.lower() not in remove]
    outgoing.append((b'Host', host_value))
    if body[0] == 'length':
        outgoing.append((b'Content-Length', str(body[1]).encode('ascii')))
    elif body[0] == 'chunked':
        outgoing.append((b'Transfer-Encoding', b'chunked'))
    outgoing.append((b'Connection', b'close'))
    wire = method + b' ' + path + b' HTTP/1.1\r\n'
    wire += b''.join(name + b': ' + value + b'\r\n' for name, value in outgoing) + b'\r\n'
    return method, host, port, wire, body, bool(expect)


async def copy_length(reader, writer, count):
    while count:
        chunk = await asyncio.wait_for(reader.read(min(count, BUFFER_SIZE)), IO_TIMEOUT)
        if not chunk:
            raise asyncio.IncompleteReadError(b'', count)
        writer.write(chunk)
        await drain(writer)
        count -= len(chunk)


async def copy_chunked(reader, writer):
    async def chunk_line():
        try:
            line = await asyncio.wait_for(reader.readuntil(b'\r\n'), IO_TIMEOUT)
        except asyncio.LimitOverrunError:
            raise ProtocolError()
        if len(line) > LINE_LIMIT:
            raise ProtocolError()
        return line

    while True:
        line = await chunk_line()
        match = CHUNK_RE.fullmatch(line[:-2])
        if not match:
            raise ProtocolError()
        size = int(match[1], 16)
        if size > 0x7fffffffffffffff:
            raise ProtocolError()
        if not size:
            trailers, total = [], 0
            while True:
                line = await chunk_line()
                total += len(line)
                if total > HEADER_LIMIT or len(trailers) > HEADER_COUNT or len(line) > LINE_LIMIT:
                    raise ProtocolError()
                if line == b'\r\n':
                    break
                trailers.append(line[:-2])
            parse_headers(trailers)  # Validate, then discard every trailer.
            writer.write(b'0\r\n\r\n')
            await drain(writer)
            return
        writer.write(('%x\r\n' % size).encode('ascii'))
        await drain(writer)
        await copy_length(reader, writer, size)
        if await exact(reader, 2) != b'\r\n':
            raise ProtocolError()
        writer.write(b'\r\n')
        await drain(writer)


async def copy_body(reader, writer, body):
    kind, count = body
    if kind == 'length':
        await copy_length(reader, writer, count)
    elif kind == 'chunked':
        await copy_chunked(reader, writer)


class UploadGuard:
    """Cooperate with cancellation even on older wait_for cancellation races."""
    def __init__(self, stream, stop):
        self.stream, self.stop = stream, stop

    def check(self):
        if self.stop.is_set():
            raise asyncio.CancelledError()

    async def _read(self, method, argument):
        self.check()
        value = await getattr(self.stream, method)(argument)
        self.check()
        return value

    async def read(self, count):
        return await self._read('read', count)

    async def readexactly(self, count):
        return await self._read('readexactly', count)

    async def readuntil(self, separator):
        return await self._read('readuntil', separator)

    def write(self, value):
        self.check()
        self.stream.write(value)

    async def drain(self):
        self.check()
        await self.stream.drain()
        self.check()


async def upload_body(reader, writer, body, stop):
    try:
        await copy_body(UploadGuard(reader, stop), UploadGuard(writer, stop), body)
    except (ProtocolError, asyncio.IncompleteReadError):
        raise ClientBodyError()


async def copy_until_eof(reader, writer):
    while True:
        chunk = await asyncio.wait_for(reader.read(BUFFER_SIZE), IDLE_TIMEOUT)
        if not chunk:
            return
        writer.write(chunk)
        await drain(writer)


async def relay(left_reader, left_writer, right_reader, right_writer):
    activity = [time.monotonic()]

    async def pump(reader, writer):
        while True:
            if RELAY_IDLE_TIMEOUT is None:
                chunk = await reader.read(BUFFER_SIZE)
            else:
                remaining = RELAY_IDLE_TIMEOUT - (time.monotonic() - activity[0])
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                try:
                    chunk = await asyncio.wait_for(reader.read(BUFFER_SIZE), remaining)
                except asyncio.TimeoutError:
                    # One direction can be silent throughout a long download.
                    if time.monotonic() - activity[0] < RELAY_IDLE_TIMEOUT:
                        continue
                    raise
            if not chunk:
                break
            activity[0] = time.monotonic()
            writer.write(chunk)
            await drain(writer)
        if writer.can_write_eof():
            writer.write_eof()
            await drain(writer)

    tasks = [asyncio.create_task(pump(left_reader, right_writer)),
             asyncio.create_task(pump(right_reader, left_writer))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def encode_destination(host, port):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode('ascii')
        if not 1 <= len(raw) <= 255:
            raise BackendError()
        target = b'\x03' + bytes([len(raw)]) + raw
    else:
        target = (b'\x01' if address.version == 4 else b'\x04') + address.packed
    return b'\x05\x01\x00' + target + port.to_bytes(2, 'big')


async def socks_connect(reader, writer, host, port):
    writer.write(b'\x05\x01\x00')
    await drain(writer)
    if await exact(reader, 2, HEADER_TIMEOUT) != b'\x05\x00':
        raise BackendError()
    writer.write(encode_destination(host, port))
    await drain(writer)
    header = await exact(reader, 4, HEADER_TIMEOUT)
    if header[:1] != b'\x05' or header[2:3] != b'\x00':
        raise BackendError()
    if header[1] != 0:
        raise DestinationError()
    if header[3] == 1:
        await exact(reader, 6, HEADER_TIMEOUT)
    elif header[3] == 4:
        await exact(reader, 18, HEADER_TIMEOUT)
    elif header[3] == 3:
        count = (await exact(reader, 1, HEADER_TIMEOUT))[0]
        if not count:
            raise BackendError()
        await exact(reader, count + 2, HEADER_TIMEOUT)
    else:
        raise BackendError()


class ProxyServer:
    def __init__(self, config):
        self.config = validate_config(config)
        self.server = None
        self.tasks = set()
        self.next_backend = 0
        self.cooldown = {}
        self.failed = asyncio.Event()
        self.closing = False

    async def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((LOOPBACK, self.config['listen_port']))
            sock.listen(MAX_CLIENTS)
            sock.setblocking(False)
            self.server = await asyncio.start_server(self._accept, sock=sock, limit=HEADER_LIMIT + LINE_LIMIT)
        except BaseException:
            sock.close()
            raise
        return self

    def _accept(self, reader, writer):
        if self.closing or len(self.tasks) >= MAX_CLIENTS:
            writer.close()
            return
        task = asyncio.create_task(self._client(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def candidates(self):
        ports = self.config['backend_ports']
        index = self.next_backend
        self.next_backend = (index + 1) % len(ports)
        now = time.monotonic()
        return [ports[(index + offset) % len(ports)] for offset in range(len(ports))
                if self.cooldown.get(ports[(index + offset) % len(ports)], 0) <= now]

    async def connect(self, destination=None):
        deadline = time.monotonic() + POOL_TIMEOUT
        for port in self.candidates():
            writer = None
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(LOOPBACK, port, limit=HEADER_LIMIT + LINE_LIMIT),
                    timeout=min(CONNECT_TIMEOUT, remaining))
                if destination:
                    await asyncio.wait_for(socks_connect(reader, writer, *destination),
                                           timeout=max(.01, deadline - time.monotonic()))
                self.cooldown.pop(port, None)
                return reader, writer
            except DestinationError:
                # A refused destination says nothing about SSH pool health.
                # Do not suppress healthy sessions or retry a remote policy.
                await close_writer(writer)
                raise
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, BackendError):
                self.cooldown[port] = time.monotonic() + BACKEND_COOLDOWN
                await close_writer(writer)
            except BaseException:
                await close_writer(writer)
                raise
        raise BackendError()

    async def _client(self, reader, writer):
        try:
            if self.config['kind'] == 'http':
                await self.http(reader, writer)
            else:
                await self.raw(reader, writer)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, BackendError, ProtocolError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self.failed.is_set():
                fatal('Local proxy component failed.')
            self.failed.set()
        finally:
            await close_writer(writer)

    async def raw(self, reader, writer):
        # SOCKS always begins with client data; an empty health probe is quiet.
        initial = b''
        if self.config['kind'] == 'socks':
            initial = await asyncio.wait_for(reader.read(BUFFER_SIZE), HEADER_TIMEOUT)
            if not initial:
                return
        remote_reader, remote_writer = await self.connect()
        try:
            if initial:
                remote_writer.write(initial)
                await drain(remote_writer)
            await relay(reader, writer, remote_reader, remote_writer)
        finally:
            await close_writer(remote_writer)

    async def error(self, writer, status):
        labels = {400: 'Bad Request', 417: 'Expectation Failed', 431: 'Request Header Fields Too Large',
                  501: 'Not Implemented', 502: 'Bad Gateway', 504: 'Gateway Timeout'}
        reason = labels.get(status, 'Bad Gateway')
        body = (reason + '\n').encode('ascii')
        writer.write(('HTTP/1.1 %s %s\r\nConnection: close\r\nContent-Length: %s\r\n'
                      'Content-Type: text/plain\r\n\r\n' % (status, reason, len(body))).encode('ascii') + body)
        await drain(writer)

    async def response_head(self, reader, upload):
        head = asyncio.create_task(read_head(reader, timeout=None))
        try:
            done, _ = await asyncio.wait((head, upload), return_when=asyncio.FIRST_COMPLETED)
            if head in done:
                return head.result()
            await upload
            return await asyncio.wait_for(head, IO_TIMEOUT)
        finally:
            if not head.done():
                head.cancel()
            await asyncio.gather(head, return_exceptions=True)

    async def http(self, reader, writer):
        remote_writer = upload = None
        upload_stop = asyncio.Event()
        response_started = False
        request_seen = False
        try:
            line, headers = await read_head(reader, HEADER_TIMEOUT)
            method, host, port, wire, body, expect = request(line, headers)
            request_seen = True
            remote_reader, remote_writer = await self.connect((host, port))
            if method == b'CONNECT':
                response_started = True
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await drain(writer)
                await relay(reader, writer, remote_reader, remote_writer)
                return
            remote_writer.write(wire)
            await drain(remote_writer)
            if expect:
                writer.write(b'HTTP/1.1 100 Continue\r\n\r\n')
                await drain(writer)
            upload = asyncio.create_task(upload_body(reader, remote_writer, body, upload_stop))
            for _ in range(16):
                try:
                    line, headers = await self.response_head(remote_reader, upload)
                    parts = line.split(b' ', 2)
                    if (len(parts) != 3 or parts[0] not in (b'HTTP/1.0', b'HTTP/1.1')
                            or not re.fullmatch(rb'[1-5][0-9]{2}', parts[1])
                            or any(byte < 32 or byte == 127 for byte in line)):
                        raise ProtocolError()
                    status = int(parts[1])
                    fields = connection_fields(headers)
                    response_body = framing(headers, parts[0])
                    if status < 200:
                        if status == 101 or response_body[0] != 'none':
                            raise ProtocolError()
                        if not (status == 100 and expect):
                            informational = [(name, value) for name, value in headers
                                             if name.lower() not in HOP_FIELDS | fields]
                            writer.write(line + b'\r\n' + b''.join(
                                name + b': ' + value + b'\r\n' for name, value in informational) + b'\r\n')
                            await drain(writer)
                        continue
                    if status == 204 and response_body[0] != 'none':
                        raise ProtocolError()
                    if status == 205 and response_body not in (('none', 0), ('length', 0)):
                        raise ProtocolError()
                except ClientBodyError:
                    raise
                except ProtocolError:
                    raise ProtocolError(502)
                break
            else:
                raise ProtocolError(502)
            # A final response can legitimately arrive before a large upload
            # completes. Stop that upload instead of deadlocking on backpressure.
            if not upload.done():
                upload_stop.set()
                upload.cancel()
            await asyncio.gather(upload, return_exceptions=True)
            remove = HOP_FIELDS | fields | {b'content-length'}
            outgoing = [(name, value) for name, value in headers if name.lower() not in remove]
            if response_body[0] == 'length':
                outgoing.append((b'Content-Length', str(response_body[1]).encode('ascii')))
            elif response_body[0] == 'chunked':
                outgoing.append((b'Transfer-Encoding', b'chunked'))
            outgoing.append((b'Connection', b'close'))
            response_started = True
            writer.write(line + b'\r\n' + b''.join(name + b': ' + value + b'\r\n'
                                                   for name, value in outgoing) + b'\r\n')
            await drain(writer)
            if method != b'HEAD' and status not in (204, 205, 304):
                if response_body[0] == 'none':
                    await copy_until_eof(remote_reader, writer)
                else:
                    await copy_body(remote_reader, writer, response_body)
        except ProtocolError as error:
            if not response_started:
                await self.error(writer, error.status)
        except asyncio.IncompleteReadError:
            if request_seen and not response_started:
                await self.error(writer, 502)
        except (BackendError, OSError, asyncio.TimeoutError):
            if not response_started:
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await self.error(writer, 502)
        finally:
            if upload is not None:
                upload_stop.set()
                upload.cancel()
                await asyncio.gather(upload, return_exceptions=True)
            await close_writer(remote_writer)

    async def close(self):
        self.closing = True
        if self.server:
            self.server.close()
        # Modern asyncio servers wait for active transports, not just the
        # listening socket. Retire our handlers first so idle clients cannot
        # delay shutdown until a protocol timeout (or forever for opaque TCP).
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=3)
        if self.server:
            await asyncio.wait_for(self.server.wait_closed(), timeout=3)


async def run(config):
    proxy = ProxyServer(config)
    try:
        await proxy.start()
    except OSError:
        fatal('Local proxy listener could not start.')
        return 1
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: loop.call_soon_threadsafe(stop.set))
    tasks = [asyncio.create_task(stop.wait()), asyncio.create_task(proxy.failed.wait())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await proxy.close()
    return 1 if proxy.failed.is_set() else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        if sys.platform == 'win32':
            from windows_platform import read_private_json
            config = read_private_json(args.config, max_bytes=65536)
        else:
            with args.config.open('rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError()
            config = json.loads(raw)
        config = validate_config(config)
    except Exception:
        fatal('Local proxy configuration is invalid.')
        return 1
    try:
        return asyncio.run(run(config))
    except KeyboardInterrupt:
        return 0
    except Exception:
        fatal('Local proxy component stopped unexpectedly.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
