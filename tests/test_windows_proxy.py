"""Actual loopback protocol tests, with synthetic SOCKS backends and no GOST."""
import asyncio
import contextlib
import copy
import ipaddress
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import windows_proxy as proxy


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class DescriptorTests(unittest.TestCase):
    def test_only_bounded_loopback_descriptor_is_accepted(self):
        valid = dict(schema=1, id='synthetic', kind='http', listen_port=21000, backend_ports=[21001, 21002])
        self.assertEqual(proxy.validate_config(valid), valid)
        for mutation in [dict(schema=True), dict(schema=1.0), dict(kind='udp'), dict(id='../secret'),
                         dict(listen_port=80), dict(listen_port=True), dict(backend_ports=[]),
                         dict(backend_ports=[21000]), dict(backend_ports=[21001, 21001]),
                         dict(backend_ports=[21001] * 5), dict(host='0.0.0.0'), dict(password='secret')]:
            value = copy.deepcopy(valid)
            value.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                proxy.validate_config(value)


class FrontendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers, self.frontends, self.workers = [], [], set()
        self.destinations, self.requests, self.accepts = [], [], []

    async def asyncTearDown(self):
        for frontend in self.frontends:
            await frontend.close()
            self.assertFalse(frontend.failed.is_set(), 'A malformed client must never crash the component')
        for server in self.servers:
            server.close()
        workers = list(self.workers)
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        for server in self.servers:
            await asyncio.wait_for(server.wait_closed(), timeout=3)

    async def wait_until(self, predicate, timeout=3):
        deadline = asyncio.get_running_loop().time() + timeout
        while not predicate():
            if asyncio.get_running_loop().time() >= deadline:
                self.fail('Synthetic listener did not reach the expected state')
            await asyncio.sleep(.005)

    async def server(self, callback):
        def accept(reader, writer):
            async def run():
                try:
                    await callback(reader, writer)
                except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
                    pass
                finally:
                    await proxy.close_writer(writer)
            task = asyncio.create_task(run())
            self.workers.add(task)
            task.add_done_callback(self.workers.discard)
        server = await asyncio.start_server(accept, '127.0.0.1', 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def socks(self, callback, label='backend'):
        async def accept(reader, writer):
            self.accepts.append(label)
            self.assertEqual(await reader.readexactly(3), b'\x05\x01\x00')
            writer.write(b'\x05\x00'); await writer.drain()
            version, command, reserved, atyp = await reader.readexactly(4)
            self.assertEqual((version, command, reserved), (5, 1, 0))
            if atyp == 3:
                count = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(count)).decode('ascii')
            elif atyp in (1, 4):
                host = str(ipaddress.ip_address(await reader.readexactly(4 if atyp == 1 else 16)))
            else:
                raise AssertionError('Invalid destination ATYP')
            port = int.from_bytes(await reader.readexactly(2), 'big')
            self.destinations.append((atyp, host, port))
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'); await writer.drain()
            await callback(reader, writer)
        return await self.server(accept)

    async def frontend(self, kind, backends):
        config = dict(schema=1, id='synthetic', kind=kind, listen_port=free_port(), backend_ports=backends)
        frontend = await proxy.ProxyServer(config).start()
        self.frontends.append(frontend)
        return frontend

    async def exchange(self, frontend, wire, eof=False):
        reader, writer = await asyncio.open_connection('127.0.0.1', frontend.config['listen_port'])
        try:
            writer.write(wire); await writer.drain()
            if eof:
                writer.write_eof()
            return await asyncio.wait_for(reader.read(), timeout=4)
        finally:
            await proxy.close_writer(writer)

    async def origin_ok(self, reader, writer):
        head = await reader.readuntil(b'\r\n\r\n')
        self.requests.append(head)
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n'
                     b'Proxy-Authentication-Info: PRIVATE\r\n\r\nOK')
        await writer.drain()

    async def test_http_rewrites_host_and_strips_proxy_and_connection_fields(self):
        frontend = await self.frontend('http', [await self.socks(self.origin_ok)])
        reply = await self.exchange(frontend,
            b'GET http://remote.invalid:8080/path?q=x HTTP/1.1\r\nHost: incorrect.invalid\r\n'
            b'Proxy-Authorization: Basic PRIVATE\r\nProxy-Connection: keep-alive\r\n'
            b'Proxy-Authentication-Info: PRIVATE\r\n'
            b'Connection: X-Hop\r\nX-Hop: PRIVATE\r\nAuthorization: Bearer end-to-end\r\n\r\n')
        self.assertTrue(reply.endswith(b'\r\n\r\nOK'))
        self.assertIn(b'Connection: close\r\n', reply)
        self.assertNotIn(b'PRIVATE', reply)
        head = self.requests[0]
        self.assertTrue(head.startswith(b'GET /path?q=x HTTP/1.1\r\n'))
        self.assertIn(b'Host: remote.invalid:8080\r\n', head)
        self.assertIn(b'Authorization: Bearer end-to-end\r\n', head)
        self.assertNotIn(b'PRIVATE', head)
        self.assertNotIn(b'Proxy-', head)
        self.assertEqual(self.destinations, [(3, 'remote.invalid', 8080)])

    async def test_content_length_and_pipelining_do_not_leak_second_request(self):
        async def origin(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            body = await reader.readexactly(4)
            self.requests.append(head + body)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'); await writer.drain()
        frontend = await self.frontend('http', [await self.socks(origin)])
        reply = await self.exchange(frontend,
            b'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 4\r\n\r\nDATA'
            b'GET http://secret.invalid/ HTTP/1.1\r\nProxy-Authorization: PRIVATE\r\n\r\n')
        self.assertTrue(reply.endswith(b'OK'))
        self.assertTrue(self.requests[0].endswith(b'\r\n\r\nDATA'))
        self.assertNotIn(b'secret.invalid', self.requests[0])
        self.assertEqual(len(self.destinations), 1)

    async def test_chunked_request_response_and_trailers_have_exact_boundaries(self):
        async def origin(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            body = await reader.readexactly(len(b'3\r\nabc\r\n0\r\n\r\n'))
            self.requests.append(head + body)
            writer.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n\r\n'
                         b'2;test="yes"\r\nOK\r\n0\r\nProxy-Authorization: PRIVATE\r\n\r\nEXTRA')
            await writer.drain()
        frontend = await self.frontend('http', [await self.socks(origin)])
        reply = await self.exchange(frontend,
            b'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nTransfer-Encoding: chunked\r\n'
            b'Trailer: Proxy-Authorization\r\n\r\n3;test=yes\r\nabc\r\n0\r\nProxy-Authorization: PRIVATE\r\n\r\n'
            b'GET /SECOND HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(self.requests[0].endswith(b'3\r\nabc\r\n0\r\n\r\n'))
        self.assertNotIn(b'PRIVATE', self.requests[0] + reply)
        self.assertNotIn(b'Trailer:', self.requests[0] + reply)
        self.assertTrue(reply.endswith(b'2\r\nOK\r\n0\r\n\r\n'))
        self.assertNotIn(b'EXTRA', reply)

    async def test_connect_preserves_prefetched_bytes_and_ipv6_target(self):
        async def echo(reader, writer):
            data = await reader.readexactly(8)
            self.requests.append(data)
            writer.write(data[::-1]); await writer.drain()
        frontend = await self.frontend('http', [await self.socks(echo)])
        reply = await self.exchange(frontend,
            b'CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\nTLSBYTES', eof=True)
        self.assertEqual(reply, b'HTTP/1.1 200 Connection Established\r\n\r\nSETYBSLT')
        self.assertEqual(self.destinations, [(4, '::1', 443)])
        self.assertEqual(self.requests, [b'TLSBYTES'])

    async def test_rejected_headers_and_targets_never_open_backend(self):
        frontend = await self.frontend('http', [await self.socks(self.origin_ok)])
        cases = [
            b'Content-Length: 0\r\nContent-Length: 0\r\n',
            b'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n',
            b'Transfer-Encoding: gzip, chunked\r\n', b'Connection: Content-Length\r\n',
            b'Connection: Host\r\n', b' Header: folded\r\n', b'Bad : value\r\n',
            b'Host: duplicate.invalid\r\n', b'X-Control: bad\x00value\r\n']
        for headers in cases:
            reply = await self.exchange(frontend,
                b'GET http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\n' + headers + b'\r\n')
            self.assertTrue(reply.startswith(b'HTTP/1.1 400'), headers)
        for target in [b'http://user:secret@origin.invalid/', b'http://origin.invalid/#fragment',
                       b'http://origin.invalid/#', b'http://origin.invalid/path\\evil',
                       b'http://origin.invalid\\evil/', b'http://origin%2einvalid/', b'http://[::1/',
                       b'http://[::1]suffix:80/']:
            reply = await self.exchange(frontend, b'GET ' + target + b' HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
            self.assertTrue(reply.startswith(b'HTTP/1.1 400'), target)
        reply = await self.exchange(frontend, b'GET / HTTP/1.1\r\nHost: bad\x80.invalid\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 400'))
        reply = await self.exchange(frontend, b'GET / HTTP/1.1\nHost: origin.invalid\n\n', eof=True)
        self.assertTrue(reply.startswith(b'HTTP/1.1 400'))
        self.assertEqual(self.accepts, [])

    async def test_connect_rejects_body_headers_and_ambiguous_authority(self):
        frontend = await self.frontend('http', [await self.socks(self.origin_ok)])
        for target, extra in [(b'origin.invalid:443', b'Content-Length: 0\r\n'),
                              (b'origin.invalid:443', b'Transfer-Encoding: chunked\r\n'),
                              (b'origin.invalid', b''), (b'origin.invalid:0', b''),
                              (b'[fe80::1%25zone]:443', b''), (b'user@origin.invalid:443', b'')]:
            reply = await self.exchange(frontend, b'CONNECT ' + target + b' HTTP/1.1\r\nHost: origin.invalid\r\n' + extra + b'\r\n')
            self.assertTrue(reply.startswith(b'HTTP/1.1 400'))
        self.assertEqual(self.accepts, [])

    async def test_expect_continue_and_early_final_response_do_not_deadlock(self):
        async def origin(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            self.assertNotIn(b'Expect:', head)
            self.requests.append(await reader.readexactly(6))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'); await writer.drain()
        frontend = await self.frontend('http', [await self.socks(origin)])
        reader, writer = await asyncio.open_connection('127.0.0.1', frontend.config['listen_port'])
        try:
            writer.write(b'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 6\r\nExpect: 100-continue\r\n\r\n'); await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2), b'HTTP/1.1 100 Continue\r\n\r\n')
            writer.write(b'ABCDEF'); await writer.drain()
            self.assertTrue((await asyncio.wait_for(reader.read(), 2)).endswith(b'OK'))
            self.assertEqual(self.requests, [b'ABCDEF'])
        finally:
            await proxy.close_writer(writer)
        async def reject(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n'); await writer.drain()
        other = await self.frontend('http', [await self.socks(reject)])
        reply = await self.exchange(other, b'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 9999999\r\n\r\nsmall')
        self.assertTrue(reply.startswith(b'HTTP/1.1 413'))

    async def test_failover_happens_before_application_bytes_only(self):
        async def failed(reader, writer):
            self.accepts.append('failed-handshake')
            await reader.readexactly(3)
        bad = await self.server(failed)
        good = await self.socks(self.origin_ok, 'good')
        frontend = await self.frontend('http', [bad, good])
        reply = await self.exchange(frontend, b'GET http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(reply.endswith(b'OK'))
        self.assertEqual(self.accepts, ['failed-handshake', 'good'])
        self.accepts.clear()
        async def after_write(reader, writer):
            self.requests.append(await reader.readuntil(b'\r\n\r\n'))
        first = await self.socks(after_write, 'received-request')
        second = await self.socks(self.origin_ok, 'must-not-retry')
        other = await self.frontend('http', [first, second])
        reply = await self.exchange(other, b'POST http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nContent-Length: 0\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 502'))
        self.assertEqual(self.accepts, ['received-request'])

    async def test_response_content_length_and_head_preserve_boundaries(self):
        async def origin(reader, writer):
            head = await reader.readuntil(b'\r\n\r\n')
            if head.startswith(b'HEAD'):
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n')
            else:
                writer.write(b'HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n'
                             b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKPRIVATE-EXTRA')
            await writer.drain()
        frontend = await self.frontend('http', [await self.socks(origin)])
        get = await self.exchange(frontend, b'GET / HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(get.startswith(b'HTTP/1.1 103'))
        self.assertTrue(get.endswith(b'OK'))
        self.assertNotIn(b'PRIVATE-EXTRA', get)
        head = await self.exchange(frontend, b'HEAD / HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(head.endswith(b'Content-Length: 999\r\nConnection: close\r\n\r\n'))

    async def test_raw_tcp_round_robin_server_first_and_half_close(self):
        def handler(label):
            async def callback(reader, writer):
                writer.write(label); await writer.drain()
                data = await reader.read()
                writer.write(data[::-1]); await writer.drain()
            return callback
        ports = [await self.server(handler(b'A')), await self.server(handler(b'B'))]
        frontend = await self.frontend('local', ports)
        for expected in (b'A', b'B', b'A', b'B'):
            reader, writer = await asyncio.open_connection('127.0.0.1', frontend.config['listen_port'])
            try:
                self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 2), expected)
                writer.write(b'data'); await writer.drain(); writer.write_eof()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'atad')
            finally:
                await proxy.close_writer(writer)

    async def test_raw_socks_bytes_large_stream_and_quiet_empty_probe(self):
        async def echo(reader, writer):
            self.accepts.append('raw')
            while True:
                chunk = await reader.read(16384)
                if not chunk:
                    return
                writer.write(chunk); await writer.drain()
        frontend = await self.frontend('socks', [await self.server(echo)])
        self.assertEqual(await self.exchange(frontend, b'', eof=True), b'')
        self.assertEqual(self.accepts, [])
        wire = b'\x04\x01\x00\x50\x7f\x00\x00\x01user\x00' + bytes(range(256)) * 8192
        self.assertEqual(await self.exchange(frontend, wire, eof=True), wire)

    async def test_header_bounds_client_limit_and_shutdown(self):
        frontend = await self.frontend('http', [await self.socks(self.origin_ok)])
        reply = await self.exchange(frontend, b'GET / HTTP/1.1\r\nHost: origin.invalid\r\nX-Large: ' + b'x' * 70000 + b'\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 431'))
        self.assertEqual(self.accepts, [])
        await self.wait_until(lambda: not frontend.tasks)
        clients = []
        try:
            with mock.patch.object(proxy, 'MAX_CLIENTS', 2):
                for _ in range(2):
                    clients.append(await asyncio.open_connection('127.0.0.1', frontend.config['listen_port']))
                await self.wait_until(lambda: len(frontend.tasks) == 2)
                third, third_writer = await asyncio.open_connection('127.0.0.1', frontend.config['listen_port'])
                try:
                    self.assertEqual(await asyncio.wait_for(third.read(), 2), b'')
                    self.assertEqual(len(frontend.tasks), 2)
                finally:
                    await proxy.close_writer(third_writer)
            await asyncio.wait_for(frontend.close(), timeout=3)
            for reader, _writer in clients:
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        finally:
            for _reader, writer in clients:
                await proxy.close_writer(writer)

    async def test_destination_refusal_does_not_poison_a_healthy_ssh_backend(self):
        async def refused(reader, writer):
            await reader.readexactly(3)
            writer.write(b'\x05\x00'); await writer.drain()
            await reader.readexactly(len(proxy.encode_destination('origin.invalid', 80)))
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'); await writer.drain()
        frontend = await self.frontend('http', [await self.server(refused)])
        response = await self.exchange(frontend, b'GET / HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(response.startswith(b'HTTP/1.1 502'))
        self.assertEqual(frontend.cooldown, {})

    async def test_invalid_chunk_and_truncated_response_never_add_an_extra_message(self):
        async def early(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            await reader.read()
        frontend = await self.frontend('http', [await self.socks(early)])
        response = await self.exchange(frontend,
            b'POST / HTTP/1.1\r\nHost: origin.invalid\r\nTransfer-Encoding: chunked\r\n\r\n'
            b'2\r\nOKbad\r\n0\r\n\r\n')
        self.assertTrue(response.startswith(b'HTTP/1.1 400'))
        async def truncated(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nOK'); await writer.drain()
        other = await self.frontend('http', [await self.socks(truncated)])
        response = await self.exchange(other, b'GET / HTTP/1.1\r\nHost: origin.invalid\r\n\r\n')
        self.assertTrue(response.startswith(b'HTTP/1.1 200'))
        self.assertTrue(response.endswith(b'\r\n\r\nOK'))
        self.assertEqual(response.count(b'HTTP/1.1'), 1)

    async def test_http_empty_probe_and_header_timeout_are_quiet(self):
        frontend = await self.frontend('http', [await self.socks(self.origin_ok)])
        self.assertEqual(await self.exchange(frontend, b'', eof=True), b'')
        with mock.patch.object(proxy, 'HEADER_TIMEOUT', .05):
            response = await self.exchange(frontend, b'GET / HTTP/1.1\r\n')
        self.assertTrue(response.startswith(b'HTTP/1.1 502'))
        self.assertEqual(self.accepts, [])

    async def test_response_is_committed_before_a_failed_client_drain(self):
        class Writer:
            def __init__(self, fail=False):
                self.writes, self.fail = [], fail
            def write(self, value):
                self.writes.append(value)
            async def drain(self):
                if self.fail:
                    raise asyncio.TimeoutError()
            def close(self):
                pass
            async def wait_closed(self):
                pass
        for wire in (b'CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid\r\n\r\n',
                     b'GET / HTTP/1.1\r\nHost: origin.invalid\r\n\r\n'):
            frontend = proxy.ProxyServer(dict(schema=1, id='synthetic', kind='http',
                                              listen_port=21000, backend_ports=[21001]))
            client, remote = asyncio.StreamReader(), asyncio.StreamReader()
            client.feed_data(wire); client.feed_eof()
            remote.feed_data(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'); remote.feed_eof()
            writer, remote_writer = Writer(fail=True), Writer()
            frontend.connect = mock.AsyncMock(return_value=(remote, remote_writer))
            await frontend.http(client, writer)
            self.assertEqual(len(writer.writes), 1)
            self.assertTrue(writer.writes[0].startswith(b'HTTP/1.1 200'))

    async def test_one_way_active_download_does_not_expire_the_silent_leg(self):
        connected, begin = asyncio.Event(), asyncio.Event()
        async def download(reader, writer):
            connected.set()
            await begin.wait()
            for _ in range(14):
                writer.write(b'active-download\n'); await writer.drain()
                await asyncio.sleep(.1)
        frontend = await self.frontend('local', [await self.server(download)])
        # Exercise a real silent-leg timeout while activity keeps the shared
        # tunnel alive. A one-second window is well above Windows' clock and
        # VM scheduling granularity; the transfer still exceeds that window.
        with mock.patch.object(proxy, 'RELAY_IDLE_TIMEOUT', 1):
            reader, writer = await asyncio.open_connection('127.0.0.1', frontend.config['listen_port'])
            try:
                await asyncio.wait_for(connected.wait(), timeout=3)
                begin.set()
                response = await asyncio.wait_for(reader.read(), timeout=5)
            finally:
                await proxy.close_writer(writer)
        self.assertEqual(response, b'active-download\n' * 14)

    async def test_shutdown_cancels_handlers_before_modern_server_wait_closed(self):
        client_closed = asyncio.Event()
        frontend = proxy.ProxyServer(dict(schema=1, id='synthetic', kind='local',
                                          listen_port=21000, backend_ports=[21001]))
        class ModernServer:
            def close(self):
                pass
            async def wait_closed(self):
                await client_closed.wait()
        async def idle_client():
            try:
                await asyncio.Event().wait()
            finally:
                client_closed.set()
        task = asyncio.create_task(idle_client())
        frontend.tasks.add(task)
        frontend.server = ModernServer()
        await asyncio.sleep(0)  # Enter the handler so its cleanup is installed.
        try:
            await asyncio.wait_for(frontend.close(), timeout=.5)
            self.assertTrue(client_closed.is_set())
            self.assertTrue(task.done())
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_default_opaque_tunnel_preserves_idle_application_channels(self):
        self.assertIsNone(proxy.RELAY_IDLE_TIMEOUT)
        async def idle_then_data(reader, writer):
            await asyncio.sleep(.08)
            writer.write(b'after-idle'); await writer.drain()
        frontend = await self.frontend('local', [await self.server(idle_then_data)])
        with mock.patch.object(proxy, 'IDLE_TIMEOUT', .01):
            response = await self.exchange(frontend, b'')
        self.assertEqual(response, b'after-idle')


if __name__ == '__main__':
    unittest.main()
