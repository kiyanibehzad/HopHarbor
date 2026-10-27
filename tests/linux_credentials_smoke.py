#!/usr/bin/python3
"""Exercise real libsecret in a private D-Bus session and disposable Linux home.

This script starts its own gnome-keyring-daemon and never connects to the user's
desktop bus or keyring. SSH fixtures use dynamic loopback ports and synthetic
encrypted keys; no connection leaves this machine.
"""
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
IDENT = 'hopharbor-smoke-synthetic'


def native_key_auth(home, helper):
    """Use the real askpass/SSH-hop chain with two distinct encrypted keys."""
    sys.path.insert(0, str(ROOT))
    from manager import Child, Manager, quote
    from agent_environment import write_agent_environment
    account = pwd.getpwuid(os.getuid())
    username = account.pw_name
    # OpenSSH StrictModes checks every directory above AuthorizedKeysFile.
    # /tmp is world-writable even when our fake HOME is private, so create only
    # these disposable SSH fixtures below the account's real, secure home.
    cache = Path(account.pw_dir) / '.cache'
    cache.mkdir(mode=0o700, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='hopharbor-ssh-smoke-', dir=cache)
    folder = Path(temporary.name)
    children = []
    ports = set()
    manager = None
    passphrases = {'smoke_first': 'synthetic-first-encrypted-key',
                   'smoke_second': 'synthetic-second-encrypted-key'}

    def diagnostic(value):
        text = str(value).replace(str(folder), '<ssh-fixture>').replace(str(home), '<test-home>')
        text = text.replace(str(ROOT), '<source>').replace(username, '<test-user>')
        for secret in list(passphrases.values()) + ['synthetic-intentionally-wrong']:
            text = text.replace(secret, '<test-secret>')
        return text[-500:]

    def port():
        while True:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                number = listener.getsockname()[1]
            if number != 17777 and number not in ports:
                ports.add(number)
                return number

    def command(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('A synthetic SSH fixture could not be prepared: '
                               + Path(argv[0]).name + ': ' + diagnostic(result.stderr))
        return result

    def server(ident):
        host, client = folder / (ident + '-host'), folder / (ident + '-client')
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(host)])
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-a', '4', '-N',
                 passphrases[ident], '-f', str(client)])
        authorized = folder / (ident + '-authorized_keys')
        authorized.write_bytes(client.with_suffix('.pub').read_bytes())
        authorized.chmod(0o600)
        number = port()
        config = folder / (ident + '-sshd_config')
        config.write_text('\n'.join([
            'Port ' + str(number), 'ListenAddress 127.0.0.1',
            'HostKey ' + quote(str(host)), 'PidFile ' + quote(str(folder / (ident + '.pid'))),
            'AuthorizedKeysFile ' + quote(str(authorized)),
            'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
            'AuthenticationMethods publickey', 'UsePAM yes', 'PermitRootLogin prohibit-password',
            'AllowUsers ' + username, 'StrictModes yes', 'AllowTcpForwarding yes',
            'GatewayPorts no', 'AllowAgentForwarding no', 'X11Forwarding no',
            'PermitTTY no', 'UseDNS no', 'PrintMotd no', 'PrintLastLog no',
            'MaxStartups 20', 'LogLevel ERROR', ''
        ]))
        config.chmod(0o600)
        command(['/usr/sbin/sshd', '-t', '-f', str(config)])
        log = (folder / (ident + '-sshd.log')).open('wb')
        child = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                 start_new_session=True)
        children.append((child, log))
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if child.poll() is not None:
                raise RuntimeError('A synthetic loopback SSH server exited before testing.')
            try:
                with socket.create_connection(('127.0.0.1', number), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('A synthetic loopback SSH server was not ready.')
        return {'id': ident, 'name': ident, 'host': '127.0.0.1', 'port': number,
                'username': username, 'identity_file': str(client), 'auth_mode': 'key',
                'jump_id': None}, '[127.0.0.1]:%s %s\n' % (number, host.with_suffix('.pub').read_text().strip())

    def save_passphrase(ident, value):
        result = helper('put', {'server_id': ident, 'key_passphrase': value})
        if result.returncode:
            raise RuntimeError('Could not save a synthetic SSH key passphrase.')

    def connect(ident, expected):
        env = dict(manager.child_env, PM_SERVER_ID=ident)
        env.pop('SSH_AUTH_SOCK', None)
        proc = subprocess.Popen(['/usr/bin/ssh', '-F', str(manager.data / 'ssh_config'),
                                 '-T', '-n', '-o', 'IdentityAgent=none', 'pm_' + ident, '/usr/bin/true'],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, errors = proc.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=3)
            raise RuntimeError('The synthetic encrypted-key SSH test timed out.')
        for value in list(passphrases.values()) + ['synthetic-intentionally-wrong']:
            if value.encode() in output or value.encode() in errors:
                raise RuntimeError('A synthetic SSH secret appeared in command output.')
        if output or (proc.returncode == 0) != expected:
            raise RuntimeError('Synthetic encrypted-key SSH authentication had an unexpected result '
                               + str(proc.returncode) + ': ' + diagnostic(errors.decode('utf-8', 'replace')))

    def agent_connect(expected):
        # This is a real Manager Child spawn, not a reconstructed test env.
        # Explicitly disable default key files so only our private SSH agent
        # can authenticate; none of the account's own key files are consulted.
        child = Child(['/usr/bin/ssh', '-F', str(manager.data / 'ssh_config'), '-T', '-n',
                       '-o', 'IdentityFile=none', '-o', 'IdentitiesOnly=no',
                       'pm_smoke_first', '/usr/bin/true'],
                      'Synthetic agent SSH', manager, 'agent_smoke', 'smoke_first')
        try:
            child.spawn()
            if child.proc is None:
                raise RuntimeError('The synthetic agent-auth SSH process could not start.')
            code = child.proc.wait(timeout=25)
            if (code == 0) != expected:
                raise RuntimeError('Synthetic SSH-agent handoff had an unexpected result ' + str(code))
        finally:
            child.stop(timeout=1)

    try:
        first, first_pin = server('smoke_first')
        second, second_pin = server('smoke_second')
        second['jump_id'] = first['id']
        data = folder / 'manager-data'
        data.mkdir(mode=0o700)
        (data / 'config.json').write_text(json.dumps({'servers': [first, second], 'tunnels': []}))
        (data / 'config.json').chmod(0o600)
        # These pins come straight from host keys generated by this fixture;
        # no network key discovery or trust bypass is involved.
        (data / 'known_hosts').write_text(first_pin + second_pin)
        (data / 'known_hosts').chmod(0o600)
        for ident, passphrase in passphrases.items():
            save_passphrase(ident, passphrase)
        manager = Manager(data, ROOT, port())
        save_passphrase(first['id'], 'synthetic-intentionally-wrong')
        connect(first['id'], False)
        save_passphrase(first['id'], passphrases[first['id']])
        connect(first['id'], True)
        # First-hop and destination keys must use their own keyring identities.
        save_passphrase(second['id'], 'synthetic-intentionally-wrong')
        connect(second['id'], False)
        save_passphrase(second['id'], passphrases[second['id']])
        save_passphrase(first['id'], 'synthetic-intentionally-wrong')
        connect(second['id'], False)
        save_passphrase(first['id'], passphrases[first['id']])
        connect(second['id'], True)

        # Simulate a service that started before a desktop SSH agent existed.
        # Publish the later agent without restarting the Manager or any SSH.
        agent_socket = folder / 'private-agent.sock'
        agent = subprocess.Popen(['/usr/bin/ssh-agent', '-D', '-a', str(agent_socket)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        children.append((agent, None))
        end = time.monotonic() + 5
        while not agent_socket.exists():
            if agent.poll() is not None or time.monotonic() >= end:
                raise RuntimeError('The disposable SSH agent was not ready.')
            time.sleep(.05)
        add_env = dict(manager.child_env, PM_SERVER_ID=first['id'], SSH_AUTH_SOCK=str(agent_socket))
        added = subprocess.run(['/usr/bin/ssh-add', '-q', first['identity_file']],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env=add_env)
        if added.returncode:
            raise RuntimeError('Could not load the synthetic encrypted key into the private SSH agent: '
                               + diagnostic(added.stderr.decode('utf-8', 'replace')))
        manager.config['servers'][0]['auth_mode'] = 'agent'
        manager.config['servers'][0]['identity_file'] = ''
        manager.write_ssh_config()
        manager.child_env.pop('SSH_AUTH_SOCK', None)
        agent_connect(False)
        write_agent_environment(manager.data, {'SSH_AUTH_SOCK': str(agent_socket)})
        agent_connect(True)
        write_agent_environment(manager.data, {})
        agent_connect(False)
        return ['real OpenSSH rejects a wrong encrypted-key passphrase without printing secrets',
                'real OpenSSH authenticates using GNOME Keyring through askpass.py',
                'two-hop ssh_hop.py uses independent encrypted keys and per-hop keyring identities',
                'new SSH children use a later desktop agent and clear it without a Manager restart']
    finally:
        if manager is not None:
            manager.shutdown()
        for proc, log in reversed(children):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=3)
            if log is not None:
                log.close()
        try:
            for ident in passphrases:
                helper('delete', {'server_id': ident})
        finally:
            temporary.cleanup()


def child():
    home = Path.home()
    if (not (home / '.hopharbor-keyring-smoke').is_file()
            or not os.environ.get('DBUS_SESSION_BUS_ADDRESS')
            or not str(home).startswith('/tmp/hopharbor-keyring-')):
        raise RuntimeError('This test requires its private home and D-Bus session.')
    control = Path(os.environ['XDG_RUNTIME_DIR']) / 'keyring'
    control.mkdir(mode=0o700)
    daemon = subprocess.Popen(['gnome-keyring-daemon', '--foreground', '--unlock',
                               '--components=secrets', '--control-directory',
                               str(control)],
                              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    daemon.stdin.write(b'hopharbor-smoke-keyring-master-only')
    daemon.stdin.close()
    checks = []

    def helper(mode, body=None, prompt=None):
        command = ['/usr/bin/python3', str(ROOT / 'credentials.py'), mode]
        if prompt is not None:
            command.append(prompt)
        env = dict(os.environ, PM_SERVER_ID=IDENT)
        return subprocess.run(command, input=json.dumps(body) if body is not None else '',
                              text=True, capture_output=True, timeout=13, env=env)

    def status():
        result = helper('has', {'server_id': IDENT})
        return result, json.loads(result.stdout)

    try:
        end = time.monotonic() + 10
        while True:
            if daemon.poll() is not None:
                raise RuntimeError('The disposable keyring daemon exited before testing.')
            result, data = status()
            if result.returncode == 0:
                break
            if time.monotonic() >= end:
                raise RuntimeError('The disposable Secret Service did not become ready.')
            time.sleep(.1)
        assert not data['has_password'] and not data['has_key_passphrase'], data
        checks.append('empty isolated Secret Service')

        result = helper('put', {'server_id': IDENT, 'password': 'synthetic-server-password',
                                'key_passphrase': 'synthetic-private-key-passphrase'})
        assert result.returncode == 0, result.stdout
        assert 'synthetic-' not in result.stdout and not result.stderr
        _, data = status()
        assert data['has_password'] and data['has_key_passphrase'], data
        checks.append('password and passphrase stored; status contains presence only')

        for prompt, secret in [("synthetic@example.invalid's password: ", 'synthetic-server-password'),
                               ('Enter passphrase for key synthetic-key: ', 'synthetic-private-key-passphrase')]:
            result = helper('askpass', prompt=prompt)
            assert result.returncode == 0 and result.stdout == secret + '\n' and not result.stderr
        checks.append('OpenSSH password and private-key passphrase prompts')

        result = helper('put', {'server_id': IDENT, 'password': 'synthetic-replaced-password'})
        assert result.returncode == 0, result.stdout
        result = helper('askpass', prompt='Enter passphrase: ')
        assert result.returncode == 0 and result.stdout == 'synthetic-private-key-passphrase\n'
        result = helper('askpass', prompt='Password: ')
        assert result.returncode == 0 and result.stdout == 'synthetic-replaced-password\n'
        checks.append('updating one secret preserves the other')

        for body in [{'server_id': '../bad', 'password': 'secret'},
                     {'server_id': IDENT, 'password': 'invalid\nsecret'},
                     {'server_id': IDENT, 'password': 'é' * 4097}]:
            result = helper('put', body)
            assert result.returncode == 1 and 'secret' not in result.stdout
        for prompt in ['Host key password verification (yes/no)?', 'Enter verification code:']:
            result = helper('askpass', prompt=prompt)
            assert result.returncode == 1 and result.stdout == '' and result.stderr == ''
        checks.append('invalid credentials and host/OTP prompts rejected')

        result = helper('delete', {'server_id': IDENT})
        assert result.returncode == 0, result.stdout
        _, data = status()
        assert not data['has_password'] and not data['has_key_passphrase'], data
        checks.append('deleting a Session removes both app-owned secrets')

        checks.extend(native_key_auth(home, helper))

        result = helper('put', {'server_id': IDENT, 'password': 'synthetic-lock-check'})
        assert result.returncode == 0, result.stdout
        import gi
        gi.require_version('Secret', '1')
        from gi.repository import Secret
        service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION
                                          | Secret.ServiceFlags.LOAD_COLLECTIONS, None)
        collection = Secret.Collection.for_alias_sync(service, 'default', Secret.CollectionFlags.NONE, None)
        assert collection is not None
        service.lock_sync([collection], None)
        started = time.monotonic()
        result = helper('askpass', prompt='Password: ')
        assert result.returncode == 1 and result.stdout == '' and result.stderr == ''
        assert time.monotonic() - started < 12
        for mode, body in [('put', {'server_id': IDENT, 'password': 'synthetic-rejected'}),
                           ('delete', {'server_id': IDENT})]:
            result = helper(mode, body)
            assert result.returncode == 1, result.stdout
        checks.append('locked keyring fails closed without SSH output or unlock prompts')
        print(json.dumps({'ok': True, 'checks': checks}, indent=2))
        return 0
    finally:
        if daemon.poll() is None:
            os.killpg(daemon.pid, signal.SIGTERM)
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(daemon.pid, signal.SIGKILL)
                daemon.wait(timeout=3)


def main():
    if not sys.platform.startswith('linux'):
        raise SystemExit('Run this integration test on Linux; it never uses macOS Keychain.')
    if sys.argv[1:] == ['--isolated-child']:
        return child()
    if sys.argv[1:]:
        raise SystemExit('No arguments are needed.')
    with tempfile.TemporaryDirectory(prefix='hopharbor-keyring-', dir='/tmp') as directory:
        home = Path(directory)
        home.chmod(0o700)
        (home / '.hopharbor-keyring-smoke').touch(mode=0o600)
        env = dict(os.environ, HOME=directory)
        for key, suffix in [('XDG_DATA_HOME', 'data'), ('XDG_CONFIG_HOME', 'config'),
                            ('XDG_RUNTIME_DIR', 'runtime'), ('XDG_CACHE_HOME', 'cache')]:
            path = home / suffix
            path.mkdir(mode=0o700)
            env[key] = str(path)
        for key in ('DBUS_SESSION_BUS_ADDRESS', 'DBUS_STARTER_ADDRESS', 'DBUS_STARTER_BUS_TYPE',
                    'GNOME_KEYRING_CONTROL', 'SSH_AUTH_SOCK'):
            env.pop(key, None)
        result = subprocess.run(['dbus-run-session', '--', '/usr/bin/python3', str(Path(__file__).resolve()),
                                 '--isolated-child'], env=env, timeout=180)
        return result.returncode


if __name__ == '__main__':
    sys.exit(main())
