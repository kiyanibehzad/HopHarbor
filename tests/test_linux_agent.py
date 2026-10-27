"""Fresh desktop SSH-agent handoff without service or connection changes."""
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

import agent_environment as agent
from test_security import bare_manager, pm


class AgentEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hh-agent-', dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.data = self.folder / 'data'
        self.data.mkdir(mode=0o700)
        self.sockets = []
        self.addCleanup(lambda: [item.close() for item in self.sockets])

    def listening_socket(self, name):
        path = self.folder / name
        item = socket.socket(socket.AF_UNIX)
        item.bind(str(path))
        item.listen(1)
        self.sockets.append(item)
        return str(path)

    def test_missing_handoff_preserves_inherited_environment_and_does_not_mutate_it(self):
        original = {'SSH_AUTH_SOCK': '/inherited/agent', 'KEEP': 'unchanged'}
        self.assertEqual(agent.child_environment(original, self.data), original)
        self.assertEqual(agent.child_environment(original, self.folder / 'not-created'), original)
        self.assertEqual(original['SSH_AUTH_SOCK'], '/inherited/agent')

    def test_new_desktop_agent_replaces_stale_startup_context_without_other_environment(self):
        old = self.listening_socket('old.sock')
        new = self.listening_socket('new.sock')
        base = {'SSH_AUTH_SOCK': old, 'KEEP': 'inherited'}
        agent.write_agent_environment(self.data, {'SSH_AUTH_SOCK': new,
                                                 'UNRELATED_SECRET': 'must-never-be-copied'})
        handoff = self.data / agent.FILENAME
        self.assertEqual(handoff.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(handoff.read_text()), {'ssh_auth_sock': new})
        self.assertEqual(agent.child_environment(base, self.data),
                         {'SSH_AUTH_SOCK': new, 'KEEP': 'inherited'})
        self.assertEqual(base['SSH_AUTH_SOCK'], old)
        self.assertNotIn('must-never-be-copied', handoff.read_text())

    def test_no_current_agent_and_removed_agent_explicitly_clear_old_socket(self):
        current = self.listening_socket('current.sock')
        inherited = {'SSH_AUTH_SOCK': '/old/agent', 'KEEP': 'same'}
        agent.write_agent_environment(self.data, {'SSH_AUTH_SOCK': current})
        os.unlink(current)
        self.assertEqual(agent.child_environment(inherited, self.data), {'KEEP': 'same'})
        agent.write_agent_environment(self.data, {})
        self.assertIsNone(json.loads((self.data / agent.FILENAME).read_text())['ssh_auth_sock'])
        self.assertEqual(agent.child_environment(inherited, self.data), {'KEEP': 'same'})

    def test_non_socket_relative_and_symlink_agent_locations_are_not_published(self):
        plain = self.folder / 'plain'
        plain.touch()
        target = self.listening_socket('target.sock')
        link = self.folder / 'link'
        link.symlink_to(target)
        for value in [str(plain), 'relative.sock', str(link), '\0bad', 42]:
            with self.subTest(value=value):
                agent.write_agent_environment(self.data, {'SSH_AUTH_SOCK': value})
                self.assertIsNone(json.loads((self.data / agent.FILENAME).read_text())['ssh_auth_sock'])

    def test_foreign_socket_is_not_published(self):
        current = self.listening_socket('foreign.sock')
        original = os.lstat

        def metadata(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if str(path) == current:
                fields = list(value)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value

        with mock.patch.object(agent.os, 'lstat', side_effect=metadata):
            agent.write_agent_environment(self.data, {'SSH_AUTH_SOCK': current})
        self.assertIsNone(json.loads((self.data / agent.FILENAME).read_text())['ssh_auth_sock'])

    def test_malformed_oversized_extra_keys_and_unprivate_files_fail_closed(self):
        path = self.data / agent.FILENAME
        base = {'SSH_AUTH_SOCK': '/old/agent', 'KEEP': 'same'}
        for text, mode in [('not-json', 0o600), ('x' * (agent.MAX_BYTES + 1), 0o600),
                           ('{"ssh_auth_sock":null,"SSH_AUTH_SOCK":"/injected"}', 0o600),
                           ('{"ssh_auth_sock":null}', 0o644), ('[]', 0o600)]:
            with self.subTest(mode=mode, text=text[:50]):
                path.write_text(text)
                path.chmod(mode)
                self.assertEqual(agent.child_environment(base, self.data), {'KEEP': 'same'})

    def test_symlink_hardlink_fifo_and_foreign_file_are_not_read(self):
        base = {'SSH_AUTH_SOCK': '/old/agent'}
        outside = self.folder / 'outside.json'
        outside.write_text('{"ssh_auth_sock":null}')
        outside.chmod(0o600)
        path = self.data / agent.FILENAME
        path.symlink_to(outside)
        self.assertEqual(agent.child_environment(base, self.data), {})
        path.unlink()
        os.link(outside, path)
        self.assertEqual(agent.child_environment(base, self.data), {})
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertEqual(agent.child_environment(base, self.data), {})
        path.unlink()
        path.write_text('{"ssh_auth_sock":null}')
        path.chmod(0o600)
        original = os.fstat

        def metadata(fd):
            fields = list(original(fd))
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)

        with mock.patch.object(agent.os, 'fstat', side_effect=metadata):
            self.assertEqual(agent.child_environment(base, self.data), {})
        self.assertEqual(outside.read_text(), '{"ssh_auth_sock":null}')

    def test_unprivate_and_symlink_data_directories_are_refused(self):
        self.data.chmod(0o755)
        with self.assertRaises(ValueError):
            agent.write_agent_environment(self.data, {})
        self.assertEqual(agent.child_environment({'SSH_AUTH_SOCK': '/old'}, self.data), {})
        self.data.chmod(0o700)
        linked = self.folder / 'linked-data'
        linked.symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(ValueError):
            agent.write_agent_environment(linked, {})

    def test_only_future_linux_ssh_children_refresh_agent_and_mac_path_is_unchanged(self):
        current = self.listening_socket('fresh.sock')
        agent.write_agent_environment(self.data, {'SSH_AUTH_SOCK': current})
        manager = bare_manager(self.data)
        manager.child_env = {'SSH_AUTH_SOCK': '/stale/startup', 'KEEP': 'same'}
        for platform, server_id, expected in [('linux', 'demo', current),
                                               ('darwin', 'demo', '/stale/startup'),
                                               ('linux', None, '/stale/startup')]:
            with self.subTest(platform=platform, server_id=server_id), \
                    mock.patch.object(pm.sys, 'platform', platform), \
                    mock.patch.object(pm.subprocess, 'Popen', side_effect=OSError('test-only no process')) as spawn:
                child = pm.Child(['/usr/bin/ssh', '-N'], 'Test', manager, 'forward', server_id)
                child.spawn()
                self.assertEqual(spawn.call_args.kwargs['env']['SSH_AUTH_SOCK'], expected)
        self.assertEqual(manager.child_env['SSH_AUTH_SOCK'], '/stale/startup')


if __name__ == '__main__':
    unittest.main()
