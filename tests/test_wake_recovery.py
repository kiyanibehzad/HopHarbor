"""Confirmed-wake recovery uses only fake children and fake kernel wake tokens."""
import copy
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_security import bare_manager, pm


class WakeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name)

    def child(self, blocked=False, fail_stop=False, alive=True):
        child = SimpleNamespace(
            blocked=blocked, failures=4, next_start=12345,
            error='Host key verification failed.' if blocked else 'Previous transport failure.',
            ready=True, proc=SimpleNamespace(poll=mock.Mock(return_value=None)) if alive else None,
            tick=mock.Mock(), spawn=mock.Mock(), mark_ready=mock.Mock(),
        )

        def stop(timeout=4):
            self.assertTrue(self.manager.lock._is_owned())
            if fail_stop:
                raise OSError('Test-only process termination failure')
            child.proc = None
            child.ready = False

        child.stop = mock.Mock(side_effect=stop)
        return child

    def runtime(self, children, stopping=False):
        frontend_process = SimpleNamespace(poll=mock.Mock(return_value=None), pid=900000)
        return {'ssh': children, 'ports': list(range(29000, 29000 + len(children))),
                'gost': SimpleNamespace(proc=frontend_process, stop=mock.Mock(), tick=mock.Mock()),
                'status': 'connected', 'healthy': len(children),
                'last_test': {'ok': True, 'message': 'Before sleep'}, 'stopping': stopping}

    def test_only_intended_running_entries_are_refreshed_on_the_same_ports(self):
        # An autostart flag does not make a stopped entry part of the running set.
        stopped = copy.deepcopy(self.manager.config['tunnels'][0])
        stopped.update(id='stopped_forward', local_port=20831, autostart=True)
        self.manager.config['tunnels'].append(stopped)
        live, already_dead = self.child(), self.child(alive=False)
        current = self.runtime([live, already_dead])
        frontend = current['gost'].proc
        ports = list(current['ports'])
        self.manager.runtime = {'socks_uk': current}
        with mock.patch.object(self.manager, 'start') as start, \
                mock.patch.object(self.manager, 'stop') as stop:
            self.manager.recover_after_wake()
        start.assert_not_called()
        stop.assert_not_called()
        self.assertEqual(set(self.manager.runtime), {'socks_uk'})
        self.assertIs(self.manager.runtime['socks_uk'], current)
        self.assertEqual(current['ports'], ports)
        self.assertEqual(current['status'], 'starting')
        self.assertEqual(current['healthy'], 0)
        self.assertIsNone(current['last_test'])
        for child in [live, already_dead]:
            child.stop.assert_called_once_with(timeout=.5)
            child.spawn.assert_not_called()  # The existing watcher owns the next spawn.
            self.assertEqual((child.next_start, child.failures), (0, 0))
        self.assertIs(current['gost'].proc, frontend)
        current['gost'].stop.assert_not_called()
        current['gost'].tick.assert_not_called()

    def test_stopping_and_absent_runtimes_are_untouched(self):
        child = self.child()
        current = self.runtime([child], stopping=True)
        previous = (current['status'], current['healthy'], current['last_test'],
                    child.proc, child.failures, child.next_start)
        self.manager.runtime = {'socks_uk': current}
        self.manager.recover_after_wake()
        self.assertEqual((current['status'], current['healthy'], current['last_test'],
                          child.proc, child.failures, child.next_start), previous)
        child.stop.assert_not_called()
        child.spawn.assert_not_called()
        current['gost'].stop.assert_not_called()
        self.assertFalse(self.manager.logs)
        self.manager.runtime.clear()
        self.manager.recover_after_wake()
        self.assertFalse(self.manager.runtime)
        self.assertFalse(self.manager.logs)

    def test_blocked_child_keeps_its_error_and_retry_state_while_sibling_is_refreshed(self):
        blocked, working = self.child(blocked=True), self.child()
        current = self.runtime([blocked, working])
        before = (blocked.proc, blocked.error, blocked.ready, blocked.next_start, blocked.failures)
        self.manager.runtime = {'socks_uk': current}
        self.manager.recover_after_wake()
        self.assertTrue(blocked.blocked)
        self.assertEqual((blocked.proc, blocked.error, blocked.ready, blocked.next_start, blocked.failures), before)
        blocked.stop.assert_not_called()
        blocked.spawn.assert_not_called()
        blocked.tick.assert_not_called()
        working.stop.assert_called_once_with(timeout=.5)
        self.assertEqual((working.next_start, working.failures), (0, 0))
        current['gost'].stop.assert_not_called()

    def test_failed_stop_preserves_deadline_and_ownership_but_does_not_skip_other_children(self):
        before, failed, after = self.child(), self.child(fail_stop=True), self.child()
        failed_process = failed.proc
        current = self.runtime([before, failed, after])
        other_child = self.child()
        other = self.runtime([other_child])
        self.manager.runtime = {'socks_uk': current, 'another_running_forward': other}
        self.manager.recover_after_wake()
        failed.stop.assert_called_once_with(timeout=.5)
        self.assertIs(failed.proc, failed_process)
        self.assertEqual((failed.next_start, failed.failures), (12345, 4))
        self.assertEqual(failed.error, 'Previous transport failure.')
        for child in [before, after, other_child]:
            child.stop.assert_called_once_with(timeout=.5)
            self.assertEqual((child.next_start, child.failures), (0, 0))
        self.assertIs(self.manager.runtime['socks_uk'], current)
        self.assertEqual((current['status'], current['healthy'], current['last_test']), ('starting', 0, None))
        errors = [entry for entry in self.manager.logs if entry['level'] == 'error']
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['tunnel_id'], 'socks_uk')
        self.assertIn('Test-only process termination failure', errors[0]['message'])
        current['gost'].stop.assert_not_called()
        other['gost'].stop.assert_not_called()

    def test_watch_refreshes_once_for_one_confirmed_wake_not_for_each_following_tick(self):
        child = self.child()
        current = self.runtime([child])
        frontend = current['gost'].proc
        self.manager.runtime = {'socks_uk': current}
        # Initial token, unchanged tick, one new wake, then unchanged token again.
        tokens = iter([(100, 0), (100, 0), (200, 0), (200, 0)])
        self.manager.wake_monitor = pm.WakeMonitor(reader=lambda: next(tokens))
        self.manager.halt = SimpleNamespace(wait=mock.Mock(side_effect=[False, False, False, True]))
        with mock.patch.object(self.manager, 'recover_after_wake', wraps=self.manager.recover_after_wake) as recover, \
                mock.patch.object(self.manager, 'maintain_local_files'), \
                mock.patch.object(self.manager, 'front_probe', return_value=True), \
                mock.patch.object(pm, 'port_open', return_value=True), \
                mock.patch.object(self.manager, 'start') as start:
            self.manager.watch()
        recover.assert_called_once_with()
        child.stop.assert_called_once_with(timeout=.5)
        self.assertEqual(child.tick.call_count, 3)
        start.assert_not_called()
        self.assertIs(current['gost'].proc, frontend)
        current['gost'].stop.assert_not_called()
        self.assertIsNone(current['last_test'])
        self.assertEqual(current['ports'], [29000])
        self.assertEqual(current['status'], 'starting')


if __name__ == '__main__':
    unittest.main()
