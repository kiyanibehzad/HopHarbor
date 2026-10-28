"""Cross-platform recovery deadlines and retry behavior with owned, synthetic children only."""
import json
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_security import bare_manager, pm


class Clock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value


class Process:
    """A process whose exit/timeout can be controlled without OS side effects."""
    def __init__(self, pid, clock, events, term='wait_exit', kill='exit'):
        self.pid, self.clock, self.events = pid, clock, events
        self.term, self.kill = term, kill
        self.returncode = None
        self.phase = 'term'

    def poll(self):
        return self.returncode

    def receive(self, sig):
        self.events.append(('signal', self.pid, sig))
        self.phase = 'kill' if sig == signal.SIGKILL else 'term'
        behavior = self.kill if self.phase == 'kill' else self.term
        if behavior == 'error':
            raise OSError('Test-only signal failure')
        if behavior == 'exit':
            self.returncode = 0

    def wait(self, timeout):
        self.events.append(('wait', self.pid, self.phase, timeout))
        behavior = self.kill if self.phase == 'kill' else self.term
        if behavior == 'wait_error':
            raise OSError('Test-only wait failure')
        if self.returncode is not None:
            return self.returncode
        if behavior == 'wait_exit':
            self.returncode = 0
            return 0
        self.clock.value += timeout
        raise subprocess.TimeoutExpired('synthetic-child', timeout)


class FastWakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name)
        self.clock = Clock()
        self.events = []
        self.processes = {}
        self.next_pid = 910000
        platform = mock.patch.object(pm.sys, 'platform', 'darwin')
        platform.start()
        self.addCleanup(platform.stop)
        clock = mock.patch.object(pm.time, 'monotonic', side_effect=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        signals = mock.patch.object(pm.os, 'killpg', side_effect=self.signal)
        signals.start()
        self.addCleanup(signals.stop)
        spawning = mock.patch.object(pm.subprocess, 'Popen',
                                     side_effect=AssertionError('Unexpected real process spawn'))
        spawning.start()
        self.addCleanup(spawning.stop)

    def signal(self, pid, sig):
        self.processes[pid].receive(sig)

    def child(self, term='wait_exit', kill='exit', blocked=False, server='uk'):
        self.next_pid += 1
        proc = Process(self.next_pid, self.clock, self.events, term, kill)
        self.processes[proc.pid] = proc
        child = pm.Child(['/synthetic-ssh'], 'Test SSH', self.manager, 'socks_uk', server)
        child.proc = proc
        child.generation = 3
        child.ready = True
        child.failures = 4
        child.next_start = 999
        child.last_start = 95
        child.error = 'Host key verification failed.' if blocked else 'Previous transport error.'
        child.blocked = blocked
        path = self.manager.data / 'runtime' / ('child-%s.json' % proc.pid)
        path.write_text(json.dumps({'pid': proc.pid, 'argv': child.argv}))
        return child

    def ownership(self, child):
        return self.manager.data / 'runtime' / ('child-%s.json' % child.proc.pid)

    def runtime(self, children, stopping=False):
        frontend = SimpleNamespace(pid=990000, poll=mock.Mock(return_value=None))
        return {'ssh': children, 'ports': list(range(29000, 29000 + len(children))),
                'gost': SimpleNamespace(proc=frontend, stop=mock.Mock(), tick=mock.Mock()),
                'status': 'connected', 'healthy': len(children),
                'last_test': {'ok': True}, 'stopping': stopping}

    def watch_once(self, port_ready=True):
        self.manager.halt = SimpleNamespace(wait=mock.Mock(side_effect=[False, True]))
        with mock.patch.object(self.manager, 'maintain_local_files'), \
                mock.patch.object(self.manager, 'front_probe', return_value=True), \
                mock.patch.object(pm, 'port_open', return_value=port_ready):
            self.manager.watch()

    def test_all_term_signals_precede_any_wait_and_success_releases_ownership(self):
        children = [self.child() for _ in range(4)]
        paths = [self.ownership(child) for child in children]
        with self.manager.lock:
            errors = pm.Child.stop_many(children)
        self.assertEqual(errors, [])
        first_wait = next(i for i, event in enumerate(self.events) if event[0] == 'wait')
        self.assertEqual(first_wait, 4)
        self.assertEqual([event[2] for event in self.events[:first_wait]], [signal.SIGTERM] * 4)
        for child, path in zip(children, paths):
            self.assertIsNone(child.proc)
            self.assertEqual(child.generation, 4)
            self.assertFalse(path.exists())
        self.assertEqual(self.clock.value, 100)

    def test_many_hung_children_share_both_deadlines_and_all_kills_precede_reaping(self):
        children = [self.child(term='hang', kill='hang') for _ in range(6)]
        procs = [child.proc for child in children]
        paths = [self.ownership(child) for child in children]
        with self.manager.lock:
            errors = pm.Child.stop_many(children, timeout=.5, kill_timeout=2)
        self.assertEqual(len(errors), 6)
        self.assertAlmostEqual(self.clock.value - 100, 2.5)
        term_waits = [event[3] for event in self.events if event[0] == 'wait' and event[2] == 'term']
        kill_waits = [event[3] for event in self.events if event[0] == 'wait' and event[2] == 'kill']
        self.assertEqual(term_waits, [.5, 0, 0, 0, 0, 0])
        self.assertEqual(kill_waits, [2, 0, 0, 0, 0, 0])
        kill_indices = [i for i, event in enumerate(self.events)
                        if event[0] == 'signal' and event[2] == signal.SIGKILL]
        first_reap = next(i for i, event in enumerate(self.events)
                          if event[0] == 'wait' and event[2] == 'kill')
        self.assertEqual(len(kill_indices), 6)
        self.assertLess(max(kill_indices), first_reap)
        for child, proc, path in zip(children, procs, paths):
            self.assertIs(child.proc, proc)
            self.assertEqual(child.generation, 3)
            self.assertTrue(path.exists())

    def test_signal_and_wait_failures_preserve_the_failed_children_but_finish_siblings(self):
        children = [self.child(term='error'), self.child(term='hang', kill='error'),
                    self.child(term='wait_error'), self.child()]
        procs = [child.proc for child in children]
        paths = [self.ownership(child) for child in children]
        with self.manager.lock:
            errors = pm.Child.stop_many(children)
        self.assertEqual({id(child) for child, _error in errors},
                         {id(child) for child in children[:3]})
        for child, proc, path in zip(children[:3], procs[:3], paths[:3]):
            self.assertIs(child.proc, proc)
            self.assertEqual(child.generation, 3)
            self.assertTrue(path.exists())
        self.assertIsNone(children[-1].proc)
        self.assertEqual(children[-1].generation, 4)
        self.assertFalse(paths[-1].exists())

    def test_wake_skips_blocked_stopping_and_absent_entries_and_keeps_frontend_ports(self):
        blocked, working, stopping = self.child(blocked=True), self.child(), self.child()
        current = self.runtime([blocked, working])
        other = self.runtime([stopping], stopping=True)
        front, ports = current['gost'].proc, list(current['ports'])
        working_pid = working.proc.pid
        blocked_before = (blocked.proc, blocked.generation, blocked.failures, blocked.next_start,
                          blocked.error, blocked.ready)
        self.manager.runtime = {'socks_uk': current, 'stopping': other}
        with mock.patch.object(self.manager, 'start') as start:
            self.manager.recover_after_wake()
        start.assert_not_called()
        self.assertEqual((blocked.proc, blocked.generation, blocked.failures, blocked.next_start,
                          blocked.error, blocked.ready), blocked_before)
        self.assertIsNotNone(stopping.proc)
        self.assertEqual(stopping.generation, 3)
        self.assertEqual({event[1] for event in self.events}, {working_pid})
        self.assertIsNone(working.proc)
        self.assertEqual((working.failures, working.next_start, working.recovery_until), (0, 0, 190))
        self.assertIs(current['gost'].proc, front)
        self.assertEqual(current['ports'], ports)
        current['gost'].stop.assert_not_called()
        other['gost'].stop.assert_not_called()
        self.assertEqual(self.manager.wake_recovery['pending'], {'socks_uk'})
        self.assertEqual((current['status'], current['healthy'], current['last_test']), ('starting', 0, None))

    def test_wake_failed_child_retains_retry_deadline_and_other_child_still_refreshes(self):
        failed, working = self.child(term='error'), self.child()
        proc, ownership = failed.proc, self.ownership(failed)
        self.manager.runtime = {'socks_uk': self.runtime([failed, working])}
        self.manager.recover_after_wake()
        self.assertIs(failed.proc, proc)
        self.assertEqual((failed.generation, failed.failures, failed.next_start, failed.recovery_until),
                         (3, 4, 999, 0))
        self.assertTrue(ownership.exists())
        self.assertIsNone(working.proc)
        self.assertEqual((working.failures, working.next_start, working.recovery_until), (0, 0, 190))
        errors = [event for event in self.manager.logs if event['level'] == 'error']
        self.assertEqual(len(errors), 1)

    def test_repeated_wake_replaces_the_recovery_epoch_and_resets_old_backoff(self):
        child = self.child()
        current = self.runtime([child])
        front = current['gost'].proc
        self.manager.runtime = {'socks_uk': current}
        self.manager.recover_after_wake()
        first = self.manager.wake_recovery
        first['pending'].clear()
        first['restored'].add('socks_uk')
        child.failures, child.next_start, child.recovery_until = 5, 999, 0
        self.clock.value = 125
        self.manager.recover_after_wake()
        self.assertIsNot(self.manager.wake_recovery, first)
        self.assertEqual(self.manager.wake_recovery['started'], 125)
        self.assertEqual(self.manager.wake_recovery['pending'], {'socks_uk'})
        self.assertEqual(self.manager.wake_recovery['restored'], set())
        self.assertEqual((child.failures, child.next_start, child.recovery_until), (0, 0, 215))
        self.assertIs(current['gost'].proc, front)

    def test_network_failure_retries_in_one_second_only_during_recovery_grace(self):
        child = self.child()
        child.spawn = mock.Mock()
        child.recovery_until = 120
        child.proc.returncode = 255
        child.tick()
        self.assertEqual(child.next_start, 101)
        child.spawn.assert_not_called()
        self.clock.value = 101
        child.tick()
        child.spawn.assert_called_once_with()

        child = self.child()
        child.spawn = mock.Mock()
        child.recovery_until = 120
        child.proc.returncode = 255
        self.clock.value = 125
        child.tick()
        self.assertEqual(child.next_start, 185)  # Ordinary exponential backoff.
        child.spawn.assert_not_called()

    def test_credential_failure_is_never_retried_even_inside_fast_window(self):
        child = self.child(blocked=True)
        child.proc.returncode = 255
        child.recovery_until = 190
        child.spawn = mock.Mock()
        child.tick()
        self.clock.value = 150
        child.tick()
        self.assertTrue(child.blocked)
        child.spawn.assert_not_called()

    def test_gost_process_does_not_inherit_fast_ssh_retry_policy(self):
        child = self.child(server=None)
        child.proc.returncode = 1
        child.recovery_until = 190
        child.tick()
        self.assertEqual(child.next_start, 160)

    def test_ready_ssh_clears_grace_and_failure_count_and_completes_recovery_once(self):
        child = self.child()
        child.tick = mock.Mock()
        child.recovery_until = 190
        current = self.runtime([child])
        self.manager.runtime = {'socks_uk': current}
        self.manager.wake_recovery = {'started': 90, 'until': 180,
                                      'pending': {'socks_uk'}, 'restored': set()}
        self.watch_once()
        self.assertTrue(child.ready)
        self.assertEqual((child.recovery_until, child.failures), (0, 0))
        self.assertEqual(current['status'], 'connected')
        self.assertIsNone(self.manager.wake_recovery)
        self.assertEqual(self.manager.halt.wait.call_args_list, [mock.call(.5), mock.call(3)])
        restored = [event for event in self.manager.logs if event['message'].startswith('SSH connections restored')]
        self.assertEqual(len(restored), 1)

    def test_unready_ssh_keeps_grace_and_short_watch_interval_then_window_expires(self):
        child = self.child()
        child.tick = mock.Mock()
        child.recovery_until = 190
        current = self.runtime([child])
        self.manager.runtime = {'socks_uk': current}
        self.manager.wake_recovery = {'started': 100, 'until': 190,
                                      'pending': {'socks_uk'}, 'restored': set()}
        self.watch_once(port_ready=False)
        self.assertFalse(child.ready)
        self.assertEqual(child.recovery_until, 190)
        self.assertEqual(self.manager.watch_interval(), .5)
        self.clock.value = 190
        self.watch_once(port_ready=False)
        self.assertIsNone(self.manager.wake_recovery)
        self.assertEqual(self.manager.watch_interval(), 3)
        warning = [event for event in self.manager.logs if event['level'] == 'warning']
        self.assertEqual(len(warning), 1)
        self.assertIn('1 port forwarding entries', warning[0]['message'])

    def test_manual_disconnect_during_grace_is_not_restarted(self):
        child = self.child()
        current = self.runtime([child])
        self.manager.config['tunnels'][0]['autostart'] = True
        self.manager.runtime = {'socks_uk': current}
        self.manager.wake_recovery = {'started': 100, 'until': 190,
                                      'pending': {'socks_uk'}, 'restored': set()}
        self.manager.stop('socks_uk')
        with mock.patch.object(self.manager, 'start') as start:
            self.watch_once()
        start.assert_not_called()
        self.assertEqual(self.manager.runtime, {})
        self.assertIsNone(child.proc)
        self.assertIsNone(self.manager.wake_recovery)
        current['gost'].stop.assert_called_once_with()

    def test_normal_and_finished_recovery_monitor_use_three_seconds(self):
        self.assertEqual(self.manager.watch_interval(), 3)
        self.manager.wake_recovery = {'until': 190, 'pending': set()}
        self.assertEqual(self.manager.watch_interval(), 3)
        self.manager.wake_recovery = {'until': 190, 'pending': {'socks_uk'}}
        self.assertEqual(self.manager.watch_interval(), .5)
        self.clock.value = 190
        self.assertEqual(self.manager.watch_interval(), 3)

    def test_recovered_loopback_pool_nodes_are_not_quarantined_for_ten_seconds(self):
        # SOCKS/TCP and HTTP use different selector locations in GOST's config;
        # both must re-admit a rebuilt SSH backend within one second.
        for kind in ('socks', 'local', 'http'):
            with self.subTest(kind=kind):
                config = self.manager.gost_config(
                    {'id': 'synthetic', 'local_port': 28080, 'kind': kind}, [29000, 29001])
                selector = (config['chains'][0]['hops'][0]['selector'] if kind == 'http'
                            else config['services'][0]['forwarder']['selector'])
                self.assertEqual(selector['failTimeout'], '1s')

    def test_all_blocked_forwards_never_report_successful_wake_recovery(self):
        child = self.child(blocked=True)
        current = self.runtime([child])
        self.manager.runtime = {'socks_uk': current}
        self.manager.recover_after_wake()
        self.watch_once(port_ready=False)
        self.assertEqual(current['status'], 'error')
        self.assertTrue(child.blocked)
        self.assertIsNone(self.manager.wake_recovery)
        self.assertFalse(any('All active SSH connections restored' in event['message']
                             for event in self.manager.logs))


class LinuxFastWakeTests(FastWakeTests):
    def setUp(self):
        super().setUp()
        platform = mock.patch.object(pm.sys, 'platform', 'linux')
        platform.start()
        self.addCleanup(platform.stop)


if __name__ == '__main__':
    unittest.main()
