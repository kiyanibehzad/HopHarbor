"""Child lifecycle diagnostics with synthetic processes only; no SSH or service actions."""
import io
import json
import tempfile
import unittest
from unittest import mock

from test_security import bare_manager, pm


class ChildLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='hopharbor-child-lifecycle-')
        self.addCleanup(self.scratch.cleanup)
        self.manager = bare_manager(self.scratch.name)
        self.child = pm.Child(['/test-only-ssh'], 'Test SSH', self.manager,
                              'test_only_forward', 'test_only_session')
        # An unexpected spawn fails the test rather than opening any real process.
        popen_patch = mock.patch.object(pm.subprocess, 'Popen',
                                       side_effect=AssertionError('Unexpected process spawn'))
        self.popen = popen_patch.start()
        self.addCleanup(popen_patch.stop)
        thread_patch = mock.patch.object(pm.threading, 'Thread')
        self.thread = thread_patch.start()
        self.addCleanup(thread_patch.stop)
        signal_patch = mock.patch.object(pm.os, 'killpg')
        self.killpg = signal_patch.start()
        self.addCleanup(signal_patch.stop)

    def process(self, pid=900101, code=None, text=''):
        proc = mock.Mock()
        proc.pid = pid
        proc.returncode = code
        proc.poll.return_value = code
        proc.wait.return_value = 0
        proc.stdout = io.BytesIO(text.encode('utf-8'))
        self.addCleanup(proc.stdout.close)
        return proc

    def own(self, proc):
        path = self.manager.data / 'runtime' / ('child-%s.json' % proc.pid)
        path.write_text(json.dumps({'pid': proc.pid, 'argv': self.child.argv}))
        return path

    def use_spawn(self, proc):
        self.popen.side_effect = None
        self.popen.return_value = proc

    def run_scheduled_reader(self, call):
        kwargs = call.kwargs
        target = kwargs.get('target', call.args[0] if call.args else None)
        self.assertTrue(callable(target), 'The reader thread must have a callable target')
        target(*kwargs.get('args', ()), **kwargs.get('kwargs', {}))

    def test_successful_spawn_starts_new_generation_and_clears_stale_state(self):
        proc = self.process()
        self.use_spawn(proc)
        self.assertEqual(self.child.generation, 0)
        self.child.error = 'Earlier run failed.'
        self.child.blocked = True
        self.child.ready = True
        self.manager.log('error', self.child.error, self.child.tunnel_id)

        self.child.spawn()

        self.assertEqual(self.child.generation, 1)
        self.assertIs(self.child.proc, proc)
        self.assertEqual(self.child.error, '')
        self.assertFalse(self.child.blocked)
        self.assertFalse(self.child.ready)
        self.assertTrue((self.manager.data / 'runtime' / ('child-%s.json' % proc.pid)).exists())
        self.thread.return_value.start.assert_called_once()
        self.assertIn('Earlier run failed.', [event['message'] for event in self.manager.logs])

    def test_failed_spawn_replaces_stale_error_and_waits_sixty_seconds(self):
        self.child.error = 'Stale diagnostic from an earlier run.'
        self.child.ready = True
        self.popen.side_effect = OSError('Test-only executable unavailable')

        with mock.patch.object(pm.time, 'monotonic', return_value=100.0):
            self.child.spawn()

        self.assertEqual(self.child.generation, 1)
        self.assertIsNone(self.child.proc)
        self.assertFalse(self.child.ready)
        self.assertIn('Test-only executable unavailable', self.child.error)
        self.assertNotIn('Stale diagnostic', self.child.error)
        self.assertEqual(self.child.next_start, 160.0)
        self.thread.assert_not_called()
        errors = [event for event in self.manager.logs if event['level'] == 'error']
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['message'], self.child.error)
        self.assertFalse(list((self.manager.data / 'runtime').glob('child-*.json')))

    def test_delayed_reader_from_previous_spawn_cannot_corrupt_new_generation(self):
        old = self.process(pid=900101, code=1, text='Permission denied (publickey).\n')
        replacement = self.process(pid=900102)
        self.use_spawn(old)
        self.child.spawn()
        old_generation = self.child.generation
        scheduled = self.thread.call_args
        # The monitor may observe exit before the old stderr reader finishes.
        self.child.proc = None
        self.use_spawn(replacement)
        self.child.spawn()
        self.child.error = 'Current-generation diagnostic.'
        history = self.manager.logs.snapshot()

        self.run_scheduled_reader(scheduled)

        self.assertGreater(self.child.generation, old_generation)
        self.assertIs(self.child.proc, replacement)
        self.assertEqual(self.child.error, 'Current-generation diagnostic.')
        self.assertFalse(self.child.blocked)
        self.assertEqual(self.manager.logs.snapshot(), history)
        self.assertTrue(old.stdout.closed)

    def test_reader_rechecks_generation_after_each_blocking_read(self):
        proc = self.process()
        replacement = self.process(pid=900102)
        self.child.proc = proc
        generation = self.child.generation
        stream = mock.Mock()
        lines = iter([b'First-generation diagnostic.\n', b'Permission denied.\n', b''])
        reads = 0

        def readline(_size):
            nonlocal reads
            reads += 1
            if reads == 2:
                # Model a new spawn occurring while readline was waiting for stderr.
                with self.manager.lock:
                    self.child.generation += 1
                    self.child.proc = replacement
                    self.child.error = 'New-generation diagnostic.'
                    self.child.blocked = False
            return next(lines)

        stream.readline.side_effect = readline
        proc.stdout = stream
        self.child.read_log(proc, generation=generation)

        self.assertIs(self.child.proc, replacement)
        self.assertEqual(self.child.error, 'New-generation diagnostic.')
        self.assertFalse(self.child.blocked)
        self.assertEqual([event['message'] for event in self.manager.logs],
                         ['Test SSH: First-generation diagnostic.'])
        stream.close.assert_called_once()

    def test_same_generation_late_stderr_refines_exit_fallback_after_proc_cleared(self):
        proc = self.process(code=7, text='Network is unreachable.\n')
        self.child.proc = proc
        self.child.ready = True
        self.own(proc)
        generation = self.child.generation

        with mock.patch.object(pm.time, 'monotonic', return_value=100.0):
            self.child.tick()
        self.assertIsNone(self.child.proc)
        self.assertFalse(self.child.ready)
        self.assertEqual(self.child.generation, generation)
        fallback = self.child.error
        self.assertIn('7', fallback)

        self.child.read_log(proc, generation=generation)

        self.assertEqual(self.child.error, 'Network is unreachable.')
        messages = [event['message'] for event in self.manager.logs]
        self.assertTrue(any(fallback in message for message in messages))
        self.assertIn('Test SSH: Network is unreachable.', messages)

    def test_successful_stop_invalidates_reader_only_after_termination(self):
        proc = self.process(text='Permission denied after stop.\n')
        self.child.proc = proc
        self.child.ready = True
        generation = self.child.generation
        ownership = self.own(proc)

        def while_waiting(**_kwargs):
            self.assertEqual(self.child.generation, generation)
            self.assertIs(self.child.proc, proc)
            return 0

        proc.wait.side_effect = while_waiting
        self.child.stop()
        history = self.manager.logs.snapshot()
        self.assertGreater(self.child.generation, generation)
        self.assertIsNone(self.child.proc)
        self.assertFalse(self.child.ready)
        self.assertFalse(ownership.exists())

        self.child.read_log(proc, generation=generation)
        self.assertEqual(self.child.error, '')
        self.assertFalse(self.child.blocked)
        self.assertEqual(self.manager.logs.snapshot(), history)

    def test_failed_stop_keeps_process_epoch_and_accepts_its_diagnostics(self):
        proc = self.process(text='Permission denied during failed stop.\n')
        self.child.proc = proc
        generation = self.child.generation
        ownership = self.own(proc)
        self.killpg.side_effect = OSError('Test-only termination failure')

        with self.assertRaisesRegex(OSError, 'Test-only termination failure'):
            self.child.stop()

        self.assertIs(self.child.proc, proc)
        self.assertEqual(self.child.generation, generation)
        self.assertTrue(ownership.exists())
        self.child.read_log(proc, generation=generation)
        self.assertEqual(self.child.error, 'Permission denied during failed stop.')
        self.assertTrue(self.child.blocked)
        self.assertIn('Test SSH: Permission denied during failed stop.',
                      [event['message'] for event in self.manager.logs])

    def test_nonzero_exit_fallback_is_logged_once(self):
        proc = self.process(code=23)
        self.child.proc = proc
        self.child.ready = True
        ownership = self.own(proc)

        with mock.patch.object(pm.time, 'monotonic', return_value=100.0):
            self.child.tick()
            self.child.tick()

        self.assertIsNone(self.child.proc)
        self.assertFalse(self.child.ready)
        self.assertFalse(ownership.exists())
        errors = [event for event in self.manager.logs if event['level'] == 'error']
        self.assertEqual(len(errors), 1)
        self.assertIn('23', self.child.error)
        self.assertIn(self.child.error, errors[0]['message'])
        self.assertEqual(errors[0]['repeats'], 1,
                         'Deduplication must not hide repeated fallback logging')
        self.popen.assert_not_called()

    def test_specific_exit_error_is_not_replaced_or_logged_again(self):
        proc = self.process(code=255)
        self.child.proc = proc
        self.child.error = 'Specific authentication diagnostic.'
        self.child.blocked = True
        self.manager.log('error', 'Test SSH: ' + self.child.error, self.child.tunnel_id)
        history = self.manager.logs.snapshot()

        with mock.patch.object(pm.time, 'monotonic', return_value=100.0):
            self.child.tick()
            self.child.tick()

        self.assertEqual(self.child.error, 'Specific authentication diagnostic.')
        self.assertEqual(self.manager.logs.snapshot(), history)
        self.popen.assert_not_called()

if __name__ == '__main__':
    unittest.main()
