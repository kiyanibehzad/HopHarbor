"""Ensure housekeeping never removes active or unrelated local configuration."""
import json
from pathlib import Path
import tempfile
import unittest

from test_security import bare_manager


class LocalCleanupTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.manager = bare_manager(self.scratch.name)
        self.runtime = Path(self.scratch.name) / 'runtime'

    def generated(self, ident):
        path = self.runtime / (ident + '.json')
        path.write_text(json.dumps(self.manager.gost_config(
            {'id': ident, 'local_port': 18080, 'kind': 'socks'}, [28080])))
        return path

    def test_only_inactive_generated_proxy_configs_are_removed(self):
        active = self.generated('active_proxy')
        stopped = self.generated('stopped_proxy')
        self.manager.runtime['active_proxy'] = {}
        unrelated = self.runtime / 'notes.json'
        unrelated.write_text('{"notes":"test-only user document"}')
        ownership = self.runtime / 'child-999999.json'
        ownership.write_text('{"pid":999999,"argv":["test-only"]}')
        temporary = self.runtime / 'test.json.tmp'
        temporary.write_text('test-only incomplete write')
        self.manager.maintain_local_files()
        self.assertTrue(active.exists())
        self.assertFalse(stopped.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(ownership.exists())
        self.assertTrue(temporary.exists())

    def test_symlink_target_and_unrecognized_json_are_preserved(self):
        outside = Path(self.scratch.name) / 'outside.json'
        outside.write_text('{"test-only":"do not delete"}')
        linked = self.runtime / 'linked_proxy.json'
        linked.symlink_to(outside)
        invalid = self.runtime / 'broken_proxy.json'
        invalid.write_text('{')
        mismatched = self.generated('other_proxy')
        value = json.loads(mismatched.read_text())
        value['services'][0]['name'] = 'different_owner'
        mismatched.write_text(json.dumps(value))
        self.manager.maintain_local_files()
        self.assertTrue(linked.is_symlink())
        self.assertTrue(outside.exists())
        self.assertTrue(invalid.exists())
        self.assertTrue(mismatched.exists())


if __name__ == '__main__':
    unittest.main()
