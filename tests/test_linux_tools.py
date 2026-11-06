"""Ubuntu Tools filesystem and narrowly allowed external-navigation contracts."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import linux_desktop as panel


def document():
    return dict(format='HopHarbor configuration',schema_version=1,origin='a'*32,
                sessions=[dict(id='synthetic',host='127.0.0.1',username='synthetic',identity_required=True)],
                forwards=[],settings={})


class LinuxToolsTests(unittest.TestCase):
    def test_official_release_urls_are_exact(self):
        for value in (panel.REPOSITORY_URL, panel.REPOSITORY_URL+'/releases',
                      panel.REPOSITORY_URL+'/releases/tag/v1.4.2',panel.REPOSITORY_URL+'/releases/tag/1.4.2'):
            self.assertTrue(panel.official_url_allowed(value),value)
        for value in (None,'http://github.com/kiyanibehzad/HopHarbor/releases',
                      'https://github.com.evil.invalid/kiyanibehzad/HopHarbor/releases',
                      'https://github.com@evil.invalid/kiyanibehzad/HopHarbor/releases',
                      'https://user@github.com/kiyanibehzad/HopHarbor/releases',
                      panel.REPOSITORY_URL+':443/releases',
                      'https://github.com:443/kiyanibehzad/HopHarbor/releases',
                      panel.REPOSITORY_URL+'/releases?x=1',panel.REPOSITORY_URL+'/releases#fragment',
                      panel.REPOSITORY_URL+'/releases/tag/v1.4.2-preview.1',
                      panel.REPOSITORY_URL+'/releases/tag/v1.4.2/extra',panel.REPOSITORY_URL+'/releases/latest'):
            self.assertFalse(panel.official_url_allowed(value),value)

    def test_export_preserves_portable_data_and_rejects_device_fields(self):
        value=document();value['sessions'][0]['color']='#58A6A6'
        self.assertEqual(json.loads(panel.portable_export_bytes(value)),value)
        for field in ('password','identity_file','host_key','token','portable_origin'):
            bad=document();bad['sessions'][0][field]='synthetic-sensitive-value'
            with self.assertRaises(ValueError):panel.portable_export_bytes(bad)
        for mutate in (lambda d:d.update(path='/tmp/from-page'),lambda d:d.update(schema_version=True),
                       lambda d:d.update(settings={'keychain':True}),
                       lambda d:d['sessions'][0].update(name='x'*(panel.FILE_LIMIT+1))):
            bad=document();mutate(bad)
            with self.assertRaises(ValueError):panel.portable_export_bytes(bad)

    def test_atomic_private_export_replaces_only_chosen_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch);target=root/'chosen.json';other=root/'other.json'
            target.write_text('old');target.chmod(0o644);other.write_text('untouched')
            data=panel.portable_export_bytes(document());panel.write_export_file(target,data)
            self.assertEqual(target.read_bytes(),data)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            self.assertEqual(other.read_text(),'untouched')
            link=root/'link.json';link.symlink_to(other)
            with self.assertRaises(ValueError):panel.write_export_file(link,data)
            self.assertEqual(other.read_text(),'untouched')
            with self.assertRaises(OSError):panel.write_export_file(root/'missing'/'file.json',data)
            self.assertEqual(list(root.glob('.hopharbor-export-*')),[])

    def test_import_requires_bounded_regular_file_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch);target=root/'file.json';target.write_bytes(b'{}')
            self.assertTrue(panel.import_file_allowed(target))
            link=root/'link.json';link.symlink_to(target)
            with self.assertRaises(OSError):panel.import_file_allowed(link)
            self.assertFalse(panel.import_file_allowed(root))
            target.write_bytes(b'x'*(panel.FILE_LIMIT+1));self.assertFalse(panel.import_file_allowed(target))
            fifo=root/'fifo';os.mkfifo(fifo);self.assertFalse(panel.import_file_allowed(fifo))
