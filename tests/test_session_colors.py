"""Session color metadata never changes SSH ownership or credential state."""
import copy
import json
import tempfile
import unittest
from unittest import mock

from test_security import bare_manager
from configuration_portability import export_configuration, session_color


class SessionColors(unittest.TestCase):
    def setUp(self):
        self.scratch=tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.manager=bare_manager(self.scratch.name)
        self.manager.config['portable_origin']='a'*32
        self.manager.validate_all(self.manager.config)
        self.manager.save();self.manager.write_ssh_config()

    def test_legacy_read_and_export_do_not_generate_or_write_color(self):
        manager=self.manager
        before=manager.config_path.read_bytes()
        self.assertTrue(all('color' not in row for row in manager.state()['servers']))
        exported=manager.export_configuration()['sessions']
        self.assertEqual([row['color'] for row in exported],[session_color(row) for row in manager.config['servers']])
        self.assertEqual(before,manager.config_path.read_bytes())

    def test_active_color_only_update_preserves_order_runtime_ssh_and_credentials(self):
        manager=self.manager
        runtime={'pid':912345,'desired_running':True}
        manager.runtime['socks_uk']=runtime
        before=copy.deepcopy(manager.config)
        ssh=(manager.data/'ssh_config').read_bytes()
        with mock.patch.object(manager,'write_ssh_config') as write_ssh, \
                mock.patch.object(manager,'keychain') as keychain:
            manager.mutate('servers','iran',{'color':'#a28bcb'})
            write_ssh.assert_not_called();keychain.assert_not_called()
        expected=copy.deepcopy(before);expected['servers'][0]['color']='#A28BCB'
        self.assertEqual(manager.config,expected)
        self.assertEqual(json.loads(manager.config_path.read_text()),expected)
        self.assertIs(manager.runtime['socks_uk'],runtime)
        self.assertEqual((manager.data/'ssh_config').read_bytes(),ssh)
        with self.assertRaises(ValueError):
            manager.mutate('servers','iran',{'color':'#58A6A6','host':'192.0.2.99'})

    def test_color_validation_is_atomic_before_auth_or_config_changes(self):
        manager=self.manager
        before=copy.deepcopy(manager.config);disk=manager.config_path.read_bytes()
        for color in (None,123,True,'red','#abc','#12345678','#12345G','#123456\n','var(--ink)','</style>'):
            for payload in ({'color':color},{'color':color,'password':'synthetic never store'}):
                with self.subTest(payload=payload),mock.patch.object(manager,'keychain') as keychain:
                    with self.assertRaises(ValueError):manager.mutate('servers','iran',payload)
                    self.assertEqual(manager.config,before)
                    self.assertEqual(manager.config_path.read_bytes(),disk)
                    keychain.assert_not_called()

    def test_color_save_failure_rolls_back_and_same_color_is_noop(self):
        manager=self.manager
        before=copy.deepcopy(manager.config);disk=manager.config_path.read_bytes()
        with mock.patch.object(manager,'save',side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError):manager.mutate('servers','iran',{'color':'#58A6A6'})
        self.assertEqual(manager.config,before);self.assertEqual(manager.config_path.read_bytes(),disk)
        manager.mutate('servers','iran',{'color':'#58A6A6'})
        with mock.patch.object(manager,'save') as save:
            manager.mutate('servers','iran',{'color':'#58a6a6'});save.assert_not_called()

    def test_full_session_save_and_reopen_retain_chosen_color(self):
        manager=self.manager
        manager.mutate('servers','iran',{'name':'Synthetic colored session','color':'#7d9dd3'})
        reopened=bare_manager(self.scratch.name,json.loads(manager.config_path.read_text()))
        reopened.validate_all(reopened.config)
        self.assertEqual(reopened.server('iran')['color'],'#7D9DD3')
        self.assertEqual(reopened.state()['servers'][-1]['color'],'#7D9DD3')

    def test_portable_color_roundtrip_idempotence_undo_and_legacy_import(self):
        manager=self.manager
        foreign=copy.deepcopy(manager.config);foreign['portable_origin']='b'*32
        foreign['tunnels']=[];foreign['servers'][0]['color']='#58A6A6'
        document=export_configuration(foreign);before=copy.deepcopy(manager.config)
        document['sessions'][1].pop('color')  # Version-one files may omit color.
        first=manager.preview_import(document);manager.apply_import(first['ticket'])
        imported=[s for s in manager.config['servers'] if s.get('portable_origin')=='b'*32]
        self.assertEqual(next(s for s in imported if s['portable_id']=='iran')['color'],'#58A6A6')
        legacy=next(s for s in imported if s['portable_id']=='uk')
        self.assertNotEqual(legacy['id'],'uk')
        self.assertEqual(legacy['color'],session_color({'id':'uk'}))
        self.assertEqual(session_color(dict(id=legacy['id'],portable_id='uk')),legacy['color'])
        second=manager.preview_import(document)
        with mock.patch.object(manager,'save') as save:
            self.assertFalse(manager.apply_import(second['ticket'])['changed']);save.assert_not_called()
        manager.undo_import();self.assertEqual(manager.config,before)
        for value in ('#123','url(synthetic)',None):
            invalid=copy.deepcopy(document);invalid['sessions'][0]['color']=value
            disk=manager.config_path.read_bytes()
            with self.assertRaises(ValueError):manager.preview_import(invalid)
            self.assertEqual(manager.config,before);self.assertEqual(manager.config_path.read_bytes(),disk)


if __name__=='__main__':unittest.main()
