"""Synthetic contracts for portable configuration and scoped Session controls."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from test_security import bare_manager, base_config, pm
from configuration_portability import export_configuration, preview, digest
from release_check import API, RELEASES, ReleaseChecker, interpret


class ToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name)
        self.manager.config['portable_origin'] = 'a' * 32
        self.manager.validate_all(self.manager.config)
        self.manager.write_ssh_config()
        self.manager.save()

    def foreign_document(self):
        config = base_config()
        config['servers'].reverse()  # Child comes before parent on purpose.
        config['portable_origin'] = 'b' * 32
        config['servers'][0]['identity_file'] = '/private/synthetic/key'
        config['servers'][0]['password'] = 'MUST-NOT-EXPORT'
        config['servers'][0]['host_key'] = 'MUST-NOT-EXPORT'
        config['servers'][0]['has_password'] = True
        config['tunnels'][0].update(id='uk', autostart=True)  # Independent ID namespace.
        config['tunnels'][0]['local_port'] = 24831
        self.manager.validate_all(dict(servers=[dict(s, identity_file='') for s in config['servers']], tunnels=config['tunnels']))
        # Normalize non-device defaults without reading an actual identity file.
        for s in config['servers']:
            s.setdefault('auth_mode', 'key' if s.get('identity_file') else 'agent')
            s.setdefault('keepalive_interval', 30)
            s.setdefault('keepalive_count', 3)
        return export_configuration(config)

    def test_export_excludes_local_identity_authentication_and_runtime(self):
        document = self.foreign_document()
        text = json.dumps(document)
        for forbidden in ('MUST-NOT-EXPORT', '/private/', 'password', 'host_key', 'has_password', 'pid'):
            self.assertNotIn(forbidden, text)
        self.assertTrue(document['sessions'][0]['identity_required'])

    def test_import_unordered_tree_repeated_merge_and_id_namespace(self):
        document = self.foreign_document()
        before = copy.deepcopy(self.manager.config)
        with mock.patch.object(self.manager, 'port_is_open', return_value=False), \
                mock.patch.object(self.manager, 'start') as start, mock.patch.object(self.manager, 'keychain') as keychain:
            result = self.manager.preview_import(document)
            self.assertEqual(self.manager.config, before)
            self.assertEqual(result['summary']['sessions_added'], 2)
            self.manager.apply_import(result['ticket'])
            imported = [s for s in self.manager.config['servers'] if s.get('portable_origin') == 'b'*32]
            by_id = {s['portable_id']: s for s in imported}
            self.assertEqual(by_id['uk']['jump_id'], by_id['iran']['id'])
            self.assertNotEqual(by_id['uk']['id'], 'uk')
            forward = self.manager.config['tunnels'][-1]
            self.assertEqual(forward['server_id'], by_id['uk']['id'])
            self.assertFalse(forward['autostart'])
            second = self.manager.preview_import(document)
            self.assertEqual(second['summary'], {'sessions_added': 0, 'forwards_added': 0, 'skipped': 3})
            self.manager.apply_import(second['ticket'])
            start.assert_not_called()
            keychain.assert_not_called()
        self.assertEqual(json.loads((self.manager.data/'config-before-import.json').read_text()), before)
        self.manager.undo_import()
        self.assertEqual(self.manager.config, before)

    def test_invalid_imports_do_not_change_disk_memory_runtime_or_credentials(self):
        valid = self.foreign_document()
        cases = []
        for key, value in [('password', 'secret'), ('identity_file', '/tmp/key'), ('token', 'secret')]:
            item = copy.deepcopy(valid);item['sessions'][0][key] = value;cases.append(item)
        item=copy.deepcopy(valid);item['schema_version']=2;cases.append(item)
        item=copy.deepcopy(valid);item['sessions'][1]['jump_id']='uk';cases.append(item)
        item=copy.deepcopy(valid);item['forwards'][0]['server_id']='missing';cases.append(item)
        item=copy.deepcopy(valid);item['forwards'][0]['local_port']=True;cases.append(item)
        item=copy.deepcopy(valid);item['forwards'][0]['local_port']=20830;cases.append(item)
        item=copy.deepcopy(valid);item['sessions'].append(copy.deepcopy(item['sessions'][0]));cases.append(item)
        before, disk = copy.deepcopy(self.manager.config), self.manager.config_path.read_bytes()
        with mock.patch.object(self.manager, 'port_is_open', return_value=False), mock.patch.object(self.manager, 'keychain') as keychain:
            for document in cases:
                with self.subTest(document=document), self.assertRaises(ValueError):
                    self.manager.preview_import(document)
                self.assertEqual(self.manager.config,before)
                self.assertEqual(self.manager.config_path.read_bytes(),disk)
            keychain.assert_not_called()

    def test_preview_is_bound_to_revision_and_apply_failure_rolls_back(self):
        with mock.patch.object(self.manager, 'port_is_open', return_value=False):
            result=self.manager.preview_import(self.foreign_document())
        self.manager.config['servers'][0]['name']='Changed after preview'
        with self.assertRaisesRegex(ValueError,'Preview|preview'):
            self.manager.apply_import(result['ticket'])
        with mock.patch.object(self.manager, 'port_is_open', return_value=False):
            result=self.manager.preview_import(self.foreign_document())
        before=copy.deepcopy(self.manager.config)
        original=self.manager.write_ssh_config
        with mock.patch.object(self.manager,'write_ssh_config',side_effect=[OSError('synthetic disk failure'),None]):
            with self.assertRaises(OSError):self.manager.apply_import(result['ticket'])
        self.assertEqual(self.manager.config,before)
        self.assertEqual(json.loads(self.manager.config_path.read_text()),before)
        original()

    def test_session_bulk_starts_parent_before_children_without_starting_stopped_on_reconnect(self):
        calls=[]
        with mock.patch.object(self.manager,'start_session_transport',side_effect=lambda i:calls.append(('session',i))), \
                mock.patch.object(self.manager,'start',side_effect=lambda i:calls.append(('forward',i))):
            result=self.manager.bulk_action('servers','connect')
            self.assertTrue(result['ok'])
            self.assertEqual(calls,[('session','iran'),('forward','socks_uk')])
            calls.clear()
            self.manager.runtime={'socks_uk':{}}
            with mock.patch.object(self.manager,'stop') as stop:
                self.manager.bulk_action('servers','reconnect')
                self.assertEqual(calls,[('forward','socks_uk')])
                stop.assert_not_called()

    def test_bulk_failure_does_not_hold_unrelated_routes_or_reset_active(self):
        self.manager.config['servers'].append(dict(id='other',name='Other',host='192.0.2.42',port=22,username='alice'))
        calls=[]
        def session(ident):
            calls.append(ident)
            if ident=='iran':raise ValueError('synthetic parent failure')
        self.manager.runtime={'socks_uk':{}}
        with mock.patch.object(self.manager,'start_session_transport',side_effect=session), \
                mock.patch.object(self.manager,'start') as start, mock.patch.object(self.manager,'stop') as stop:
            result=self.manager.bulk_action('servers','connect')
            self.assertEqual(calls,['iran','other'])
            self.assertEqual(result['summary']['failed'],1)
            start.assert_not_called();stop.assert_not_called()

    def test_bulk_reconnect_cannot_resurrect_a_session_stopped_while_queued(self):
        self.manager.config['tunnels']=[]
        self.manager.session_runtime={}
        for ident in ('iran','uk'):
            directory=tempfile.TemporaryDirectory()
            self.addCleanup(directory.cleanup)
            self.manager.session_runtime[ident]=dict(child=SimpleNamespace(),directory=directory,
                                                     path=Path(directory.name)/'control',status='connected')
        original=self.manager.action_generation
        reads={}
        def generation(kind,ident,advance=False):
            if not advance:
                reads[ident]=reads.get(ident,0)+1
                if ident=='uk' and reads[ident]==2:
                    self.manager.stop_session_transport(ident)
            return original(kind,ident,advance)
        with mock.patch.object(self.manager,'stop_owned_batch',return_value=[]), \
                mock.patch.object(self.manager,'action_generation',side_effect=generation), \
                mock.patch.object(self.manager,'start_session_transport') as start:
            result=self.manager.bulk_action('servers','reconnect')
        start.assert_called_once_with('iran')
        self.assertNotIn('uk',self.manager.session_runtime)
        self.assertTrue(result['results'][1]['cancelled'])

    def test_failed_reconnect_preparation_keeps_desired_runtime_and_control_directory(self):
        self.manager.config['tunnels']=[]
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        record=dict(child=SimpleNamespace(),directory=directory,path=Path(directory.name)/'control',status='connected')
        self.manager.session_runtime={'iran':record}
        with mock.patch.object(self.manager,'stop_owned_batch',return_value=[]), \
                mock.patch.object(self.manager,'start_session_transport',side_effect=ValueError('Synthetic preparation failure')):
            result=self.manager.bulk_action('servers','reconnect')
        self.assertFalse(result['ok'])
        self.assertIs(self.manager.session_runtime['iran'],record)
        self.assertEqual(record['status'],'error')
        self.assertNotIn('bulk_pending',record)
        self.assertTrue(Path(directory.name).exists())

    def test_master_readiness_checks_authenticated_owner_once_per_generation(self):
        path=self.manager.data/'control';path.touch()
        child=SimpleNamespace(proc=SimpleNamespace(pid=912345,poll=lambda:None),ready=False,server_id='iran')
        with mock.patch.object(pm.subprocess,'run',return_value=SimpleNamespace(returncode=0,stderr=b'Master running (pid=912345)\r\n')) as run:
            self.assertTrue(self.manager.control_ready(child,path))
            child.ready=True
            self.assertTrue(self.manager.control_ready(child,path))
            self.assertEqual(run.call_count,1)
            child.ready=False
            run.return_value.stderr=b'Master running (pid=999999)'
            self.assertFalse(self.manager.control_ready(child,path))

    def test_firewall_role_has_priority_over_earlier_direct_and_retry_mixes_transport_types(self):
        self.manager.config['servers'].insert(0,dict(id='direct',name='Direct first',host='192.0.2.40',port=22,username='alice'))
        # Parent owns a forward, child has only a standalone Session.
        self.manager.config['tunnels'][0]['server_id']='iran'
        self.assertEqual([s['id'] for s in self.manager.ordered_servers()],['iran','direct','uk'])
        calls=[]
        child=SimpleNamespace(tick=lambda:calls.append('parent-forward'),blocked=False,proc=None,ready=False)
        self.manager.runtime={'socks_uk':dict(ssh=[child],ports=[],gost=None,healthy=0,status='starting',last_test=None)}
        self.manager.session_runtime={'uk':{}}
        self.manager.halt=mock.Mock(wait=mock.Mock(side_effect=[False,True]))
        self.manager.next_maintenance=10**15
        with mock.patch.object(self.manager,'tick_session_transports',side_effect=lambda ident:calls.append(ident)):
            self.manager.watch()
        self.assertEqual(calls,['parent-forward','uk'])

    def test_long_running_watch_requests_the_throttled_periodic_check(self):
        self.manager.halt=mock.Mock(wait=mock.Mock(side_effect=[False,False,True]))
        self.manager.next_maintenance=10**15
        self.manager.release_checker=mock.Mock()
        self.manager.watch()
        self.assertEqual(self.manager.release_checker.check.call_count,2)

    def test_trust_ticket_is_endpoint_revision_and_session_bound(self):
        original=copy.deepcopy(self.manager.config['servers'][0])
        self.manager.trust_proofs={'iran':dict(ticket='proof',expires=10**15,revision=digest(self.manager.config),
               original=original,host='192.0.2.99',port=2222,keys=['ssh-ed25519 synthetic'])}
        record=dict(original,host='192.0.2.99',port=2222)
        self.assertIn('[192.0.2.99]:2222',self.manager.verified_pin('iran',record,'proof'))
        for change in ({'port':2223},{'jump_id':'uk'},{'username':'other'}):
            with self.assertRaises(ValueError):self.manager.verified_pin('iran',dict(record,**change),'proof')
        with self.assertRaises(ValueError):self.manager.verified_pin('uk',record,'proof')
        self.manager.config['servers'][0]['name']='Revision changed'
        with self.assertRaises(ValueError):self.manager.verified_pin('iran',record,'proof')

    def test_saving_changed_trusted_endpoint_without_proof_preserves_old_reference(self):
        known=self.manager.data/'known_hosts'
        known.write_text('192.0.2.10 ssh-ed25519 synthetic\n')
        before=copy.deepcopy(self.manager.config)
        disk=self.manager.config_path.read_bytes();pins=known.read_bytes()
        with mock.patch.object(self.manager,'keychain') as keychain:
            with self.assertRaisesRegex(ValueError,'previously trusted key'):
                self.manager.mutate('servers','iran',dict(host='192.0.2.99',password='synthetic must not save'))
            keychain.assert_not_called()
        self.assertEqual(self.manager.config,before)
        self.assertEqual(self.manager.config_path.read_bytes(),disk)
        self.assertEqual(known.read_bytes(),pins)

    def test_shutdown_cancels_and_reaps_owned_inflight_endpoint_proof(self):
        self.manager.service_lock=None
        (self.manager.data/'known_hosts').write_text('192.0.2.10 ssh-ed25519 synthetic\n')
        entered, stopped = threading.Event(), threading.Event()
        child=SimpleNamespace(proc=None,ready=False,blocked=False)
        def spawn():child.proc=SimpleNamespace(poll=lambda:None)
        def stop():child.proc=None;stopped.set()
        child.spawn,child.stop=spawn,stop
        errors=[]
        def check(*args):entered.set();stopped.wait(2);return False
        def prove():
            try:self.manager.prove_endpoint('iran',dict(host='192.0.2.90',port=2222))
            except ValueError as error:errors.append(str(error))
        with mock.patch.object(self.manager,'make_child',return_value=child), \
                mock.patch.object(self.manager,'stop_owned_batch',side_effect=lambda children:([c.stop() for c in children] and [])), \
                mock.patch.object(self.manager,'control_ready',side_effect=check):
            thread=threading.Thread(target=prove);thread.start()
            self.assertTrue(entered.wait(2))
            records=list(self.manager.proof_runtime.values())
            path=Path(records[0]['directory'].name)
            self.manager.shutdown()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(self.manager.proof_runtime)
            self.assertFalse(path.exists())
        self.assertTrue(stopped.is_set());self.assertTrue(errors)
        self.assertFalse(getattr(self.manager,'trust_proofs',{}))

    def test_missing_imported_identity_guards_all_upstream_routes_before_any_spawn(self):
        self.manager.config['servers'][0]['identity_required']=True
        with mock.patch.object(self.manager,'make_child') as child, mock.patch.object(self.manager,'start_session_transport') as start:
            with self.assertRaisesRegex(ValueError,'Firewall chain'):
                self.manager.start('socks_uk')
            with self.assertRaisesRegex(ValueError,'Firewall chain'):
                self.manager.check_identity_setup(self.manager.server('uk'))
            child.assert_not_called();start.assert_not_called()

    def test_port_conflict_or_preparation_failure_preserves_existing_standalone(self):
        self.manager.config['servers'][1]['identity_required']=False
        with mock.patch.object(pm,'port_open',return_value=True), mock.patch.object(self.manager,'stop_session_transport') as stop:
            with self.assertRaisesRegex(ValueError,'Another application'):
                self.manager.start('socks_uk')
            stop.assert_not_called()
        with mock.patch.object(pm,'port_open',return_value=False), \
                mock.patch.object(pm,'Child',side_effect=ValueError('Synthetic preparation failure')), \
                mock.patch.object(self.manager,'stop_session_transport') as stop:
            with self.assertRaisesRegex(ValueError,'preparation'):
                self.manager.start('socks_uk')
            stop.assert_not_called()
        self.assertFalse(self.manager.runtime)


class ReleaseTests(unittest.TestCase):
    def document(self, tag):
        return dict(draft=False,prerelease=False,tag_name=tag,html_url=RELEASES+'/tag/'+tag)

    def test_numeric_stable_comparison_and_strict_project_url(self):
        for tag,status in [('v1.10.0','available'),('v1.4.0','current'),('v1.3.9','older')]:
            self.assertEqual(interpret(self.document(tag),'1.4.0')['status'],status)
        for document in [self.document('v1.5.0-rc1'),dict(self.document('v1.5.0'),prerelease=True),
                         dict(self.document('v1.5.0'),draft=True),dict(self.document('v1.5.0'),html_url='https://example.com')]:
            with self.assertRaises(ValueError):interpret(document,'1.4.0')

    def test_outage_malformed_large_and_redirect_response_are_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            for payload,url in [(b'bad',API),(b'x'*65537,API),(json.dumps(self.document('v1.5.0')).encode(),'https://example.com')]:
                response=io.BytesIO(payload);response.geturl=lambda:url
                checker=ReleaseChecker(Path(folder)/'cache','1.4.0',pm.atomic_json,opener=mock.Mock(return_value=response))
                checker.last_attempt=100;checker.running=True;checker._fetch()
                self.assertEqual(checker.snapshot()['status'],'unavailable')
            checker=ReleaseChecker(Path(folder)/'cache2','1.4.0',pm.atomic_json,opener=mock.Mock(side_effect=OSError('offline')))
            checker.last_attempt=100;checker.running=True;checker._fetch()
            self.assertEqual(checker.snapshot()['status'],'unavailable')

    def test_cache_and_manual_throttle_do_not_start_network_workers(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'cache'
            pm.atomic_json(path,dict(checked_at=100,document=self.document('v1.5.0')))
            checker=ReleaseChecker(path,'1.4.0',pm.atomic_json,clock=lambda:110)
            with mock.patch('release_check.threading.Thread') as worker:
                self.assertFalse(checker.check());self.assertFalse(checker.check(manual=True));worker.assert_not_called()
            self.assertEqual(checker.snapshot()['status'],'available')
            checker.clock=lambda:100+24*3600+1
            with mock.patch('release_check.threading.Thread') as worker:
                self.assertTrue(checker.check())
                worker.return_value.start.assert_called_once()

    def test_daily_check_survives_open_panel_cache_reopen_and_overdue_wake(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'cache';clock=[100000.0];requests=[]
            def opener(request,timeout):
                requests.append((request.full_url,request.get_method(),request.data,timeout))
                response=io.BytesIO(json.dumps(self.document('v1.3.2')).encode())
                response.geturl=lambda:API
                return response
            checker=ReleaseChecker(path,'1.4.0',pm.atomic_json,opener=opener,clock=lambda:clock[0])
            with mock.patch('release_check.threading.Thread') as worker:
                self.assertTrue(checker.check())
                for _ in range(30):self.assertFalse(checker.check())
                worker.return_value.start.assert_called_once()
                checker._fetch()
                clock[0]+=3600
                for _ in range(30):self.assertFalse(checker.check())
                reopened=ReleaseChecker(path,'1.4.0',pm.atomic_json,opener=opener,clock=lambda:clock[0])
                self.assertFalse(reopened.check())
                # A long-running controller's first opportunity after sleep.
                clock[0]+=24*3600
                self.assertTrue(checker.check())
                self.assertFalse(checker.check())
                checker._fetch()
                self.assertEqual(worker.return_value.start.call_count,2)
            self.assertEqual(requests,[(API,'GET',None,5)]*2)
            self.assertEqual(checker.snapshot()['status'],'older')


if __name__=='__main__':unittest.main()
