#!/usr/bin/env python3
"""Opt-in loopback SSH acceptance checks, with private external fixtures only."""
import argparse
import contextlib
import copy
import getpass
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import socket
import sys
import tempfile
import threading
import time
import traceback

from local_smoke import ROOT, LocalManager, free_port, make_ssh_server, pm, port_open, wait_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--host-key-type', choices=('ed25519','rsa'), default='ed25519')
    args = parser.parse_args()
    if not args.report.is_absolute() or args.report.exists():
        parser.error('Choose a fresh absolute private report path.')
    try:
        args.report.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        parser.error('The report belongs outside the public checkout.')
    os.umask(0o077)
    cleanup, checks, manager = [], [], None
    result = {'host_key_type':args.host_key_type,'external_connections': False, 'production_settings_changed': False, 'checks': checks}
    with tempfile.TemporaryDirectory(prefix='hh-acceptance-', dir=args.report.parent) as scratch:
        folder = Path(scratch)
        try:
            excluded = set()
            parent_port, old_port, new_port, wrong_port = [free_port(excluded) for _ in range(4)]
            parent_key, parent_host = make_ssh_server(folder, 'parent', parent_port, getpass.getuser(), cleanup)
            edge_key, edge_host = make_ssh_server(folder, 'edge', old_port, getpass.getuser(), cleanup, host_type=args.host_key_type)
            make_ssh_server(folder, 'wrong', wrong_port, getpass.getuser(), cleanup, host_type=args.host_key_type)
            clone = folder / 'clone-config'
            clone.write_text((folder/'edge-sshd_config').read_text().replace('Port '+str(old_port)+'\n', 'Port '+str(new_port)+'\n').replace('edge.pid','clone.pid'))
            log = (folder/'clone.log').open('ab')
            proc = subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(clone)], stdin=subprocess.DEVNULL,
                                    stdout=log,stderr=log,start_new_session=True)
            def stop_clone():
                if proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGTERM)
                    proc.wait(timeout=4)
                log.close()
            cleanup.append(stop_clone)
            wait_for(lambda:port_open(new_port),timeout=5)
            # Deliberately realistic, long macOS-style path with spaces. Only
            # the private control socket uses a short, private /tmp directory.
            data = folder/'Library'/'Application Support'/'HopHarbor synthetic acceptance'/'private manager data'
            data.mkdir(parents=True,mode=0o700)
            config={'servers':[
                dict(id='parent',name='Synthetic parent',host='127.0.0.1',port=parent_port,username=getpass.getuser(),auth_mode='key',identity_file=str(parent_key),jump_id=None),
                dict(id='edge',name='Synthetic child',host='127.0.0.1',port=old_port,username=getpass.getuser(),auth_mode='key',identity_file=str(edge_key),jump_id='parent')], 'tunnels':[]}
            pm.atomic_json(data/'config.json',config)
            known=''.join('[127.0.0.1]:%s %s\n'%(p,' '.join(k.read_text().split()[:2])) for p,k in [(parent_port,parent_host),(old_port,edge_host)])
            pm.write_private_text(data/'known_hosts',known)
            manager=LocalManager(data,ROOT,free_port(excluded))
            manager.child_env.pop('SSH_AUTH_SOCK',None)
            ssh_config=data/'ssh_config'
            ssh_config.write_text(ssh_config.read_text().replace('Host *\n','Host *\n  IdentityAgent none\n',1))
            manager.session_action('edge','connect')
            def edge_status():
                return next(s for s in manager.state()['servers'] if s['id']=='edge')['connection_status']
            wait_for(lambda:edge_status()=='connected',description='authenticated no-forward session through parent')
            child=manager.session_runtime['edge']['child']
            assert child.proc and child.ready and manager.runtime=={}
            original_pid=child.proc.pid
            manager.session_action('edge','reconnect')
            wait_for(lambda:edge_status()=='connected',description='no-forward reconnect')
            assert manager.session_runtime['edge']['child'].proc.pid!=original_pid
            manager.recover_after_wake()
            wait_for(lambda:edge_status()=='connected',description='no-forward wake recovery')
            manager.session_action('edge','disconnect')
            assert not manager.session_runtime
            checks.append('Authenticated no-forward SSH via Firewall; reconnect, wake, disconnect and owned cleanup')
            before=(data/'known_hosts').read_bytes()
            proof=manager.prove_endpoint('edge',dict(host='127.0.0.1',port=new_port))
            assert (data/'known_hosts').read_bytes()==before
            manager.mutate('servers','edge',dict(host='127.0.0.1',port=new_port,trust_ticket=proof['ticket']))
            assert (data/'known_hosts').read_bytes().startswith(before)
            assert '[127.0.0.1]:%s '%new_port in (data/'known_hosts').read_text()
            checks.append('New endpoint proves old host-key possession and user authentication through strict Firewall; Save alone pins')
            before=(data/'known_hosts').read_bytes()
            try:
                manager.prove_endpoint('edge',dict(host='127.0.0.1',port=wrong_port))
                raise AssertionError('A different host key was accepted')
            except ValueError:
                pass
            assert (data/'known_hosts').read_bytes()==before
            checks.append('Different host key rejected without any pin mutation')
            manager.mutate('servers','edge',dict(identity_file=str(parent_key)))
            try:
                manager.prove_endpoint('edge',dict(host='127.0.0.1',port=old_port))
                raise AssertionError('Failed user authentication was accepted')
            except ValueError:
                pass
            manager.session_action('edge','connect')
            wait_for(lambda:edge_status()=='error',description='rejected no-forward authentication')
            assert not manager.session_runtime['edge']['child'].ready
            manager.session_action('edge','disconnect')
            assert (data/'known_hosts').read_bytes()==before
            checks.append('Authentication failure never becomes connected, never pins, and stops cleanly')
            # Three owned synthetic processes ignore TERM. This exercises the
            # actual batch deadline and measures a concurrent panel-state read.
            stubborn = []
            for index in range(3):
                ident='stubborn'+str(index)
                manager.config['servers'].append(dict(manager.server('parent'),id=ident,name='Synthetic stubborn '+str(index)))
                directory=tempfile.TemporaryDirectory(prefix='hh-stubborn-',dir='/tmp')
                child=manager.make_child([sys.executable,'-u','-c',
                    'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("fixture ready",flush=True);time.sleep(90)'],
                    'Synthetic stubborn',ident,ident)
                child.spawn()
                manager.session_runtime[ident]=dict(child=child,path=Path(directory.name)/'control',directory=directory,status='connecting')
                stubborn.append(child)
            wait_for(lambda:all(c.error=='fixture ready' for c in stubborn),timeout=5)
            processes=[c.proc for c in stubborn]
            observation={}
            def observe():
                started=time.monotonic();manager.state();observation['state_wait_seconds']=time.monotonic()-started
            with manager.lock:
                reader=threading.Thread(target=observe);reader.start()
                started=time.monotonic();manager.recover_after_wake()
                elapsed=time.monotonic()-started
                manager.stop_session_transports(['stubborn'+str(i) for i in range(3)])
            reader.join(timeout=3)
            assert elapsed<2 and observation['state_wait_seconds']<2
            assert all(p.poll() is not None for p in processes)
            result['stubborn_wake_seconds']=round(elapsed,3)
            result.update({k:round(v,3) for k,v in observation.items()})
            checks.append('Three TERM-resistant owned processes share one wake deadline; concurrent state responds within two seconds')

            # A real SSH proof stalled before key exchange belongs to shutdown.
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4)
            sink_port=listener.getsockname()[1]
            done=threading.Event();accepted=[]
            def sink():
                listener.settimeout(.2)
                while not done.is_set():
                    try:
                        client,_=listener.accept();accepted.append(client)
                    except socket.timeout:pass
                    except OSError:break
            sink_thread=threading.Thread(target=sink,daemon=True);sink_thread.start()
            proof_errors=[]
            def proof_call():
                try:manager.prove_endpoint('edge',dict(host='127.0.0.1',port=sink_port))
                except ValueError as error:proof_errors.append(str(error))
            proof_thread=threading.Thread(target=proof_call);proof_thread.start()
            wait_for(lambda:bool(getattr(manager,'proof_runtime',{})),timeout=5)
            with manager.lock:
                proof_children=[r['child'] for r in manager.proof_runtime.values()]
                proof_processes=[c.proc for c in proof_children if c.proc]
            manager.shutdown();proof_thread.join(timeout=3)
            done.set();listener.close();sink_thread.join(timeout=1)
            for client in accepted:client.close()
            assert proof_processes and all(p.poll() is not None for p in proof_processes)
            assert not proof_thread.is_alive() and proof_errors and not manager.proof_runtime
            assert (data/'known_hosts').read_bytes()==before
            checks.append('Shutdown cancels and reaps an in-flight real SSH endpoint proof without changing trust')
            assert not list((data/'runtime').glob('child-*.json'))
            result['ok']=True
        except Exception as error:
            result.update(ok=False,error=str(error).replace(str(folder),'<private-fixture>'))
            result['traceback'] = traceback.format_exc()
            if manager:
                result['diagnostic_logs'] = manager.state()['logs']
                result['sessions'] = [{k:s.get(k) for k in ('id','connection_status','last_error','active_ssh_count')} for s in manager.state()['servers']]
        finally:
            if manager:
                with contextlib.suppress(Exception):manager.shutdown()
            for stop in reversed(cleanup):
                with contextlib.suppress(Exception):stop()
    pm.atomic_json(args.report,result)
    print(json.dumps(result,indent=2))
    return 0 if result.get('ok') else 1


if __name__=='__main__':raise SystemExit(main())
