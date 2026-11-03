#!/usr/bin/env python3
"""Real process/deadline acceptance check; no SSH, network or production files."""
import argparse
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest import mock

from test_security import bare_manager, pm


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if not args.report.is_absolute() or args.report.exists():parser.error('Choose a fresh private report.')
    result={'synthetic_processes':25,'ssh_connections':False,'production_changed':False}
    children=[];manager=None
    with tempfile.TemporaryDirectory(prefix='bulk-acceptance-',dir=args.report.parent) as folder:
        try:
            config={'servers':[dict(id='s'+str(i),name='Synthetic '+str(i),host='127.0.0.1',port=22,
                                    username='synthetic',jump_id=None) for i in range(26)],'tunnels':[]}
            manager=bare_manager(folder,config);manager.service_lock=None
            manager.validate_all(manager.config);manager.write_ssh_config();manager.session_runtime={}
            starts=[]
            def start(ident):
                directory=tempfile.TemporaryDirectory(prefix='hh-bulk-',dir='/tmp')
                child=manager.make_child([sys.executable,'-u','-c',
                    'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("fixture ready",flush=True);time.sleep(90)'],
                    'Synthetic batch',ident,ident)
                children.append(child);child.spawn()
                manager.session_runtime[ident]={'child':child,'path':Path(directory.name)/'control',
                                                'directory':directory,'status':'connecting'}
                starts.append(ident)
            with manager.lock:
                for i in range(25):start('s'+str(i))
            deadline=time.monotonic()+10
            while not all(c.error=='fixture ready' for c in children):
                if time.monotonic()>deadline:raise RuntimeError('Fixture readiness deadline exceeded.')
                time.sleep(.02)
            old_processes=[c.proc for c in children];starts.clear()
            stopping=threading.Event();observations={};original=manager.stop_owned_batch
            def batch(selected):stopping.set();return original(selected)
            def state_request():
                stopping.wait(5);started=time.monotonic();manager.state()
                observations['state_wait_seconds']=time.monotonic()-started
            reader=threading.Thread(target=state_request);reader.start()
            with mock.patch.object(manager,'start_session_transport',side_effect=start), \
                    mock.patch.object(manager,'stop_owned_batch',side_effect=batch):
                started=time.monotonic();response=manager.bulk_action('servers','reconnect')
                elapsed=time.monotonic()-started
            reader.join(timeout=3)
            assert response['summary']=={'requested':25,'succeeded':25,'failed':0}
            assert 's25' not in starts and len(starts)==25
            assert all(p.poll() is not None for p in old_processes)
            assert elapsed<3 and observations['state_wait_seconds']<3
            result.update(ok=True,reconnect_seconds=round(elapsed,3),
                          state_wait_seconds=round(observations['state_wait_seconds'],3),
                          stopped_entry_preserved=True,old_processes_reaped=True)
        except Exception as error:
            result.update(ok=False,error=str(error))
        finally:
            if manager:
                with manager.lock:
                    pm.Child.stop_many(children)
                with contextlib.suppress(Exception):manager.shutdown()
    pm.atomic_json(args.report,result);print(json.dumps(result,indent=2))
    return 0 if result.get('ok') else 1


if __name__=='__main__':raise SystemExit(main())
