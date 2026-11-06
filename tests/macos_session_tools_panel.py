#!/usr/bin/env python3
"""Opt-in manual native dialog fixture. Never opens SSH or the installed app.

Use the printed unique bundle for actual open/save, import preview, bulk-result,
appearance and accessibility checks. Create workspace/stop to finish and clean up.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import manager as pm


class FixtureManager(pm.Manager):
    allow_release_network = False

    def keychain(self, action, payload):
        if action == 'has':
            return dict(has_password=False, has_key_passphrase=False)
        raise AssertionError('Synthetic panel fixture cannot access credentials.')

    def start(self, ident):
        raise ValueError('Synthetic fixture: port forwarding start was recorded; no SSH was opened.')

    def start_session_transport(self, ident):
        raise ValueError('Synthetic fixture: session start was recorded; no SSH was opened.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_absolute() or workspace.exists():
        parser.error('Choose a new absolute private workspace.')
    try:
        workspace.relative_to(ROOT)
    except ValueError:
        pass
    else:
        parser.error('Fixture must remain outside the public checkout.')
    os.umask(0o077)
    workspace.mkdir(parents=True,mode=0o700)
    data = workspace/'data';data.mkdir()
    config = {'servers':[
        dict(id='direct',name='Synthetic direct',host='192.0.2.40',port=22,username='alice',jump_id=None),
        dict(id='parent',name='Synthetic Firewall',host='192.0.2.10',port=22,username='alice',jump_id=None),
        dict(id='child',name='Synthetic child',host='192.0.2.20',port=2222,username='alice',jump_id='parent')],
        'tunnels':[dict(id='parent-socks',name='Synthetic SOCKS',server_id='parent',kind='socks',local_port=24871,pool_size=2,autostart=False)]}
    pm.atomic_json(data/'config.json',config)
    server=ThreadingHTTPServer(('127.0.0.1',0),pm.Handler)
    server.daemon_threads=True
    manager=FixtureManager(data,ROOT,server.server_address[1])
    pm.Handler.manager=manager
    server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
    document=manager.export_configuration();document['origin']='b'*32
    for item in document['sessions']:item['name']='Imported '+item['name']
    document['forwards'][0].update(local_port=24872,autostart=True)
    pm.atomic_json(workspace/'import-valid.json',document)
    invalid=copy.deepcopy(document);invalid['sessions'][0]['password']='synthetic forbidden field'
    pm.atomic_json(workspace/'import-invalid.json',invalid)
    app=workspace/'HopHarbor Session Tools Test.app'
    subprocess.run([sys.executable,str(ROOT/'packaging/build_app.py'),'--output',str(app),'--data-dir',str(data)],check=True)
    info_path=app/'Contents/Info.plist'
    info=plistlib.loads(info_path.read_bytes());info['CFBundleIdentifier']='local.hopharbor.session-tools-test.'+uuid.uuid4().hex
    info['CFBundleName']='HopHarbor Session Tools Test'
    info_path.write_bytes(plistlib.dumps(info))
    subprocess.run(['/usr/bin/codesign','--force','--sign','-','--options','runtime','--identifier',info['CFBundleIdentifier'],str(app)],check=True)
    process=subprocess.Popen([str(app/'Contents/MacOS/HopHarbor')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    pm.atomic_json(workspace/'fixture.json',dict(bundle=str(app),port=manager.port,synthetic_only=True,native_pid=process.pid))
    print(json.dumps(dict(bundle=str(app),workspace=str(workspace),synthetic_only=True)),flush=True)
    try:
        while not (workspace/'stop').exists() and process.poll() is None:
            time.sleep(.25)
    finally:
        if process.poll() is None:
            process.terminate();process.wait(timeout=5)
        server.shutdown();server.server_close();manager.shutdown()
        pm.atomic_json(workspace/'cleanup.json',dict(ok=True,ssh_started=False,installed_app_changed=False))


if __name__=='__main__':main()
