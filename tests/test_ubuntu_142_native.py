#!/usr/bin/python3
"""Opt-in real Ubuntu142 Tools/UI checks; isolated generated loopback data only."""
import argparse
import contextlib
import copy
import getpass
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--app-dir',type=Path,default=ROOT)
    args=parser.parse_args()
    assert sys.platform=='linux' and args.report.is_absolute() and not args.report.exists()
    sys.path.insert(0,str(args.app_dir))
    import gi
    gi.require_version('Gtk','3.0');gi.require_version('WebKit2','4.1')
    from gi.repository import GLib,Gtk,Gio,WebKit2
    import linux_desktop as panel
    import manager as core
    from configuration_portability import export_configuration,digest
    from release_check import API,ReleaseChecker
    sys.path.insert(0,str(ROOT/'tests'))
    from local_smoke import make_ssh_server,free_port
    context=GLib.MainContext.default();checks=[]

    def passed(label):
        checks.append(label);print('PASS: '+label,flush=True)

    def spin(seconds):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            while context.pending():context.iteration(False)
            time.sleep(.01)

    def wait(predicate,label,timeout=25):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            while context.pending():context.iteration(False)
            if predicate():return
            time.sleep(.02)
        raise AssertionError('Timed out: '+label)

    def evaluate(expression):
        output=[]
        def done(view,result,_):
            try:output.append((True,json.loads(view.run_javascript_finish(result).get_js_value().to_string())))
            except Exception as error:output.append((False,type(error).__name__))
        app.browser.run_javascript('JSON.stringify(('+expression+'))',None,done,None)
        wait(lambda:output,'JavaScript completion')
        assert output[0][0],output[0][1]
        return output[0][1]

    def online():
        if app.browser is None or app.browser.is_loading():return False
        with contextlib.suppress(Exception):
            return evaluate("document.getElementById('serviceLabel')?.textContent")== 'Online'
        return False

    def action(expression):
        evaluate('(()=>{'+expression+';return true})()')
        spin(.15)

    def select_file(path,save=False):
        wait(lambda:app.file_dialog is not None,'native file dialog')
        chooser=app.file_dialog
        assert chooser.get_action()==(Gtk.FileChooserAction.SAVE if save else Gtk.FileChooserAction.OPEN)
        if save:
            chooser.set_current_folder(str(path.parent));chooser.set_current_name(path.name)
        else:
            assert chooser.set_filename(str(path))
        spin(.3)
        chooser.response(Gtk.ResponseType.ACCEPT)
        spin(.3)

    def refresh():
        action('refresh(true)');wait(online,'refreshed status')

    class FixtureManager(core.Manager):
        allow_release_network=False
        def keychain(self,command,payload):
            if command=='has':return {'has_password':False,'has_key_passphrase':False}
            raise AssertionError('No real credential storage in this UI fixture')

    cache=Path.home()/'.cache';cache.mkdir(exist_ok=True,mode=0o700)
    os.umask(0o077);cleanup=[];app=None;manager=None;server=None
    with tempfile.TemporaryDirectory(prefix='hh142-native-',dir=cache) as scratch:
        folder=Path(scratch);excluded=set();port=free_port(excluded)
        key,host=make_ssh_server(folder,'loopback',port,getpass.getuser(),cleanup)
        data=folder/'private';data.mkdir(mode=0o700)
        servers=[dict(id=ident,name=name,host='127.0.0.1',port=port,username=getpass.getuser(),
                      auth_mode='key',identity_file=str(key),jump_id=jump,**extra)
                 for ident,name,jump,extra in [('harbor','Harbor parent',None,{'color':'#58A6A6'}),
                    ('relay','Review relay','harbor',{'color':'#A28BCB'}),
                    ('studio','Studio direct',None,{'color':'#7D9DD3'}),
                    ('archive','Archive legacy',None,{})]]
        forwards=[dict(id='socks',name='Synthetic SOCKS',server_id='harbor',kind='socks',
                       local_port=free_port(excluded),pool_size=1,autostart=False),
                  dict(id='http',name='Synthetic HTTP',server_id='archive',kind='http',
                       local_port=free_port(excluded),pool_size=1,autostart=False)]
        core.atomic_json(data/'config.json',dict(servers=servers,tunnels=forwards))
        core.write_private_text(data/'known_hosts','[127.0.0.1]:%s %s\n'%(port,' '.join(host.read_text().split()[:2])))
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),core.Handler);server.daemon_threads=True
        manager=FixtureManager(data,args.app_dir,server.server_address[1]);server.manager=manager
        manager.child_env.pop('SSH_AUTH_SOCK',None)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            app=panel.desktop_application(data,args.app_dir);assert app.register(None);app.activate()
            wait(online,'native1.4.2 Overview')
            assert evaluate("document.getElementById('appVersion').textContent").startswith('v1.4.2')
            assert evaluate('location.hash')==''
            passed('Actual GTK/WebKit1.4.2/build15 bootstrap; current compact panel and cleared token fragment')
            # Real owned session-only SSH, in addition to an active Firewall child.
            manager.session_action('studio','connect');manager.session_action('relay','connect')
            wait(lambda:all(manager.session_runtime.get(i,{}).get('child') and
                            manager.session_runtime[i]['child'].ready for i in ('studio','relay')),
                 'authenticated standalone and Firewall sessions')
            refresh();action("goView('servers')")
            assert evaluate("document.querySelectorAll('.server-card').length")==4
            action("openServer()")
            assert evaluate("document.getElementById('serverColor').value.toUpperCase()") in ('#7D9DD3','#A28BCB','#C67E9B')
            action("document.getElementById('serverDialog').close()")
            assert 'color' not in manager.server('archive')
            passed('Real loopback standalone Session SSH and Session through Firewall become ready in the native panel')

            # OR within each group, AND across groups, including Firewall overlap.
            action("viewFilters.servers.status.add('connected');viewFilters.servers.status.add('disconnected');viewFilters.servers.role.add('uses');renderServers()")
            assert evaluate("document.querySelectorAll('.server-card').length")==1
            action("viewFilters.servers.role.add('firewall');renderServers()")
            assert evaluate("document.querySelectorAll('.server-card').length")==2
            action("document.getElementById('sessionSearch').value='Review';document.getElementById('sessionSearch').dispatchEvent(new Event('input'))")
            assert evaluate("document.querySelectorAll('.server-card').length")==1
            action("viewFilters.tunnels.kind.add('http');goView('tunnels')")
            assert evaluate("document.querySelectorAll('#allTunnels tbody tr').length")==1
            action("goView('servers')")
            assert evaluate("document.getElementById('sessionSearch').value")== 'Review'
            action("document.getElementById('sessionSearch').value='';document.getElementById('serversClearFilters').click()")
            assert evaluate("document.querySelectorAll('.server-card').length")==4
            passed('Session search, independent forwarding filters, OR/AND groups and Firewall/direct overlap work without changing saved scope')

            app.window.resize(780,760);spin(.3)
            action("document.getElementById('toolsToggle').click()")
            assert evaluate("(()=>{const r=document.getElementById('toolsMenu').getBoundingClientRect();return document.documentElement.scrollWidth<=innerWidth+1&&r.left>=0&&r.right<=innerWidth+1})()")
            action("closePopover()");app.window.resize(1120,760);spin(.2)
            passed('Current compact Session cards and native sidebar Tools remain inside the minimum780px viewport')

            # Color-only native Save retains the active standalone transport.
            child=manager.session_runtime['studio']['child'];pid=child.proc.pid
            preserved={name:(data/name).read_bytes() for name in ('known_hosts','ssh_config','control.json')}
            action("document.querySelector('[data-color-session=studio]').click()")
            assert evaluate("document.querySelectorAll('#sessionColorPalette button').length")==8
            action("document.getElementById('sessionColorChoice').value='#D38B75';document.getElementById('applySessionColor').click()")
            wait(lambda:manager.server('studio').get('color')=='#D38B75','real color PUT persisted')
            assert child.proc.pid==pid and child.proc.poll() is None
            assert all((data/name).read_bytes()==content for name,content in preserved.items())
            passed('Native palette/color Save persists on an active Session with SSH PID/trust/control/configuration of SSH unchanged')

            # Full export dispatch from the real sidebar, not a substitute bridge.
            action("window.fileResults=[];window.addEventListener('hopharbor-file-result',e=>window.fileResults.push(e.detail));document.getElementById('exportConfig').click()")
            output=folder/'chosen-export.json';select_file(output,save=True)
            wait(output.exists,'private export file written')
            exported=json.loads(output.read_text())
            assert exported==manager.export_configuration()
            assert next(row['color'] for row in exported['sessions'] if row['id']=='archive')==evaluate("sessionColor(serverById('archive'))")
            assert 'color' not in manager.server('archive')
            assert output.stat().st_mode&0o777==0o600
            assert all(secret not in output.read_text() for secret in ('identity_file','known_hosts',str(key),str(data),'token'))
            assert evaluate('window.fileResults')==[{'status':'saved'}]
            passed('Actual Tools Export opens GTK Save; portable file0600 excludes local identity/trust/token and returns only fixed saved status')

            error_path=folder/'not-written.json'
            with mock.patch.object(panel,'write_export_file',side_effect=OSError('Synthetic write failure')):
                action("document.getElementById('exportConfig').click()")
                select_file(error_path,save=True)
            assert not error_path.exists() and evaluate('window.fileResults.at(-1)')=={'status':'error'}
            passed('Native Save failure returns only fixed error status and leaves no output file')

            action("document.getElementById('exportConfig').click()")
            wait(lambda:app.file_dialog is not None,'cancelled export dialog');app.file_dialog.response(Gtk.ResponseType.CANCEL);spin(.2)
            assert evaluate('window.fileResults.at(-1)')=={'status':'cancelled'}
            action("document.getElementById('exportConfig').click()")
            wait(lambda:app.file_dialog is not None,'stale export dialog');old=app.browser;app.close_panel()
            assert app.file_dialog is None;app.activate();wait(online,'reopen cancels native dialog')
            assert app.browser is not old
            action("goView('servers')")
            passed('Export cancellation/hide/reopen cancels pending file operations and authenticates a new owned page')

            # Import needs new IDs/origin, remains stopped, persists color, then no-op/Undo.
            incoming=copy.deepcopy(exported);incoming['origin']='b'*32
            incoming['sessions']=[dict(incoming['sessions'][0],id='incoming',name='Imported synthetic',jump_id=None,color='#A28BCB')]
            incoming['forwards']=[]
            import_path=folder/'chosen-import.json';import_path.write_text(json.dumps(incoming))
            action("document.getElementById('importConfig').click()")
            select_file(import_path)
            wait(lambda:evaluate("document.getElementById('importDialog').open"),'real file read/import preview')
            assert str(folder) not in evaluate("document.getElementById('configFile').value")
            before=copy.deepcopy(manager.config)
            action("document.getElementById('applyImport').click()")
            wait(lambda:len(manager.config['servers'])==5,'import merge')
            imported=manager.config['servers'][-1]
            assert imported['color']=='#A28BCB' and imported['identity_file']=='' and imported['identity_required']
            assert imported['id'] not in manager.session_runtime
            action("document.getElementById('importConfig').click()");select_file(import_path)
            wait(lambda:evaluate("document.getElementById('importDialog').open"),'repeat preview')
            action("document.getElementById('applyImport').click()");spin(.2)
            assert len(manager.config['servers'])==5
            action("document.getElementById('undoImport').click()")
            wait(lambda:len(manager.config['servers'])==4,'native Undo import')
            assert manager.config==before
            passed('Actual native Open/File API preview/apply/reimport-noop/Undo; imported identity disabled and colors preserved without local-path disclosure')

            # Wrong-path/export extras and forbidden device fields never open a dialog.
            action("postNativePanelMessage({action:'exportConfiguration',document:{format:'bad'},path:'/tmp/not-chosen'})")
            assert app.file_dialog is None
            action("history.replaceState(null,'','/api/state');document.getElementById('exportConfig').click()")
            spin(.2);assert app.file_dialog is None
            action("history.replaceState(null,'','/')")
            passed('Native file bridge rejects extra filesystem fields, malformed documents and wrong current panel path')

            # Advisory checks use a deterministic official-document opener only.
            class Response(io.BytesIO):
                def geturl(self):return API
            calls=[]
            def opener(request,timeout):
                calls.append(request.full_url)
                return Response(json.dumps(dict(draft=False,prerelease=False,tag_name='v1.4.3',
                    html_url='https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.3')).encode())
            manager.release_checker=ReleaseChecker(data/'synthetic-release.json','1.4.2',core.atomic_json,opener=opener)
            action("document.getElementById('checkRelease').click()")
            wait(lambda:not manager.release_checker.running and manager.release_checker.result['status']=='available','manual release notice')
            refresh();assert len(calls)==1
            assert manager.release_checker.snapshot()['latest_version']=='1.4.3'
            assert not manager.release_checker.check(manual=True)
            assert not manager.release_checker.check()
            passed('Native manual release check shows a newer official fixture, obeys manual/daily throttles and downloads/installs no assets')

            # Real user-gesture navigation in Xvfb; never launch a host browser.
            action("openUpdates(false)")
            opened=[]
            with mock.patch.object(Gio.AppInfo,'launch_default_for_uri',side_effect=lambda uri,ctx:opened.append(uri)):
                for uri,accepted in [('https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.3',True),
                                     ('https://user@github.com/kiyanibehzad/HopHarbor/releases',False)]:
                    action("document.getElementById('releaseLink').href="+json.dumps(uri)+";openUpdates(false)")
                    rect=evaluate("(()=>{const r=document.getElementById('releaseLink').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()")
                    ox,oy=app.browser.get_window().get_origin()[-2:]
                    subprocess.run(['xdotool','mousemove','--sync',str(int(ox+rect['x'])),str(int(oy+rect['y'])),'click','1'],check=True)
                    spin(.3)
                    assert (uri in opened)==accepted
                    assert online()
            passed('Actual native release-link gesture opens only exact official HTTPS URL externally; credentials lookalike stays blocked')

            # Filtering cannot silently narrow a bulk action. Forwarding scope
            # must leave both actual standalone Session transports connected.
            action("closeUpdates();goView('tunnels');document.querySelector('[data-bulk-scope=tunnels][data-bulk-action=disconnect]').click()")
            wait(lambda:evaluate("document.getElementById('confirmDialog').open"),'forwarding disconnect confirmation')
            action("document.getElementById('confirmYes').click()")
            wait(lambda:evaluate("document.getElementById('bulkDialog').open"),'forwarding results')
            assert all(manager.session_runtime[i]['child'].proc.poll() is None for i in ('studio','relay'))
            action("document.getElementById('bulkDialog').close();goView('servers');document.getElementById('sessionSearch').value='Archive';document.getElementById('sessionSearch').dispatchEvent(new Event('input'));document.querySelector('[data-bulk-scope=servers][data-bulk-action=disconnect]').click()")
            wait(lambda:evaluate("document.getElementById('confirmDialog').open"),'Session disconnect confirmation')
            action("document.getElementById('confirmNo').click()")
            assert all(manager.session_runtime[i]['child'].proc.poll() is None for i in ('studio','relay'))
            action("document.querySelector('[data-bulk-scope=servers][data-bulk-action=disconnect]').click()")
            wait(lambda:evaluate("document.getElementById('confirmDialog').open"),'Session disconnect second confirmation')
            action("document.getElementById('confirmYes').click()")
            wait(lambda:not manager.session_runtime and not manager.runtime,'scoped native fixture cleanup')
            manager.recover_after_wake();spin(.2)
            assert not manager.session_runtime and not manager.runtime
            passed('Disconnect All owns/stops standalone and Firewall children; deliberate stopped intent survives wake')
            report=dict(ok=True,version=panel.VERSION,build=panel.BUILD,checks=checks,count=len(checks),
                        external_ssh=False,production_changed=False,source_app=str(args.app_dir))
            args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
        finally:
            if app:app.quit_panel();spin(.1)
            if server:server.shutdown();server.server_close()
            if manager:manager.shutdown()
            for stop in reversed(cleanup):
                with contextlib.suppress(Exception):stop()


if __name__=='__main__':main()
