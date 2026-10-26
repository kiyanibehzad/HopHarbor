'use strict';
const $=id=>document.getElementById(id);
const num=n=>new Intl.NumberFormat('en-US').format(Number(n)||0);

// Only appearance and setup-note dismissal are browser-stored preferences; credentials never enter browser storage.
const APPEARANCE_KEY='hopharbor.appearance';
const systemAppearance=window.matchMedia('(prefers-color-scheme: dark)');
let appearanceChoice=['system','light','dark'].includes(document.documentElement.dataset.appearance)?document.documentElement.dataset.appearance:'system';
function applyAppearance(){
  document.documentElement.dataset.appearance=appearanceChoice;
  document.documentElement.dataset.theme=appearanceChoice==='system'?(systemAppearance.matches?'dark':'light'):appearanceChoice;
  $('appearanceSelect').value=appearanceChoice;
}
function changeAppearance(choice){
  appearanceChoice=['system','light','dark'].includes(choice)?choice:'system';
  try{if(appearanceChoice==='system')localStorage.removeItem(APPEARANCE_KEY);else localStorage.setItem(APPEARANCE_KEY,appearanceChoice)}catch{}
  applyAppearance();
}
$('appearanceSelect').addEventListener('change',event=>changeAppearance(event.target.value));
if(systemAppearance.addEventListener)systemAppearance.addEventListener('change',()=>{if(appearanceChoice==='system')applyAppearance()});
else systemAppearance.addListener(()=>{if(appearanceChoice==='system')applyAppearance()});
window.addEventListener('storage',event=>{if(event.key!==APPEARANCE_KEY&&event.key!==null)return;let choice='system';try{choice=localStorage.getItem(APPEARANCE_KEY)||'system'}catch{}appearanceChoice=['system','light','dark'].includes(choice)?choice:'system';applyAppearance()});
applyAppearance();


const SETUP_NOTE_KEY='hopharbor.dismissedSetupNote';
let setupNoteDismissed=false;
try{setupNoteDismissed=localStorage.getItem(SETUP_NOTE_KEY)==='true'}catch{}
$('dismissSetupNote').addEventListener('click',()=>{
  setupNoteDismissed=true;
  try{localStorage.setItem(SETUP_NOTE_KEY,'true')}catch{}
  $('migrationBanner').hidden=true;
  $('refreshButton').focus({preventScroll:true});
});

const state={servers:[],tunnels:[],logs:[],service:{},migration:{}};
let currentView='dashboard',filter='all',authorized=true,loaded=false,refreshSequence=0,refreshInFlight=false,lastSuccess=null;
const busy=new Set();
const sessionBusy=new Set();
const titles={dashboard:['Overview','A clear view of your SSH connections and forwarding.'],tunnels:['Port Forwarding','Manage local proxy ports and TCP forwarding.'],servers:['Sessions','Saved SSH connection settings and authentication.'],logs:['Logs','Connection activity and diagnostic details.']};
const statusText={connected:'Connected',degraded:'Partially connected',starting:'Connecting',stopped:'Disconnected',error:'Connection error'};
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=String(text);return n}
function children(parent,...nodes){nodes.flat().filter(Boolean).forEach(n=>parent.append(n));return parent}
function authMode(server){return ['agent','key','password','key_password'].includes(server?.auth_mode)?server.auth_mode:server?.identity_file?'key':'agent'}
function authDescription(server){const labels={agent:'Agent',key:'PublicKey',password:'Password',key_password:'PublicKey + Password'};const mode=authMode(server);return labels[mode]+(['password','key_password'].includes(mode)&&server.has_password===false?' · password needed':'')}
function clearSensitiveFields(){for(const name of ['password','key_passphrase'])field($('serverForm'),name).value=''}
function serverById(id){return state.servers.find(s=>String(s.id)===String(id))}
function isRunning(t){return !!(t.desired_running||Number(t.active_sessions)>0||['connected','degraded','starting'].includes(t.status))}
function sortedLogs(){return [...state.logs].sort((a,b)=>(new Date(b.time).getTime()||0)-(new Date(a.time).getTime()||0))}
function timeText(value,seconds=false){const d=new Date(value);return Number.isNaN(d.getTime())?'—':d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',hour12:false,...(seconds?{second:'2-digit'}:{})})}
function errorMessage(err){return err&&err.message?err.message:'This action could not be completed. Please try again.'}
function showLocked(copy){authorized=false;$('lockedScreen').hidden=false;if(copy)$('lockedCopy').textContent=copy;setService(false,'Panel access is not authorized.')}
async function request(path,options={}){const headers={'Accept':'application/json','X-Requested-With':'ProxyManager',...(options.headers||{})};const opts={credentials:'same-origin',cache:'no-store',...options,headers};if(opts.method&&!['GET','HEAD'].includes(opts.method.toUpperCase())&&opts.body===undefined)opts.body={};if(opts.body!==undefined&&typeof opts.body!=='string'){headers['Content-Type']='application/json';opts.body=JSON.stringify(opts.body)}const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),path.endsWith('/test')?20000:12000);opts.signal=controller.signal;let response;try{response=await fetch(path,opts)}catch(err){if(err.name==='AbortError')throw new Error('The local service took too long to respond. Refresh its status.');throw new Error('The local service is unavailable. Open HopHarbor on this Mac.')}finally{clearTimeout(timer)}const text=await response.text();let data={};if(text){try{data=JSON.parse(text)}catch{if(response.ok)throw new Error('The local service returned an unreadable response.');data={}}}if(!response.ok){if(response.status===401||response.status===403)showLocked(data.error||'Open this panel from HopHarbor on this Mac.');throw new Error(typeof data.error==='string'?data.error:typeof data.error?.message==='string'?data.error.message:`The request failed (${response.status}).`)}return data}
function setService(connected,message){$('serviceDot').classList.toggle('offline',!connected);$('footerDot').classList.toggle('offline',!connected);$('serviceLabel').textContent=connected?'Local service online':'Service unavailable';$('serviceBanner').hidden=connected||!authorized;if(!connected&&authorized)$('serviceBannerText').textContent=message||'Cannot reach the local service.'}
async function refresh(force=false){if(!authorized)return;if(refreshInFlight&&!force)return;const sequence=++refreshSequence;refreshInFlight=true;$('refreshButton').disabled=true;try{const data=await request('/api/state');if(sequence!==refreshSequence)return;for(const key of ['servers','tunnels','logs'])state[key]=Array.isArray(data[key])?data[key]:[];state.service=data.service||{};state.migration=data.migration||{};loaded=true;lastSuccess=new Date();setService(true);render()}catch(err){if(sequence===refreshSequence)setService(false,errorMessage(err))}finally{if(sequence===refreshSequence){refreshInFlight=false;$('refreshButton').disabled=false}}}
function goView(view){if(!titles[view])return;currentView=view;for(const n of document.querySelectorAll('.view'))n.hidden=n.id!==`view-${view}`;for(const n of document.querySelectorAll('.nav-button')){const active=n.dataset.view===view;n.classList.toggle('active',active);if(active)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current')}$('pageTitle').textContent=titles[view][0];$('pageSubtitle').textContent=titles[view][1];$('primaryActionText').textContent=view==='servers'?'New session':'New forwarding';$('primaryAction').hidden=view==='logs';if(loaded)render()}
function emptyState(title,copy,action,label,symbol='tunnel'){const box=el('div','empty-state');children(box,children(el('div','empty-symbol'),icon(symbol)),el('h3','',title),el('p','',copy));if(action){const b=children(el('button','button soft'),icon('plus'),el('span','',label));b.type='button';b.addEventListener('click',action);box.append(b)}return box}
function statusBadge(t){const cls=t.status==='connected'?'running':t.status==='error'?'error':['starting','degraded'].includes(t.status)?'connecting':'stopped';return children(el('span',`badge ${cls}`),el('span','status-dot'),el('span','',statusText[t.status]||'Unknown'))}
function actionButton(label,symbol,action,id,cls='button small'){const b=children(el('button',cls),symbol?icon(symbol):null,label?el('span','',label):null);b.type='button';b.dataset.action=action;b.dataset.id=String(id);if(!label){b.title=action.startsWith('edit')?'Edit':action.startsWith('delete')?'Delete':action==='test'?'Test traffic':'Reconnect';b.setAttribute('aria-label',b.title)}return b}
function protocolBadge(t){return el('span',`badge protocol ${t.kind==='http'?'http':t.kind==='local'?'local':''}`,t.kind==='local'?'TCP':t.kind==='http'?'HTTP':'SOCKS5')}
function tunnelTable(list,compact=false,grouped=false){if(!list.length){if(state.tunnels.length)return emptyState('No matching forwarding','Try another name, port or status filter.');return emptyState('Create your first port forwarding','Choose a saved session and create a SOCKS, HTTP or TCP forwarding port.',()=>state.servers.length?openTunnel():openServer(),state.servers.length?'New forwarding':'New session')}const wrap=el('div','table-wrap');const table=el('table');table.setAttribute('aria-label','Port forwarding');const header=el('thead');const hrow=el('tr');for(const title of [grouped?'Forwarding Name':'Name / Session','Type','Local endpoint','Status','Actions']){const th=el('th','',title);th.scope='col';hrow.append(th)}header.append(hrow);table.append(header);const body=el('tbody');for(const t of list){const row=el('tr');const server=serverById(t.server_id);const running=isRunning(t);const name=el('div','row-name');const symbol=children(el('div',`tunnel-symbol ${t.status==='connected'?'running':t.status==='error'?'error':''}`),icon(t.kind==='http'?'globe':'tunnel'));const info=children(el('div'),el('div','primary-text',t.name||'Unnamed forwarding'));let secondary=grouped?'':server?.name||'Unknown session';if(t.kind==='local'&&t.remote_host)secondary+=`${secondary?' · ':''}${t.remote_host}:${t.remote_port}`;if(secondary)info.append(el('div','secondary-text',secondary));children(name,symbol,info);row.append(children(el('td'),name));row.append(children(el('td'),protocolBadge(t)));const port=el('button','copy-port mono',`127.0.0.1:${t.local_port}`);port.type='button';port.title='Copy local endpoint';port.setAttribute('aria-label',`Copy local endpoint for ${t.name||'forwarding'}`);port.dataset.action='copy';port.dataset.id=String(t.id);row.append(children(el('td'),port));const status=children(el('td'),statusBadge(t));const pool=Math.max(1,Number(t.pool_size)||1);status.append(el('span','session-detail',running?`${num(t.healthy_sessions)} / ${num(pool)} SSH sessions ready`:`${num(pool)} SSH session${pool===1?'':'s'}`));if(t.last_test){const result=el('div',`session-detail test-result ${t.last_test.ok?'passed':'failed'}`,`${t.last_test.ok?'Test passed':'Test failed'} · ${timeText(t.last_test.time)}`);result.title=t.last_test.message||'';status.append(result)}if(t.last_error){const error=el('div','error-inline',String(t.last_error).slice(0,190));error.title=String(t.last_error);status.append(error)}row.append(status);const actions=el('div','row-actions');let control=actionButton(running?'Disconnect':'Connect',running?'stop':'play',running?'stop':'start',t.id,`button small ${running?'':'soft'}`);control.setAttribute('aria-label',`${running?'Disconnect':'Connect'} ${t.name||'forwarding'}`);if(busy.has(String(t.id))){control.setAttribute('aria-busy','true');control.replaceChildren(el('span','spinner'));control.classList.add('busy');control.disabled=true}actions.append(control);if(running&&Number(t.healthy_sessions)>0){const test=actionButton('','shield','test',t.id,'icon-button mini');test.setAttribute('aria-label',`Test traffic for ${t.name||'forwarding'}`);test.disabled=busy.has(String(t.id));actions.append(test)}if(running){const restart=actionButton('','refresh','restart',t.id,'icon-button mini');restart.setAttribute('aria-label',`Reconnect ${t.name||'forwarding'}`);restart.disabled=busy.has(String(t.id));actions.append(restart)}actions.append(el('span','action-divider'));for(const action of ['edit','delete']){const b=actionButton('',action==='edit'?'edit':'trash',action,t.id,`icon-button mini ${action==='delete'?'delete':''}`);b.setAttribute('aria-label',`${action==='edit'?'Edit':'Delete'} forwarding ${t.name||'Unnamed forwarding'}`);b.disabled=running||busy.has(String(t.id));if(running)b.title=action==='edit'?'Disconnect this forwarding before editing.':'Disconnect this forwarding before deleting.';actions.append(b)}row.append(children(el('td'),actions));body.append(row)}table.append(body);wrap.append(table);return wrap}
function firewallRoute(server){
  if(!server)return 'Unavailable';
  const names=[],seen=new Set([String(server.id)]);
  let id=server.jump_id;
  while(id){
    if(seen.has(String(id))){names.unshift('Connection loop');break}
    seen.add(String(id));
    const jump=serverById(id);
    if(!jump){names.unshift('Unknown session');break}
    names.unshift(jump.name||'Unnamed session');
    id=jump.jump_id;
  }
  return names.length?names.join(' → '):'None';
}
function groupedForwarding(list){
  if(!list.length){const empty=tunnelTable(list);empty.classList.add('panel');return [empty]}
  const groups=new Map();
  for(const tunnel of list){const id=String(tunnel.server_id);if(!groups.has(id))groups.set(id,[]);groups.get(id).push(tunnel)}
  const order=state.servers.map(server=>String(server.id)).filter(id=>groups.has(id));
  for(const id of groups.keys())if(!order.includes(id))order.push(id);
  return order.map((id,index)=>{
    const server=serverById(id),forwards=groups.get(id);
    const total=state.tunnels.filter(t=>String(t.server_id)===id).length;
    const active=forwards.filter(isRunning).length;
    const name=server?.name||'Unknown session';
    const group=el('section','panel forwarding-group');
    const headingId=`forwarding-session-${index}`;
    group.setAttribute('aria-labelledby',headingId);
    const header=el('div','forwarding-group-head');
    const summary=el('div','forwarding-group-summary');
    const heading=el('h2','',name);heading.id=headingId;
    if(server)heading.title=`${server.username||''}@${server.host}:${server.port}`;
    const count=el('span','group-count',`${forwards.length===total?num(total):`${num(forwards.length)} of ${num(total)}`} forward${total===1?'':'s'} · ${num(active)} active`);
    const title=children(el('div','forwarding-group-title'),heading,count);
    const route=el('div','group-route',`Firewall: ${firewallRoute(server)}`);
    children(summary,children(el('div','server-symbol'),icon('server')),children(el('div','forwarding-group-info'),title,route));
    header.append(summary);
    if(server){const add=actionButton('Add forwarding','plus','add-forwarding',server.id,'text-button');add.setAttribute('aria-label',`Add forwarding for session ${name}`);header.append(add)}
    const table=tunnelTable(forwards,false,true);
    table.querySelector('table').setAttribute('aria-label',`Port forwarding for ${name}`);
    children(group,header,table);
    return group;
  });
}
function renderTunnels(){
  const search=$('tunnelSearch').value.trim().toLocaleLowerCase('en');
  let list=state.tunnels.filter(t=>!search||`${t.name||''} ${serverById(t.server_id)?.name||''} ${t.local_port||''}`.toLocaleLowerCase('en').includes(search));
  if(filter==='running')list=list.filter(isRunning);
  if(filter==='stopped')list=list.filter(t=>!isRunning(t));
  $('allTunnels').replaceChildren(...groupedForwarding(list));
  const dashboard=[...state.tunnels].sort((a,b)=>Number(isRunning(b))-Number(isRunning(a))).slice(0,5);
  $('dashboardTunnels').replaceChildren(tunnelTable(dashboard,true));
}
function serverInUse(serverId,onlyRunning=false){return state.tunnels.some(t=>{if(onlyRunning&&!isRunning(t))return false;let current=serverById(t.server_id);const seen=new Set();while(current&&!seen.has(String(current.id))){if(String(current.id)===String(serverId))return true;seen.add(String(current.id));current=current.jump_id?serverById(current.jump_id):null}return false})}
function sessionMetrics(server){
  const own=state.tunnels.filter(t=>String(t.server_id)===String(server.id));
  const fallbackActive=own.filter(isRunning);
  const active=Number.isFinite(server.active_forward_count)?server.active_forward_count:fallbackActive.length;
  const total=Number.isFinite(server.own_forward_count)?server.own_forward_count:own.length;
  const sshActive=Number.isFinite(server.active_ssh_count)?server.active_ssh_count:own.reduce((sum,t)=>sum+(Number(t.active_sessions)||0),0);
  const sshHealthy=Number.isFinite(server.healthy_ssh_count)?server.healthy_ssh_count:own.reduce((sum,t)=>sum+(Number(t.healthy_sessions)||0),0);
  let status=server.connection_status;
  if(!status)status=!active?'disconnected':fallbackActive.every(t=>t.status==='error')?'error':fallbackActive.every(t=>t.status==='starting')?'connecting':fallbackActive.every(t=>t.status==='connected')?'connected':'degraded';
  return {own,active,total,sshActive,sshHealthy,status,firewall:!!server.firewall_in_use||status==='in_use_as_firewall'};
}
function renderServers(){
  const grid=$('serverGrid');
  if(!state.servers.length){const empty=emptyState('Add your first session','Save SSH connection settings, then create port forwarding for that session.',()=>openServer(),'New session','server');empty.style.gridColumn='1 / -1';empty.classList.add('panel');grid.replaceChildren(empty);return}
  const nodes=state.servers.map(s=>{
    const metrics=sessionMetrics(s),pending=sessionBusy.has(String(s.id))||metrics.own.some(t=>busy.has(String(t.id)));
    const card=el('article','panel server-card');
    const head=el('div','server-card-head');
    children(head,children(el('div','server-symbol'),icon('server')),children(el('div'),el('div','primary-text',s.name||'Unnamed session'),el('div','secondary-text mono',`${s.host}:${s.port}`)));
    const tools=el('div','server-card-tools');
    const edit=actionButton('','edit','edit-server',s.id,'icon-button');edit.setAttribute('aria-label',`Edit session ${s.name||'Unnamed session'}`);edit.disabled=serverInUse(s.id,true)||pending;if(edit.disabled)edit.title='Disconnect dependent forwarding before editing this session.';
    const remove=actionButton('','trash','delete-server',s.id,'icon-button delete');remove.setAttribute('aria-label',`Delete session ${s.name||'Unnamed session'}`);remove.disabled=serverInUse(s.id)||state.servers.some(x=>String(x.jump_id)===String(s.id))||pending;if(remove.disabled)remove.title='This session is used by forwarding or by another session as a firewall.';
    children(tools,edit,remove);head.append(tools);card.append(head);
    const statusbar=el('div','session-statusbar');
    const indicators=el('div','session-indicators');
    const normalized={connecting:'starting',disconnected:'stopped',in_use_as_firewall:'stopped'}[metrics.status]||metrics.status;
    indicators.append(statusBadge({status:normalized}));
    if(metrics.firewall){const firewall=el('span','badge firewall-badge','Firewall in use');firewall.title=`Other active forwarding depends on this session${Number(s.dependent_forward_count)>0?` (${num(s.dependent_forward_count)})`:''}. Session controls leave those connections running.`;indicators.append(firewall)}
    const counts=el('div','session-counts');
    counts.append(el('div','',metrics.total?`${num(metrics.active)} / ${num(metrics.total)} forward${metrics.total===1?'':'s'} active`:'No forwarding configured'));
    if(metrics.active>0||metrics.sshActive>0)counts.append(el('div','',metrics.sshActive?`${num(metrics.sshHealthy)} / ${num(metrics.sshActive)} SSH sessions ready`:'0 SSH sessions ready'));
    children(statusbar,indicators,counts);card.append(statusbar);
    const details=el('div','server-card-details');
    const interval=Number(s.keepalive_interval??30),missed=Number(s.keepalive_count??3);
    const keepalive=interval?`${num(interval)} seconds · ${num(missed)} missed replies`:'Off';
    for(const [label,value,mono]of [['Username',s.username||'—',true],['Firewall',s.jump_id?(serverById(s.jump_id)?.name||'Unknown session'):'None',false],['Authentication',authDescription(s),false],['Keepalive',keepalive,false]])details.append(children(el('div'),el('div','detail-label',label),el('div',`detail-value${mono?' mono':''}`,value)));
    card.append(details);
    const controls=el('div','session-actions');
    for(const [action,label,symbol]of [['connect','Connect','play'],['disconnect','Disconnect','stop'],['reconnect','Reconnect','refresh']]){
      const button=actionButton(label,symbol,`${action}-session`,s.id,`button small${action==='connect'?' soft':''}`);
      button.setAttribute('aria-label',`${label} session ${s.name||'Unnamed session'}`);
      button.disabled=pending||!metrics.total||(action==='connect'?metrics.active>=metrics.total:metrics.active===0);
      if(!metrics.total)button.title='Add port forwarding to this session first.';
      if(pending)button.setAttribute('aria-busy','true');
      controls.append(button);
    }
    card.append(controls,el('p','session-control-note',metrics.total?'Controls apply to this session’s port forwarding.':'Add forwarding to this session to enable connection controls.'));
    if(metrics.status==='error'){
      const error=metrics.own.find(t=>t.last_error)?.last_error;
      if(error){const message=el('div','session-error',String(error).slice(0,240));message.title=String(error);card.append(message)}
    }
    const bottom=el('div','server-card-bottom');
    if(s.host_key_trusted===true)bottom.append(children(el('span','status-note'),icon('shield'),el('span','', 'Host key verified')));
    else if(s.host_key_trusted===false)bottom.append(el('span','badge connecting','Host key needed'));
    else bottom.append(el('span','secondary-text','Session saved'));
    const add=el('button','text-button','Add forwarding');add.type='button';add.setAttribute('aria-label',`Add forwarding for session ${s.name||'Unnamed session'}`);add.addEventListener('click',()=>openTunnel(null,s.id));bottom.append(add);card.append(bottom);
    return card;
  });
  grid.replaceChildren(...nodes);
}
function eventMessage(event,cls='log-message'){
  const message=children(el('div',cls),el('span','',event.message||''));
  const repeats=Number(event.repeats);
  if(Number.isInteger(repeats)&&repeats>1){
    const count=el('span','badge log-repeat',`×${num(repeats)}`);
    count.title=`${num(repeats)} occurrences; duplicate events collapsed`;
    count.setAttribute('aria-label',`${num(repeats)} occurrences`);
    message.append(count);
  }
  return message;
}
function renderLogs(){const logs=sortedLogs();const recent=$('recentActivity');if(!logs.length){recent.replaceChildren(emptyState('No activity yet','Connection activity will appear here when you use port forwarding.',null,null,'logs'))}else recent.replaceChildren(...logs.slice(0,4).map(l=>{const level=String(l.level||'info').toLowerCase();const row=el('div','activity');const dot=el('span',`status-dot activity-dot ${level}`);children(row,dot,eventMessage(l,'activity-text'),el('time','activity-time',timeText(l.time)));return row}));const search=$('logSearch').value.trim().toLocaleLowerCase('en');const visible=logs.filter(l=>!search||String(l.message||'').toLocaleLowerCase('en').includes(search));if(!visible.length){$('logsList').replaceChildren(emptyState(search?'No matching events':'No log entries yet',search?'Try a different search.':'Connection activity and errors will appear here.',null,null,'logs'));return}$('logsList').replaceChildren(...visible.slice(0,200).map(l=>{const level=String(l.level||'info').toLowerCase();return children(el('div','log-row'),el('time','mono',timeText(l.time,true)),el('span',`log-level ${level}`,level),eventMessage(l))}))}
function render(){const focused=document.activeElement;const focusInfo=focused&&focused.dataset.action?{action:focused.dataset.action,id:focused.dataset.id,container:focused.closest('#dashboardTunnels,#allTunnels,#serverGrid')?.id}:null;const active=state.tunnels.filter(t=>['connected','degraded'].includes(t.status)).length;const errors=state.tunnels.filter(t=>t.status==='error').length;const starting=state.tunnels.filter(t=>t.status==='starting').length;$('metricActive').textContent=num(active);$('metricTunnels').textContent=num(state.tunnels.length);$('metricServers').textContent=num(state.servers.length);$('navTunnelCount').textContent=num(state.tunnels.length);$('metricActiveFoot').textContent=errors?`${num(errors)} forwarding configuration${errors===1?' needs':'s need'} attention`:starting?`${num(starting)} connecting`:'SSH connection status';$('metricServersFoot').textContent=state.servers.length?'Connection settings and firewalls':'Add a session to get started';$('lastUpdated').textContent=lastSuccess?`Updated at ${timeText(lastSuccess)}`:'Loading status...';$('appVersion').textContent=`v${String(state.service.version||'1.1.2').replace(/^v/i,'').slice(0,32)} · build ${String(state.service.build??5).slice(0,16)}`;const migration=state.migration;$('migrationBanner').hidden=setupNoteDismissed||!migration.message||migration.phase==='complete';$('migrationTitle').textContent=migration.phase==='testing'?'Testing mode · ':'Migration status · ';$('migrationText').textContent=migration.message||'';renderTunnels();renderServers();renderLogs();if(focusInfo&&focusInfo.container){const replacement=Array.from($(focusInfo.container).querySelectorAll('button[data-action]')).find(b=>b.dataset.action===focusInfo.action&&b.dataset.id===focusInfo.id&&!b.disabled);if(replacement)replacement.focus({preventScroll:true})}}
function toast(message,error=false){const n=children(el('div',`toast${error?' error':''}`),icon(error?'warning':'check'),el('span','',String(message).slice(0,350)));$('toastRegion').append(n);setTimeout(()=>n.remove(),error?8000:4500)}
async function confirmDelete(title,message){const d=$('confirmDialog');$('confirmTitle').textContent=title;$('confirmCopy').textContent=message;d.showModal();return new Promise(resolve=>{let finished=false;const finish=value=>{if(finished)return;finished=true;d.close();$('confirmYes').onclick=null;$('confirmNo').onclick=null;$('confirmClose').onclick=null;d.oncancel=null;resolve(value)};$('confirmYes').onclick=()=>finish(true);$('confirmNo').onclick=()=>finish(false);$('confirmClose').onclick=()=>finish(false);d.oncancel=e=>{e.preventDefault();finish(false)}})}
async function tunnelAction(action,id){const t=state.tunnels.find(t=>String(t.id)===String(id));if(!t)return;if(action==='copy'){const address=`127.0.0.1:${t.local_port}`;try{await navigator.clipboard.writeText(address);toast('Local endpoint copied.')}catch{toast(address)}return}if(action==='edit'){if(isRunning(t)){toast('Disconnect this forwarding before editing.',true);return}openTunnel(t);return}if(busy.has(String(id)))return;if(action==='delete'&&!await confirmDelete('Delete forwarding',`Delete forwarding "${t.name}"? The saved session will remain available.`))return;busy.add(String(id));renderTunnels();try{const result=await request(`/api/tunnels/${encodeURIComponent(id)}${action==='delete'?'':`/${action}`}`,{method:action==='delete'?'DELETE':'POST',body:{}});if(action==='test')toast(result.message||'Traffic test finished.',!result.ok);else toast(action==='delete'?'Forwarding deleted.':action==='start'?'Connection requested.':action==='stop'?'Disconnection requested.':'Reconnection requested.');await refresh(true)}catch(err){toast(errorMessage(err),true)}finally{busy.delete(String(id));renderTunnels()}}
async function sessionConnectionAction(action,id){
  const server=serverById(id);if(!server||sessionBusy.has(String(id)))return;
  const own=state.tunnels.filter(t=>String(t.server_id)===String(id));
  if(own.some(t=>busy.has(String(t.id))))return;
  sessionBusy.add(String(id));for(const t of own)busy.add(String(t.id));renderServers();renderTunnels();
  try{
    const result=await request(`/api/servers/${encodeURIComponent(id)}/${action}`,{method:'POST',body:{}});
    const results=Array.isArray(result.results)?result.results:[];
    const requested=Number(result.summary?.requested??results.length);
    const failed=Number(result.summary?.failed??results.filter(r=>!r.ok).length);
    const succeeded=Number(result.summary?.succeeded??Math.max(0,requested-failed));
    const firstError=results.find(r=>!r.ok&&r.error)?.error;
    if(failed)toast(`${server.name}: ${num(succeeded)} of ${num(requested)} forwarding requests accepted. ${num(failed)} failed.${firstError?` ${firstError}`:''}`,true);
    else toast(`${server.name}: ${action==='connect'?'Connect':action==='disconnect'?'Disconnect':'Reconnect'} requested for ${num(requested)} forward${requested===1?'':'s'}.`);
    await refresh(true);
  }catch(err){toast(errorMessage(err),true)}
  finally{sessionBusy.delete(String(id));for(const t of own)busy.delete(String(t.id));renderServers();renderTunnels()}
}
async function serverAction(action,id){const s=serverById(id);if(!s)return;if(['connect-session','disconnect-session','reconnect-session'].includes(action))return sessionConnectionAction(action.replace('-session',''),id);if(action==='edit-server'){openServer(s);return}if(!await confirmDelete('Delete session',`Delete the saved session "${s.name}"?`))return;try{await request(`/api/servers/${encodeURIComponent(id)}`,{method:'DELETE'});toast('Session deleted.');await refresh(true)}catch(err){toast(errorMessage(err),true)}}
function option(value,label){const n=el('option','',label);n.value=String(value??'');return n}
function field(form,name){return form.elements.namedItem(name)}
function openServer(server=null){const form=$('serverForm');form.reset();clearSensitiveFields();form.dataset.hasPassword=server?.has_password?'true':'false';form.dataset.hasKeyPassphrase=server?.has_key_passphrase?'true':'false';$('serverFormError').textContent='';$('serverDialogTitle').textContent=server?'Edit session':'New session';field(form,'id').value=server?.id||'';field(form,'name').value=server?.name||'';field(form,'host').value=server?.host||'';field(form,'port').value=server?.port||22;field(form,'username').value=server?.username||'';field(form,'keepalive_interval').value=server?.keepalive_interval??30;field(form,'keepalive_count').value=server?.keepalive_count??3;const identity=server?server.identity_file||'':state.service.default_identity_file||state.servers.find(s=>s.identity_file)?.identity_file||'';field(form,'identity_file').value=identity;field(form,'auth_mode').value=server?authMode(server):identity?'key':'agent';const choices=[option('','None'),...state.servers.filter(s=>String(s.id)!==String(server?.id)).map(s=>option(s.id,s.name))];field(form,'jump_id').replaceChildren(...choices);field(form,'jump_id').value=server?.jump_id||'';$('hostKeyHelp').textContent=server?.host_key_trusted?'This host key is already verified. Leave this field blank to keep the trusted key.':'Obtain the trusted host public key from the server administrator. This is separate from your login key.';$('serverDialog').querySelectorAll('details').forEach(details=>details.open=false);updateAuthForm();$('serverDialog').showModal();$('serverName').focus({preventScroll:true});$('serverDialog').querySelector('.modal-body').scrollTop=0}
function updateAuthForm(){const form=$('serverForm');const mode=field(form,'auth_mode').value;const useKey=['key','key_password'].includes(mode);const usePassword=['password','key_password'].includes(mode);$('identityField').hidden=!useKey;$('keyPassphraseField').hidden=!useKey;$('passwordField').hidden=!usePassword;field(form,'identity_file').required=false;field(form,'password').required=false;field(form,'key_passphrase').required=false;if(!useKey)field(form,'key_passphrase').value='';if(!usePassword)field(form,'password').value='';const hasPassword=form.dataset.hasPassword==='true';const hasKeyPassphrase=form.dataset.hasKeyPassphrase==='true';field(form,'password').placeholder=hasPassword?'Leave blank to keep the saved password':'You can add this later';$('passwordHelp').textContent=hasPassword?'A password is saved in Keychain. Leave this field blank to keep it.':'No password is saved for this session. You can add it later.';field(form,'key_passphrase').placeholder=hasKeyPassphrase?'Leave blank to keep the saved passphrase':'Leave blank if the key is not encrypted';$('keyPassphraseHelp').textContent=hasKeyPassphrase?'A key passphrase is saved securely in Keychain and is never displayed here.':'Needed only for an encrypted private key. You can add it later.'}
function openTunnel(tunnel=null,serverId=null){if(!state.servers.length){toast('Add a session first.');openServer();return}const form=$('tunnelForm');form.reset();$('tunnelFormError').textContent='';$('tunnelDialogTitle').textContent=tunnel?'Edit forwarding':'New forwarding';field(form,'id').value=tunnel?.id||'';field(form,'name').value=tunnel?.name||'';field(form,'kind').value=tunnel?.kind||'socks';field(form,'server_id').replaceChildren(...state.servers.map(s=>option(s.id,s.name)));field(form,'server_id').value=tunnel?.server_id||serverId||state.servers[0].id;field(form,'local_port').value=tunnel?.local_port||'';field(form,'remote_host').value=tunnel?.remote_host||'127.0.0.1';field(form,'remote_port').value=tunnel?.remote_port||'';field(form,'pool_size').value=tunnel?.pool_size||1;field(form,'autostart').checked=!!tunnel?.autostart;updateTunnelForm();$('tunnelDialog').showModal();$('tunnelName').focus({preventScroll:true});$('tunnelDialog').querySelector('.modal-body').scrollTop=0}
function updateTunnelForm(){const form=$('tunnelForm');const kind=field(form,'kind').value;const local=kind==='local';$('tunnelTargetHostField').hidden=!local;$('tunnelTargetPortField').hidden=!local;field(form,'remote_host').required=local;field(form,'remote_port').required=local;const notes={socks:'Creates a local SOCKS5 proxy on 127.0.0.1. Save the configuration, then choose Connect when ready.',http:'Creates a local HTTP proxy through SSH on 127.0.0.1. Save the configuration, then choose Connect when ready.',local:'Forwards a local TCP port through SSH. The destination must be reachable from the SSH host. Saving does not connect.'};$('tunnelFormHelp').textContent=notes[kind]||notes.socks}
function validatePort(value,min=1){return Number.isInteger(Number(value))&&Number(value)>=min&&Number(value)<=65535}
function validateHost(value){return /^[A-Za-z0-9_.:\[\]-]+$/.test(value)&&value.length<=253&&!value.startsWith('-')}
async function saveServer(event){event.preventDefault();const form=$('serverForm');if(!form.reportValidity())return;const id=field(form,'id').value;const data={name:field(form,'name').value.trim(),host:field(form,'host').value.trim(),port:Number(field(form,'port').value),username:field(form,'username').value.trim(),auth_mode:field(form,'auth_mode').value,identity_file:['key','key_password'].includes(field(form,'auth_mode').value)?field(form,'identity_file').value.trim():'',jump_id:field(form,'jump_id').value||null,keepalive_interval:Number(field(form,'keepalive_interval').value),keepalive_count:Number(field(form,'keepalive_count').value)};const password=field(form,'password').value;const keyPassphrase=field(form,'key_passphrase').value;if(['password','key_password'].includes(data.auth_mode)&&password.length)data.password=password;if(['key','key_password'].includes(data.auth_mode)&&keyPassphrase.length)data.key_passphrase=keyPassphrase;const hostKey=field(form,'host_key').value.trim();if(hostKey)data.host_key=hostKey;const error=$('serverFormError');error.textContent='';if(!data.name){error.textContent='Enter a Session Name.';return}if(!validateHost(data.host)){error.textContent='Enter a hostname or IP address. Enter the username in its own field.';return}if(!validatePort(data.port)){error.textContent='Port must be between 1 and 65535.';return}if(!data.username||/\s/.test(data.username)||data.username.startsWith('-')){error.textContent='Enter a valid SSH username without spaces.';return}if(!Number.isInteger(data.keepalive_interval)||data.keepalive_interval<0||data.keepalive_interval>600){error.textContent='Keepalive interval must be between 0 and 600 seconds.';return}if(!Number.isInteger(data.keepalive_count)||data.keepalive_count<1||data.keepalive_count>10){error.textContent='Missed replies must be between 1 and 10.';return}if(data.jump_id){let current=serverById(data.jump_id);const seen=new Set();while(current&&!seen.has(String(current.id))){if(id&&String(current.id)===String(id)){error.textContent='This Firewall creates a connection loop. Choose another session.';return}seen.add(String(current.id));current=current.jump_id?serverById(current.jump_id):null}}const button=$('saveServerButton');button.disabled=true;button.textContent='Saving...';try{await request(`/api/servers${id?`/${encodeURIComponent(id)}`:''}`,{method:id?'PUT':'POST',body:data});clearSensitiveFields();$('serverDialog').close();toast(id?'Session changes saved.':'Session added.');await refresh(true)}catch(err){error.textContent=errorMessage(err)}finally{button.disabled=false;button.textContent='Save session'}}
async function saveTunnel(event){event.preventDefault();const form=$('tunnelForm');if(!form.reportValidity())return;const id=field(form,'id').value;const kind=field(form,'kind').value;const data={name:field(form,'name').value.trim(),server_id:field(form,'server_id').value,kind,local_port:Number(field(form,'local_port').value),pool_size:Number(field(form,'pool_size').value),remote_host:kind==='local'?field(form,'remote_host').value.trim():'',remote_port:kind==='local'?Number(field(form,'remote_port').value):0,autostart:field(form,'autostart').checked};const error=$('tunnelFormError');error.textContent='';if(!data.name){error.textContent='Enter a Forwarding Name.';return}if(!validatePort(data.local_port,1024)){error.textContent='Local port must be between 1024 and 65535.';return}if(state.tunnels.some(t=>String(t.id)!==String(id)&&Number(t.local_port)===data.local_port)){error.textContent='This local port is already assigned to another forwarding configuration. Choose another port.';return}if(!serverById(data.server_id)){error.textContent='Choose a saved session.';return}if(!Number.isInteger(data.pool_size)||data.pool_size<1||data.pool_size>4){error.textContent='Choose between 1 and 4 SSH sessions.';return}if(kind==='local'&&(!validateHost(data.remote_host)||!validatePort(data.remote_port))){error.textContent='Enter a valid destination hostname and port.';return}const button=$('saveTunnelButton');button.disabled=true;button.textContent='Saving...';try{await request(`/api/tunnels${id?`/${encodeURIComponent(id)}`:''}`,{method:id?'PUT':'POST',body:data});$('tunnelDialog').close();toast(id?'Forwarding changes saved.':'Forwarding added.');await refresh(true)}catch(err){error.textContent=errorMessage(err)}finally{button.disabled=false;button.textContent='Save forwarding'}}
for(const n of document.querySelectorAll('[data-view]'))n.addEventListener('click',()=>goView(n.dataset.view));for(const n of document.querySelectorAll('[data-go-view]'))n.addEventListener('click',()=>goView(n.dataset.goView));for(const n of document.querySelectorAll('[data-close-dialog]'))n.addEventListener('click',()=>$(n.dataset.closeDialog).close());for(const n of document.querySelectorAll('[data-filter]'))n.addEventListener('click',()=>{filter=n.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>{const active=x.dataset.filter===filter;x.classList.toggle('active',active);x.setAttribute('aria-pressed',String(active))});renderTunnels()});$('primaryAction').addEventListener('click',()=>currentView==='servers'?openServer():openTunnel());$('refreshButton').addEventListener('click',()=>refresh(true));$('retryButton').addEventListener('click',()=>refresh(true));$('lockedRetry').addEventListener('click',()=>{authorized=true;$('lockedScreen').hidden=true;refresh(true)});$('tunnelSearch').addEventListener('input',renderTunnels);$('logSearch').addEventListener('input',renderLogs);$('serverAuth').addEventListener('change',updateAuthForm);$('serverDialog').addEventListener('close',clearSensitiveFields);document.querySelectorAll('input[name="kind"]').forEach(n=>n.addEventListener('change',updateTunnelForm));$('serverForm').addEventListener('submit',saveServer);$('tunnelForm').addEventListener('submit',saveTunnel);for(const id of ['dashboardTunnels','allTunnels'])$(id).addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(button&&!button.disabled){if(button.dataset.action==='add-forwarding')openTunnel(null,button.dataset.id);else tunnelAction(button.dataset.action,button.dataset.id)}});$('serverGrid').addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(button&&!button.disabled)serverAction(button.dataset.action,button.dataset.id)});document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh(true)});setInterval(()=>{if(!document.hidden&&authorized)refresh()},5000);
async function bootstrap(){const parameters=new URLSearchParams(location.hash.slice(1));const token=parameters.get('token');if(token){history.replaceState(null,'',location.pathname+location.search);try{await request('/api/session',{method:'POST',body:{token}});authorized=true;$('lockedScreen').hidden=true}catch(err){showLocked(errorMessage(err));return}}await refresh(true)}
bootstrap();
