'use strict';
const $=id=>document.getElementById(id);
const num=n=>new Intl.NumberFormat('en-US').format(Number(n)||0);

// Appearance, setup dismissal and the last seen release are browser preferences; credentials never enter browser storage.
const APPEARANCE_KEY='hopharbor.appearance';
const systemAppearance=window.matchMedia('(prefers-color-scheme: dark)');
let appearanceChoice=['system','light','dark'].includes(document.documentElement.dataset.appearance)?document.documentElement.dataset.appearance:'system';
function applyAppearance(){
  document.documentElement.dataset.appearance=appearanceChoice;
  document.documentElement.dataset.theme=appearanceChoice==='system'?((typeof window.HopHarborSystemDark==='boolean'?window.HopHarborSystemDark:systemAppearance.matches)?'dark':'light'):appearanceChoice;
  const modes=['system','light','dark'],names=['System','Light','Dark'],i=modes.indexOf(appearanceChoice);
  const button=$('appearanceSelect');button.value=appearanceChoice;button.replaceChildren(icon(['appearance','sun','moon'][i]));
  button.title=`Appearance: ${names[i]}. Switch to ${names[(i+1)%3]}`;button.setAttribute('aria-label',button.title);
}
function changeAppearance(choice){
  appearanceChoice=['system','light','dark'].includes(choice)?choice:'system';
  try{if(appearanceChoice==='system')localStorage.removeItem(APPEARANCE_KEY);else localStorage.setItem(APPEARANCE_KEY,appearanceChoice)}catch{}
  applyAppearance();
}
$('appearanceSelect').addEventListener('click',event=>{event.currentTarget.focus({preventScroll:true});const modes=['system','light','dark'];changeAppearance(modes[(modes.indexOf(appearanceChoice)+1)%3])});
window.addEventListener('hopharbor-system-appearance',()=>{if(appearanceChoice==='system')applyAppearance()});
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
let currentView='dashboard',authorized=true,loaded=false,refreshSequence=0,refreshInFlight=false,lastSuccess=null;
let nativeRecoveryRequested=false,nativeReadySent=false;
const busy=new Set();
const sessionBusy=new Set();

// View filter state never changes saved configuration or bulk action scope.
const viewFilters={servers:{status:new Set(),role:new Set()},tunnels:{kind:new Set(),session:new Set(),status:new Set()}};
function filterCount(scope){return Object.values(viewFilters[scope]).reduce((n,values)=>n+values.size,0)}
function matchesChoice(values,value){return !values.size||values.has(String(value))}
function sessionFirewallRoles(){
  const roles=new Set();
  for(const s of state.servers){
    if(Number(s.dependent_session_count)>0||s.firewall_in_use||s.connection_status==='in_use_as_firewall')roles.add(String(s.id));
    if(s.jump_id)roles.add(String(s.jump_id));
    for(const id of s.firewall_path||[])roles.add(String(id));
  }
  return roles;
}
function matchesSessionFilters(server,query,firewalls){
  const filters=viewFilters.servers,metrics=sessionMetrics(server);
  const status={starting:'connecting',stopped:'disconnected',in_use_as_firewall:'disconnected'}[metrics.status]||metrics.status;
  const roles=new Set([server.jump_id||(server.firewall_path||[]).length?'uses':'direct']);
  if(firewalls.has(String(server.id)))roles.add('firewall');
  return matchesChoice(filters.status,status)&&(!filters.role.size||[...filters.role].some(role=>roles.has(role)))
    &&(!query||[server.name,server.host,server.port,`${server.host}:${server.port}`,server.username,firewallRoute(server)].join(' ').toLowerCase().includes(query));
}
function pruneSessionFilters(){
  const valid=new Set(state.servers.map(s=>String(s.id)));
  for(const id of viewFilters.tunnels.session)if(!valid.has(id))viewFilters.tunnels.session.delete(id);
}
function matchesTunnelFilters(tunnel,query){
  const filters=viewFilters.tunnels;
  const statusMatch=!filters.status.size||[...filters.status].some(status=>status==='active'?isRunning(tunnel):status==='disconnected'?!isRunning(tunnel):status==='connecting'?tunnel.status==='starting':tunnel.status==='error');
  return matchesChoice(filters.kind,tunnel.kind)&&matchesChoice(filters.session,tunnel.server_id)&&statusMatch
    &&(!query||`${tunnel.name||''} ${serverById(tunnel.server_id)?.name||''} ${tunnel.local_port||''}`.toLocaleLowerCase('en').includes(query));
}
// Filter controls are stable DOM nodes, so polling preserves checkbox focus.
function renderFilterControls(scope){
  const count=filterCount(scope),toggle=$(scope+'FilterToggle');
  toggle.textContent=count?`Filter · ${num(count)}`:'Filter';
  toggle.setAttribute('aria-label',`${scope==='servers'?'Session':'Port forwarding'} filters${count?`, ${num(count)} active option${count===1?'':'s'}`:''}`);
  for(const input of $(scope+'Filters').querySelectorAll('input[data-filter-group]'))input.checked=viewFilters[scope][input.dataset.filterGroup].has(input.value);
  for(const button of document.querySelectorAll(`[data-bulk-scope="${scope}"]`)){
    const limited=count>0||$(scope==='servers'?'sessionSearch':'tunnelSearch').value.trim();
    button.title=`Applies to all ${scope==='servers'?'saved sessions':'port forwarding'}, including any hidden by search or filters.`;
    button.setAttribute('aria-label',button.textContent+(limited?` — all ${scope==='servers'?'sessions':'forwarding'}, including hidden results`:''));
  }
  if(activePopover?.panel===$(scope+'Filters'))positionPopover();
}
function renderSessionFilterOptions(){
  pruneSessionFilters();
  const list=$('tunnelSessionOptions'),ids=new Set(state.servers.map(s=>String(s.id)));
  for(const label of [...list.children])if(!ids.has(label.dataset.sessionId)){
    if(label.contains(document.activeElement))$('tunnelsFilters').focus({preventScroll:true});
    label.remove();
  }
  state.servers.forEach((server,index)=>{
    const id=String(server.id);
    let label=[...list.children].find(node=>node.dataset.sessionId===id);
    if(!label){
      label=el('label','facet-option');label.dataset.sessionId=id;
      const input=el('input');input.type='checkbox';input.value=id;input.dataset.filterGroup='session';
      children(label,input,el('span'));list.append(label);
    }
    label.querySelector('span').textContent=server.name||'Unnamed session';
    if(list.children[index]!==label)list.insertBefore(label,list.children[index]||null);
  });
}

const SESSION_COLORS=['#58A6A6','#A28BCB','#D9A25F','#76A978','#7D9DD3','#C67E9B','#D38B75','#98A5B3'];
function validSessionColor(value){return typeof value==='string'&&/^#[0-9a-f]{6}$/i.test(value)}
function sessionColor(server){
  if(validSessionColor(server?.color))return server.color.toUpperCase();
  let hash=2166136261;
  for(const character of String(server?.portable_id||server?.id||''))hash=Math.imul(hash^character.charCodeAt(0),16777619);
  return SESSION_COLORS[(hash>>>0)%SESSION_COLORS.length];
}
function newSessionColor(){const preferred=[SESSION_COLORS[4],SESSION_COLORS[1],SESSION_COLORS[5]];return preferred[crypto.getRandomValues(new Uint32Array(1))[0]%preferred.length]}
function colorMarker(server,scope){
  const color=sessionColor(server),button=el('button','session-color-marker');
  button.type='button';button.id=`session-color-${scope}-${server.id}`;button.dataset.colorSession=String(server.id);
  button.title=`Color for ${server.name||'Unnamed session'}`;button.setAttribute('aria-label',button.title);
  button.setAttribute('aria-controls','sessionColorPanel');
  button.setAttribute('aria-expanded',String(activePopover?.toggleId===button.id));
  const stripe=el('span','session-color-stripe');stripe.style.backgroundColor=color;stripe.setAttribute('aria-hidden','true');
  button.append(stripe);return button;
}
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
// The native shell owns the access file. Recovery messages never carry credentials
// or replay the failed action; a fresh document performs the normal bootstrap.
function postNativePanelMessage(message){
  try{
    const handler=window.webkit?.messageHandlers?.hopharborPanel;
    if(handler&&typeof handler.postMessage==='function'){handler.postMessage(message);return true}
    const webview=window.chrome?.webview;
    if(webview&&typeof webview.postMessage==='function'){webview.postMessage(message);return true}
    return false;
  }catch{return false}
}
function requestNativeRecovery(reason){if(reason==='authentication'){if(nativeRecoveryRequested)return false;nativeRecoveryRequested=true}return postNativePanelMessage({action:'reauthenticate',reason})}
function retryLockedPanel(){if(requestNativeRecovery('retry'))return;authorized=true;$('lockedScreen').hidden=true;refresh(true)}
function showLocked(copy){authorized=false;$('lockedScreen').hidden=false;if(copy)$('lockedCopy').textContent=copy;setService(false,'Panel access is not authorized.')}
async function request(path,options={}){const headers={'Accept':'application/json','X-Requested-With':'ProxyManager',...(options.headers||{})};const opts={credentials:'same-origin',cache:'no-store',...options,headers};if(opts.method&&!['GET','HEAD'].includes(opts.method.toUpperCase())&&opts.body===undefined)opts.body={};if(opts.body!==undefined&&typeof opts.body!=='string'){headers['Content-Type']='application/json';opts.body=JSON.stringify(opts.body)}const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),path.endsWith('/verify-endpoint')?24000:path.endsWith('/test')?20000:12000);opts.signal=controller.signal;let response;try{response=await fetch(path,opts)}catch(err){if(err.name==='AbortError')throw new Error('The local service took too long to respond. Refresh its status.');throw new Error(`The local service is unavailable. Open HopHarbor on ${deviceName()}.`)}finally{clearTimeout(timer)}const text=await response.text();let data={};if(text){try{data=JSON.parse(text)}catch{if(response.ok)throw new Error('The local service returned an unreadable response.');data={}}}if(!response.ok){if(response.status===401||response.status===403){showLocked(data.error||`Open this panel from HopHarbor on ${deviceName()}.`);if(response.status===401&&path!=='/api/session')requestNativeRecovery('authentication')}throw new Error(typeof data.error==='string'?data.error:typeof data.error?.message==='string'?data.error.message:`The request failed (${response.status}).`)}return data}
function setService(connected,message){$('serviceDot').classList.toggle('offline',!connected);$('footerDot').classList.toggle('offline',!connected);$('serviceLabel').textContent=connected?'Online':'Offline';$('serviceLabel').title=connected?'Local service online':'Local service unavailable';renderUpdatesSummary();$('serviceBanner').hidden=connected||!authorized;if(!connected&&authorized)$('serviceBannerText').textContent=message||'Cannot reach the local service.'}
async function refresh(force=false){if(!authorized)return;if(refreshInFlight&&!force)return;const sequence=++refreshSequence;refreshInFlight=true;$('refreshButton').disabled=true;try{const data=await request('/api/state');if(sequence!==refreshSequence)return;for(const key of ['servers','tunnels','logs'])state[key]=Array.isArray(data[key])?data[key]:[];state.service=data.service||{};state.migration=data.migration||{};loaded=true;lastSuccess=new Date();setService(true);render();if(!nativeReadySent&&postNativePanelMessage({action:'ready'}))nativeReadySent=true}catch(err){if(sequence===refreshSequence)setService(false,errorMessage(err))}finally{if(sequence===refreshSequence){refreshInFlight=false;$('refreshButton').disabled=false}}}
function goView(view){if(!titles[view])return;currentView=view;for(const n of document.querySelectorAll('.view'))n.hidden=n.id!==`view-${view}`;for(const n of document.querySelectorAll('.nav-button')){const active=n.dataset.view===view;n.classList.toggle('active',active);if(active)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current')}$('pageTitle').textContent=titles[view][0];$('pageSubtitle').textContent=titles[view][1];$('primaryActionText').textContent=view==='servers'?'New session':'New forwarding';$('primaryAction').hidden=view==='logs';if(loaded)render()}
function emptyState(title,copy,action,label,symbol='tunnel'){const box=el('div','empty-state');children(box,children(el('div','empty-symbol'),icon(symbol)),el('h3','',title),el('p','',copy));if(action){const b=children(el('button','button soft'),icon('plus'),el('span','',label));b.type='button';b.addEventListener('click',action);box.append(b)}return box}
function statusBadge(t){const cls=t.status==='connected'?'running':t.status==='error'?'error':['starting','degraded'].includes(t.status)?'connecting':'stopped';return children(el('span',`badge ${cls}`),el('span','status-dot'),el('span','',statusText[t.status]||'Unknown'))}
function actionButton(label,symbol,action,id,cls='button small'){const b=children(el('button',cls),symbol?icon(symbol):null,label?el('span','',label):null);b.type='button';b.dataset.action=action;b.dataset.id=String(id);if(!label){b.title=action.startsWith('edit')?'Edit':action.startsWith('delete')?'Delete':action==='test'?'Test traffic':'Reconnect';b.setAttribute('aria-label',b.title)}return b}
function protocolBadge(t){return el('span',`badge protocol ${t.kind==='http'?'http':t.kind==='local'?'local':''}`,t.kind==='local'?'TCP':t.kind==='http'?'HTTP':'SOCKS5')}
function tunnelTable(list,compact=false,grouped=false){if(!list.length){if(state.tunnels.length)return emptyState('No matching forwarding','Try another search or clear the forwarding filters.');return emptyState('Create your first port forwarding','Choose a saved session and create a SOCKS, HTTP or TCP forwarding port.',()=>state.servers.length?openTunnel():openServer(),state.servers.length?'New forwarding':'New session')}const wrap=el('div','table-wrap');const table=el('table');table.setAttribute('aria-label','Port forwarding');const header=el('thead');const hrow=el('tr');for(const title of [grouped?'Forwarding Name':'Name / Session','Type','Local endpoint','Status','Actions']){const th=el('th','',title);th.scope='col';hrow.append(th)}header.append(hrow);table.append(header);const body=el('tbody');for(const t of list){const row=el('tr');const server=serverById(t.server_id);const running=isRunning(t);const name=el('div','row-name');const symbol=children(el('div',`tunnel-symbol ${t.status==='connected'?'running':t.status==='error'?'error':''}`),icon(t.kind==='http'?'globe':'tunnel'));const info=children(el('div'),el('div','primary-text',t.name||'Unnamed forwarding'));let secondary=grouped?'':server?.name||'Unknown session';if(t.kind==='local'&&t.remote_host)secondary+=`${secondary?' · ':''}${t.remote_host}:${t.remote_port}`;if(secondary)info.append(el('div','secondary-text',secondary));children(name,symbol,info);row.append(children(el('td'),name));row.append(children(el('td'),protocolBadge(t)));const port=el('button','copy-port mono',`127.0.0.1:${t.local_port}`);port.type='button';port.title='Copy local endpoint';port.setAttribute('aria-label',`Copy local endpoint for ${t.name||'forwarding'}`);port.dataset.action='copy';port.dataset.id=String(t.id);row.append(children(el('td'),port));const status=children(el('td'),statusBadge(t));const pool=Math.max(1,Number(t.pool_size)||1);status.append(el('span','session-detail',running?`${num(t.healthy_sessions)} / ${num(pool)} SSH sessions ready`:`${num(pool)} SSH session${pool===1?'':'s'}`));if(t.last_test){const result=el('div',`session-detail test-result ${t.last_test.ok?'passed':'failed'}`,`${t.last_test.ok?'Test passed':'Test failed'} · ${timeText(t.last_test.time)}`);result.title=t.last_test.message||'';status.append(result)}if(t.last_error){const error=el('div','error-inline',String(t.last_error).slice(0,190));error.title=String(t.last_error);status.append(error)}row.append(status);const actions=el('div','row-actions');let control=actionButton(running?'Disconnect':'Connect',running?'stop':'play',running?'stop':'start',t.id,`button small ${running?'':'soft'}`);control.setAttribute('aria-label',`${running?'Disconnect':'Connect'} ${t.name||'forwarding'}`);if(busy.has(String(t.id))){control.setAttribute('aria-busy','true');control.replaceChildren(el('span','spinner'));control.classList.add('busy');control.disabled=true}actions.append(control);if(running&&Number(t.healthy_sessions)>0){const test=actionButton('','shield','test',t.id,'icon-button mini');test.setAttribute('aria-label',`Test traffic for ${t.name||'forwarding'}`);test.disabled=busy.has(String(t.id));actions.append(test)}if(running){const restart=actionButton('','refresh','restart',t.id,'icon-button mini');restart.setAttribute('aria-label',`Reconnect ${t.name||'forwarding'}`);restart.disabled=busy.has(String(t.id));actions.append(restart)}actions.append(el('span','action-divider'));for(const action of ['edit','delete']){const b=actionButton('',action==='edit'?'edit':'trash',action,t.id,`icon-button mini ${action==='delete'?'delete':''}`);b.setAttribute('aria-label',`${action==='edit'?'Edit':'Delete'} forwarding ${t.name||'Unnamed forwarding'}`);b.disabled=running||busy.has(String(t.id));if(running)b.title=action==='edit'?'Disconnect this forwarding before editing.':'Disconnect this forwarding before deleting.';actions.append(b)}row.append(children(el('td'),actions));body.append(row)}table.append(body);wrap.append(table);return wrap}
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
    const nameGroup=children(el('div','forwarding-group-name'),heading);
    const title=children(el('div','forwarding-group-title'),nameGroup,count);
    const route=el('div','group-route',`Firewall: ${firewallRoute(server)}`);
    const text=children(el('div','forwarding-group-text'),title,route);
    children(summary,server?sessionStatusSymbol(server,'forwards'):children(el('div','server-symbol'),icon('server')),children(el('div','forwarding-group-info'),text));
    header.append(summary);
    if(server){const add=actionButton('Add forwarding','plus','add-forwarding',server.id,'text-button');add.setAttribute('aria-label',`Add forwarding for session ${name}`);header.append(add)}
    const table=tunnelTable(forwards,false,true);
    table.querySelector('table').setAttribute('aria-label',`Port forwarding for ${name}`);
    children(group,server?colorMarker(server,'forwards'):null,header,table);
    return group;
  });
}
function renderTunnels(){
  const search=$('tunnelSearch').value.trim().toLocaleLowerCase('en');
  renderSessionFilterOptions();
  const list=state.tunnels.filter(t=>matchesTunnelFilters(t,search));
  renderFilterControls('tunnels');
  $('allTunnels').replaceChildren(...groupedForwarding(list));
  const dashboard=[...state.tunnels].sort((a,b)=>Number(isRunning(b))-Number(isRunning(a))).slice(0,5);
  $('dashboardTunnels').replaceChildren(tunnelTable(dashboard,true));
}
function serverInUse(serverId,onlyRunning=false){return state.servers.some(s=>{if(String(s.id)===String(serverId)&&s.desired_running)return true;if(onlyRunning&&!s.desired_running)return false;return (s.firewall_path||[]).some(id=>String(id)===String(serverId))})||state.tunnels.some(t=>{if(onlyRunning&&!isRunning(t))return false;let current=serverById(t.server_id);const seen=new Set();while(current&&!seen.has(String(current.id))){if(String(current.id)===String(serverId))return true;seen.add(String(current.id));current=current.jump_id?serverById(current.jump_id):null}return false})}
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

function sessionStatusSymbol(server,scope){
  const metrics=sessionMetrics(server);
  const status={connecting:'starting',disconnected:'stopped',in_use_as_firewall:'firewall'}[metrics.status]||metrics.status;
  const own=status==='firewall'?'Firewall in use; no own SSH connection.':`${statusText[status]||'Unknown status'}.`;
  const description=own+(metrics.firewall&&status!=='firewall'?' Also in use as a Firewall.':'');
  const symbol=children(el('span',`server-symbol session-status-icon status-${status}`),icon('server'));
  symbol.id=`session-status-${scope}-${server.id}`;symbol.tabIndex=0;symbol.dataset.statusSession=String(server.id);
  symbol.setAttribute('role','img');symbol.setAttribute('aria-label',`${server.name||'Unnamed session'}: ${description}`);
  symbol.title=description;
  const tooltip=el('span','session-status-tooltip',description);tooltip.id=`${symbol.id}-tooltip`;tooltip.setAttribute('role','tooltip');
  symbol.setAttribute('aria-describedby',tooltip.id);
  return children(el('div','session-status-symbol'),symbol,tooltip);
}

// Tools and Firewall details float outside the card/grid flow. Only one is open.
let activePopover=null;
function positionPopover(){
  if(!activePopover)return;
  const toggle=$(activePopover.toggleId),panel=activePopover.panel;
  if(!toggle||!toggle.getClientRects().length){closePopover();return}
  const anchor=toggle.getBoundingClientRect(),box=panel.getBoundingClientRect();
  const beside=toggle.id==='toolsToggle'&&innerWidth>580;
  let left=beside?anchor.right+8:anchor.left;
  let top=beside?anchor.top:anchor.bottom+7;
  if(top+box.height>innerHeight-12)top=anchor.top-box.height-7;
  panel.style.left=`${Math.max(12,Math.min(left,innerWidth-box.width-12))}px`;
  panel.style.top=`${Math.max(12,Math.min(top,innerHeight-box.height-12))}px`;
}
function closePopover(restoreFocus=false){
  if(!activePopover)return;
  const {toggleId,panel}=activePopover;
  const focusInside=panel.contains(document.activeElement);
  activePopover=null;panel.hidden=true;
  const toggle=$(toggleId);
  toggle?.setAttribute('aria-expanded','false');
  if(restoreFocus||focusInside)(toggle||document.querySelector(`.nav-button[data-view="${currentView}"]`))?.focus({preventScroll:true});
  queueMicrotask(maybeShowReleaseNotice);
}
function openPopover(toggle,panel,focusTarget=panel){
  if(activePopover?.toggleId===toggle.id){closePopover(true);return}
  closePopover();closeUpdates();
  activePopover={toggleId:toggle.id,panel};panel.hidden=false;
  toggle.setAttribute('aria-expanded','true');positionPopover();
  focusTarget.focus({preventScroll:true});
}
function firewallDependents(server){
  const seen=new Set([String(server.id)]),dependents=[];
  for(const candidate of state.servers){
    const id=String(candidate.id);
    if(seen.has(id))continue;
    const path=new Set((candidate.firewall_path||[]).map(String));
    const visited=new Set([id]);
    let current=candidate;
    while(current?.jump_id&&!visited.has(String(current.jump_id))){
      const jump=String(current.jump_id);visited.add(jump);path.add(jump);
      current=serverById(jump);
    }
    if(!path.has(String(server.id)))continue;
    seen.add(id);
    const metrics=sessionMetrics(candidate);
    const active=!!candidate.desired_running||metrics.active>0||metrics.sshActive>0||metrics.firewall;
    const status=active?({in_use_as_firewall:'firewall',connecting:'starting',disconnected:'starting'}[metrics.status]||metrics.status):'stopped';
    const label=status==='firewall'?'Firewall in use':statusText[status]||'Connecting';
    dependents.push({server:candidate,active,status,label});
  }
  return dependents;
}
function renderFirewallDependents(server){
  const dependents=firewallDependents(server),groups=[];
  for(const [active,title] of [[true,'Using this Firewall'],[false,'Saved · disconnected']]){
    const items=dependents.filter(item=>item.active===active);
    if(!items.length)continue;
    const section=children(el('section','dependent-group'),el('h3','',`${title} · ${num(items.length)}`));
    const list=el('ul','dependent-list');
    for(const item of items){
      const name=el('span','dependent-name',item.server.name||'Unnamed session');
      list.append(children(el('li'),name,el('span',`dependent-state ${item.status}`,item.label)));
    }
    groups.push(children(section,list));
  }
  $('firewallDependents').replaceChildren(...groups);
}
function updateFirewallDetails(server){
  const metrics=sessionMetrics(server),count=Number(server.dependent_session_count)||0;
  const panel=$('firewallDetails');
  const sessions=`${num(count)} dependent session${count===1?'':'s'}.`;
  const usage=metrics.firewall?'Firewall in use by other active SSH connections.':'No other active SSH connections are using this Firewall.';
  const forwards=Number(server.dependent_forward_count)||0;
  const forwarding=forwards>0?`${num(forwards)} dependent forward${forwards===1?'':'s'} active.`:'';
  $('firewallDetailsTitle').textContent=`Firewall · ${server.name||'Unnamed session'}`;
  $('firewallDetailsCopy').textContent=[sessions,usage,forwarding].filter(Boolean).join(' ');
  $('firewallDetailsRoute').textContent=`Upstream route: ${firewallRoute(server)}`;
  panel.dataset.serverId=String(server.id);
  renderFirewallDependents(server);
}
function firewallIndicator(server,metrics){
  if(!sessionFirewallRoles().has(String(server.id)))return null;
  const count=Number(server.dependent_session_count)||0;
  const label=`Firewall details for ${server.name||'Unnamed session'}: ${num(count)} dependent session${count===1?'':'s'}${metrics.firewall?', in use':''}`;
  const button=children(el('button',`firewall-indicator${metrics.firewall?' in-use':''}`),el('span','firewall-label','Firewall in use'));
  button.type='button';button.id=`firewall-info-${server.id}`;button.dataset.firewall=String(server.id);
  button.title=label;button.setAttribute('aria-label',label);
  button.setAttribute('aria-controls','firewallDetails');
  button.setAttribute('aria-expanded',String(activePopover?.toggleId===button.id));
  return button;
}
$('toolsToggle').addEventListener('click',()=>openPopover($('toolsToggle'),$('toolsMenu'),$('importConfig')));
$('firewallDetailsClose').addEventListener('click',()=>closePopover(true));
$('sessionColorClose').addEventListener('click',()=>closePopover(true));
const colorNames=['Teal','Purple','Amber','Green','Blue','Pink','Coral','Gray'];
for(const [index,color]of SESSION_COLORS.entries()){
  const button=el('button','color-swatch');button.type='button';button.title=colorNames[index];
  button.setAttribute('aria-label',colorNames[index]);button.style.backgroundColor=color;
  button.addEventListener('click',()=>{$('sessionColorChoice').value=color});$('sessionColorPalette').append(button);
}
document.addEventListener('click',event=>{
  const button=event.target.closest('button[data-color-session]');
  if(!button)return;
  const server=serverById(button.dataset.colorSession);if(!server)return;
  $('sessionColorTitle').textContent=`Color · ${server.name||'Unnamed session'}`;
  $('sessionColorPanel').dataset.serverId=String(server.id);$('sessionColorChoice').value=sessionColor(server);
  $('sessionColorError').textContent='';openPopover(button,$('sessionColorPanel'),$('sessionColorChoice'));
});
$('applySessionColor').addEventListener('click',async()=>{
  const button=$('applySessionColor'),color=$('sessionColorChoice').value;
  if(!validSessionColor(color))return;
  button.disabled=true;
  try{
    await request(`/api/servers/${encodeURIComponent($('sessionColorPanel').dataset.serverId)}`,{method:'PUT',body:{color}});
    closePopover(true);await refresh(true);toast('Session color saved.');
  }catch(error){$('sessionColorError').textContent=errorMessage(error)}finally{button.disabled=false}
});
$('toolsMenu').addEventListener('click',event=>{if(event.target.closest('button'))closePopover(true)});
for(const scope of ['servers','tunnels']){
  const panel=$(scope+'Filters'),toggle=$(scope+'FilterToggle');
  toggle.addEventListener('click',()=>openPopover(toggle,panel,panel.querySelector('input')||panel));
  $(scope+'FiltersClose').addEventListener('click',()=>closePopover(true));
  panel.addEventListener('change',event=>{
    const input=event.target.closest('input[data-filter-group]');if(!input)return;
    const values=viewFilters[scope][input.dataset.filterGroup];
    if(input.checked)values.add(input.value);else values.delete(input.value);
    (scope==='servers'?renderServers:renderTunnels)();
  });
  $(scope+'ClearFilters').addEventListener('click',()=>{
    Object.values(viewFilters[scope]).forEach(values=>values.clear());
    (scope==='servers'?renderServers:renderTunnels)();
  });
}

document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&activePopover){event.preventDefault();closePopover(true)}
});
document.addEventListener('click',event=>{
  if(activePopover&&!activePopover.panel.contains(event.target)&&!$(activePopover.toggleId)?.contains(event.target))closePopover();
});
document.addEventListener('focusin',event=>{
  if(activePopover&&!activePopover.panel.contains(event.target)&&!$(activePopover.toggleId)?.contains(event.target))closePopover();
});
window.addEventListener('resize',positionPopover);
document.addEventListener('scroll',positionPopover,true);

function renderServers(){
  const grid=$('serverGrid');
  renderFilterControls('servers');
  const focusedIndicator=document.activeElement?.dataset.firewall;
  const focusedColor=document.activeElement?.closest('#serverGrid')?document.activeElement?.id:null;
  if(!state.servers.length){const empty=emptyState('Add your first session','Save SSH connection settings, then create port forwarding for that session.',()=>openServer(),'New session','server');empty.style.gridColumn='1 / -1';empty.classList.add('panel');grid.replaceChildren(empty);if(activePopover?.panel.dataset.serverId)closePopover();return}
  const query=$('sessionSearch').value.trim().toLowerCase();
  const firewalls=sessionFirewallRoles();
  const visible=state.servers.filter(s=>matchesSessionFilters(s,query,firewalls));
  const nodes=visible.map(s=>{
    const metrics=sessionMetrics(s),pending=sessionBusy.has(String(s.id))||metrics.own.some(t=>busy.has(String(t.id)));
    const card=el('article','panel server-card');
    const head=el('div','server-card-head');
    const name=el('div','primary-text',s.name||'Unnamed session');name.title=s.name||'Unnamed session';
    const title=children(el('div','session-title'),name,firewallIndicator(s,metrics));
    const text=children(el('div','session-name-block'),title,el('div','secondary-text mono',`${s.host}:${s.port}`));
    children(head,sessionStatusSymbol(s,'sessions'),children(el('div','session-heading'),text));
    const tools=el('div','server-card-tools');
    const edit=actionButton('','edit','edit-server',s.id,'icon-button');edit.setAttribute('aria-label',`Edit session ${s.name||'Unnamed session'}`);edit.disabled=serverInUse(s.id,true)||pending;if(edit.disabled)edit.title='Disconnect dependent forwarding before editing this session.';
    const remove=actionButton('','trash','delete-server',s.id,'icon-button delete');remove.setAttribute('aria-label',`Delete session ${s.name||'Unnamed session'}`);remove.disabled=serverInUse(s.id)||state.servers.some(x=>String(x.jump_id)===String(s.id))||pending;if(remove.disabled)remove.title='This session is used by forwarding or by another session as a firewall.';
    children(tools,edit,remove);head.append(tools);
    children(card,colorMarker(s,'sessions'),head);
    const statusbar=el('div','session-statusbar');
    const counts=el('div','session-counts');
    counts.append(el('div','',metrics.total?`${num(metrics.active)} / ${num(metrics.total)} forward${metrics.total===1?'':'s'} active`:'No forwarding configured'));
    if(metrics.active>0||metrics.sshActive>0)counts.append(el('div','',metrics.sshActive?`${num(metrics.sshHealthy)} / ${num(metrics.sshActive)} SSH sessions ready`:'0 SSH sessions ready'));
    statusbar.append(counts);
    const status=children(el('div','session-status'),statusbar);
    if(s.last_error)status.append(el('div','error-inline',s.last_error));
    card.append(status);
    const details=el('div','server-card-details');
    const interval=Number(s.keepalive_interval??30),missed=Number(s.keepalive_count??3);
    const keepalive=interval?`${num(interval)} seconds · ${num(missed)} missed replies`:'Off';
    for(const [label,value,mono]of [['Username',s.username||'—',true],['Firewall route',firewallRoute(s),false],['Authentication',authDescription(s),false],['Keepalive',keepalive,false]])details.append(children(el('div'),el('div','detail-label',label),el('div',`detail-value${mono?' mono':''}`,value)));
    card.append(details);
    const controls=el('div','session-actions');
    for(const [action,label,symbol]of [['connect','Connect','play'],['disconnect','Disconnect','stop'],['reconnect','Reconnect','refresh']]){
      const button=actionButton(label,symbol,`${action}-session`,s.id,`button small${action==='connect'?' soft':''}`);
      button.setAttribute('aria-label',`${label} session ${s.name||'Unnamed session'}`);
      button.disabled=pending||(metrics.total?(action==='connect'?metrics.active>=metrics.total:metrics.active===0):(action==='connect'?!!s.desired_running:!s.desired_running));
      if(pending)button.setAttribute('aria-busy','true');
      controls.append(button);
    }
    const controlGroup=children(el('div','session-control-group'),controls,el('p','session-control-note',metrics.total?'Controls apply to this session’s port forwarding.':'Connect an authenticated SSH session without a local port or shell.'));
    if(metrics.status==='error'){
      const error=metrics.own.find(t=>t.last_error)?.last_error;
      if(error){const message=el('div','session-error',String(error).slice(0,240));message.title=String(error);controlGroup.append(message)}
    }
    card.append(controlGroup);
    const bottom=el('div','server-card-bottom');
    if(s.host_key_trusted===true)bottom.append(children(el('span','status-note'),icon('shield'),el('span','', 'Host key verified')));
    else if(s.host_key_trusted===false)bottom.append(el('span','badge connecting','Host key needed'));
    else bottom.append(el('span','secondary-text','Session saved'));
    const add=el('button','text-button','Add forwarding');add.type='button';add.setAttribute('aria-label',`Add forwarding for session ${s.name||'Unnamed session'}`);add.addEventListener('click',()=>openTunnel(null,s.id));bottom.append(add);card.append(bottom);
    return card;
  });
  if(!nodes.length){
    const empty=emptyState('No matching sessions','Try another search or clear the session filters.',null,null,'search');
    empty.style.gridColumn='1 / -1';empty.classList.add('panel');nodes.push(empty);
  }
  grid.replaceChildren(...nodes);
  if(focusedIndicator)$(`firewall-info-${focusedIndicator}`)?.focus({preventScroll:true});
  if(focusedColor)$(focusedColor)?.focus({preventScroll:true});
  if(activePopover?.panel===$('firewallDetails')){
    const server=serverById($('firewallDetails').dataset.serverId);
    if(server){updateFirewallDetails(server);positionPopover()}else closePopover();
  }
  if(activePopover?.panel===$('sessionColorPanel'))positionPopover();
}
$('serverGrid').addEventListener('click',event=>{
  const button=event.target.closest('button[data-firewall]');
  if(!button)return;
  const server=serverById(button.dataset.firewall);
  if(server){updateFirewallDetails(server);openPopover(button,$('firewallDetails'))}
});
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
function deviceName(){return ['linux','win32'].includes(window.HopHarborPlatform||state?.service?.platform)?'this computer':'this Mac'}
function credentialStore(){return state?.service?.credential_store||(window.HopHarborPlatform==='win32'?'Windows Credential Manager':window.HopHarborPlatform==='linux'?'GNOME Keyring':'Keychain')}
function renderPlatform(){
  const device=deviceName(),store=credentialStore();
  $('managedDevice').textContent=`Managed on ${device}.`;
  $('forwardingDevice').textContent=`Connection configurations on ${device}`;
  $('privateDevice').textContent=`Private access on ${device}`;
  $('autostartDevice').textContent=`Connect automatically when you log in to ${device}`;
  $('credentialNote').textContent=`Passwords you enter are saved securely in ${store==='Keychain'?'macOS Keychain':store}. Saved passwords are never displayed here.`;
  if($('lockedScreen').hidden)$('lockedCopy').textContent=`Open this panel from HopHarbor on ${device} to sign in securely.`;
}
function render(){renderPlatform();const focused=document.activeElement;const colorFocus=focused?.dataset.colorSession||focused?.dataset.statusSession?focused.id:null;const focusInfo=focused&&focused.dataset.action?{action:focused.dataset.action,id:focused.dataset.id,container:focused.closest('#dashboardTunnels,#allTunnels,#serverGrid')?.id}:null;const active=state.tunnels.filter(t=>['connected','degraded'].includes(t.status)).length;const errors=state.tunnels.filter(t=>t.status==='error').length;const starting=state.tunnels.filter(t=>t.status==='starting').length;$('metricActive').textContent=num(active);$('metricTunnels').textContent=num(state.tunnels.length);$('metricServers').textContent=num(state.servers.length);$('navTunnelCount').textContent=num(state.tunnels.length);$('metricActiveFoot').textContent=errors?`${num(errors)} forwarding configuration${errors===1?' needs':'s need'} attention`:starting?`${num(starting)} connecting`:'SSH connection status';$('metricServersFoot').textContent=state.servers.length?'Connection settings and firewalls':'Add a session to get started';$('lastUpdated').textContent=lastSuccess?`Updated at ${timeText(lastSuccess)}`:'Loading status...';const appInfo=window.HopHarborNativeVersion||state.service;$('appVersion').textContent=`v${String(appInfo.version||'1.4.2').replace(/^v/i,'').slice(0,32)} · build ${String(appInfo.build??15).slice(0,16)}`;renderUpdatesSummary();const migration=state.migration;$('migrationBanner').hidden=setupNoteDismissed||!migration.message||migration.phase==='complete';$('migrationTitle').textContent=migration.phase==='testing'?'Testing mode · ':'Migration status · ';$('migrationText').textContent=migration.message||'';renderTunnels();renderServers();renderLogs();renderRelease();if(colorFocus)$(colorFocus)?.focus({preventScroll:true});if(focusInfo&&focusInfo.container){const replacement=Array.from($(focusInfo.container).querySelectorAll('button[data-action]')).find(b=>b.dataset.action===focusInfo.action&&b.dataset.id===focusInfo.id&&!b.disabled);if(replacement)replacement.focus({preventScroll:true})}}
function toast(message,error=false){const n=children(el('div',`toast${error?' error':''}`),icon(error?'warning':'check'),el('span','',String(message).slice(0,350)));$('toastRegion').append(n);setTimeout(()=>n.remove(),error?8000:4500)}
async function confirmDelete(title,message,confirmLabel='Delete'){const d=$('confirmDialog');$('confirmTitle').textContent=title;$('confirmCopy').textContent=message;$('confirmYes').textContent=confirmLabel;d.showModal();return new Promise(resolve=>{let finished=false;const finish=value=>{if(finished)return;finished=true;d.close();$('confirmYes').onclick=null;$('confirmNo').onclick=null;$('confirmClose').onclick=null;d.oncancel=null;resolve(value)};$('confirmYes').onclick=()=>finish(true);$('confirmNo').onclick=()=>finish(false);$('confirmClose').onclick=()=>finish(false);d.oncancel=e=>{e.preventDefault();finish(false)}})}
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
    else toast(`${server.name}: ${action==='connect'?'Connect':action==='disconnect'?'Disconnect':'Reconnect'} requested for ${num(requested)} connection${requested===1?'':'s'}.`);
    await refresh(true);
  }catch(err){toast(errorMessage(err),true)}
  finally{sessionBusy.delete(String(id));for(const t of own)busy.delete(String(t.id));renderServers();renderTunnels()}
}
async function serverAction(action,id){const s=serverById(id);if(!s)return;if(['connect-session','disconnect-session','reconnect-session'].includes(action))return sessionConnectionAction(action.replace('-session',''),id);if(action==='edit-server'){openServer(s);return}if(!await confirmDelete('Delete session',`Delete the saved session "${s.name}"?`))return;try{await request(`/api/servers/${encodeURIComponent(id)}`,{method:'DELETE'});toast('Session deleted.');await refresh(true)}catch(err){toast(errorMessage(err),true)}}
function option(value,label){const n=el('option','',label);n.value=String(value??'');return n}
function field(form,name){return form.elements.namedItem(name)}
function openServer(server=null){const form=$('serverForm');form.reset();clearSensitiveFields();form.dataset.hasPassword=server?.has_password?'true':'false';form.dataset.hasKeyPassphrase=server?.has_key_passphrase?'true':'false';$('serverFormError').textContent='';$('serverDialogTitle').textContent=server?'Edit session':'New session';field(form,'id').value=server?.id||'';field(form,'name').value=server?.name||'';field(form,'color').value=server?sessionColor(server):newSessionColor();field(form,'host').value=server?.host||'';field(form,'port').value=server?.port||22;field(form,'username').value=server?.username||'';field(form,'keepalive_interval').value=server?.keepalive_interval??30;field(form,'keepalive_count').value=server?.keepalive_count??3;const identity=server?server.identity_file||'':state.service.default_identity_file||state.servers.find(s=>s.identity_file)?.identity_file||'';field(form,'identity_file').value=identity;field(form,'auth_mode').value=server?authMode(server):identity?'key':'agent';const choices=[option('','None'),...state.servers.filter(s=>String(s.id)!==String(server?.id)).map(s=>option(s.id,s.name))];field(form,'jump_id').replaceChildren(...choices);field(form,'jump_id').value=server?.jump_id||'';form.dataset.originalHost=server?.host||'';form.dataset.originalPort=String(server?.port||22);form.dataset.originalTrusted=server?.host_key_trusted?'true':'false';delete form.dataset.trustTicket;$('verifyEndpoint').hidden=!server?.host_key_trusted; $('hostKeyHelp').textContent=server?.host_key_trusted?'The saved endpoint is verified. Changing Hostname or Port requires verification before saving.':'Obtain the trusted host public key from the server administrator. This is separate from your login key.';$('serverDialog').querySelectorAll('details').forEach(details=>details.open=false);updateAuthForm();$('serverDialog').showModal();$('serverName').focus({preventScroll:true});$('serverDialog').querySelector('.modal-body').scrollTop=0}
function updateAuthForm(){const form=$('serverForm');const mode=field(form,'auth_mode').value;const useKey=['key','key_password'].includes(mode);const usePassword=['password','key_password'].includes(mode);$('identityField').hidden=!useKey;$('keyPassphraseField').hidden=!useKey;$('passwordField').hidden=!usePassword;field(form,'identity_file').required=false;field(form,'password').required=false;field(form,'key_passphrase').required=false;if(!useKey)field(form,'key_passphrase').value='';if(!usePassword)field(form,'password').value='';const hasPassword=form.dataset.hasPassword==='true';const hasKeyPassphrase=form.dataset.hasKeyPassphrase==='true';field(form,'password').placeholder=hasPassword?'Leave blank to keep the saved password':'You can add this later';$('passwordHelp').textContent=hasPassword?`A password is saved in ${credentialStore()}. Leave this field blank to keep it.`:'No password is saved for this session. You can add it later.';field(form,'key_passphrase').placeholder=hasKeyPassphrase?'Leave blank to keep the saved passphrase':'Leave blank if the key is not encrypted';$('keyPassphraseHelp').textContent=hasKeyPassphrase?`A key passphrase is saved securely in ${credentialStore()} and is never displayed here.`:'Needed only for an encrypted private key. You can add it later.'}
function openTunnel(tunnel=null,serverId=null){if(!state.servers.length){toast('Add a session first.');openServer();return}const form=$('tunnelForm');form.reset();$('tunnelFormError').textContent='';$('tunnelDialogTitle').textContent=tunnel?'Edit forwarding':'New forwarding';field(form,'id').value=tunnel?.id||'';field(form,'name').value=tunnel?.name||'';field(form,'kind').value=tunnel?.kind||'socks';field(form,'server_id').replaceChildren(...state.servers.map(s=>option(s.id,s.name)));field(form,'server_id').value=tunnel?.server_id||serverId||state.servers[0].id;field(form,'local_port').value=tunnel?.local_port||'';field(form,'remote_host').value=tunnel?.remote_host||'127.0.0.1';field(form,'remote_port').value=tunnel?.remote_port||'';field(form,'pool_size').value=tunnel?.pool_size||1;field(form,'autostart').checked=!!tunnel?.autostart;updateTunnelForm();$('tunnelDialog').showModal();$('tunnelName').focus({preventScroll:true});$('tunnelDialog').querySelector('.modal-body').scrollTop=0}
function updateTunnelForm(){const form=$('tunnelForm');const kind=field(form,'kind').value;const local=kind==='local';$('tunnelTargetHostField').hidden=!local;$('tunnelTargetPortField').hidden=!local;field(form,'remote_host').required=local;field(form,'remote_port').required=local;const notes={socks:'Creates a local SOCKS5 proxy on 127.0.0.1. Save the configuration, then choose Connect when ready.',http:'Creates a local HTTP proxy through SSH on 127.0.0.1. Save the configuration, then choose Connect when ready.',local:'Forwards a local TCP port through SSH. The destination must be reachable from the SSH host. Saving does not connect.'};$('tunnelFormHelp').textContent=notes[kind]||notes.socks}
function validatePort(value,min=1){return Number.isInteger(Number(value))&&Number(value)>=min&&Number(value)<=65535}
function validateHost(value){return /^[A-Za-z0-9_.:\[\]-]+$/.test(value)&&value.length<=253&&!value.startsWith('-')}
async function saveServer(event){event.preventDefault();const form=$('serverForm');if(!form.reportValidity())return;const id=field(form,'id').value;const data={name:field(form,'name').value.trim(),color:field(form,'color').value,host:field(form,'host').value.trim(),port:Number(field(form,'port').value),username:field(form,'username').value.trim(),auth_mode:field(form,'auth_mode').value,identity_file:['key','key_password'].includes(field(form,'auth_mode').value)?field(form,'identity_file').value.trim():'',jump_id:field(form,'jump_id').value||null,keepalive_interval:Number(field(form,'keepalive_interval').value),keepalive_count:Number(field(form,'keepalive_count').value)};const password=field(form,'password').value;const keyPassphrase=field(form,'key_passphrase').value;if(['password','key_password'].includes(data.auth_mode)&&password.length)data.password=password;if(['key','key_password'].includes(data.auth_mode)&&keyPassphrase.length)data.key_passphrase=keyPassphrase;const hostKey=field(form,'host_key').value.trim();if(hostKey)data.host_key=hostKey;else if(form.dataset.trustTicket)data.trust_ticket=form.dataset.trustTicket;const error=$('serverFormError');error.textContent='';if(id&&form.dataset.originalTrusted==='true'&&(data.host!==form.dataset.originalHost||String(data.port)!==form.dataset.originalPort)&&!data.host_key&&!data.trust_ticket){error.textContent='Verify this new endpoint or enter a manually trusted host key before saving. Your saved endpoint is unchanged.';error.scrollIntoView({block:'nearest'});return}if(!data.name){error.textContent='Enter a Session Name.';return}if(!validateHost(data.host)){error.textContent='Enter a hostname or IP address. Enter the username in its own field.';return}if(!validatePort(data.port)){error.textContent='Port must be between 1 and 65535.';return}if(!data.username||/\s/.test(data.username)||data.username.startsWith('-')){error.textContent='Enter a valid SSH username without spaces.';return}if(!Number.isInteger(data.keepalive_interval)||data.keepalive_interval<0||data.keepalive_interval>600){error.textContent='Keepalive interval must be between 0 and 600 seconds.';return}if(!Number.isInteger(data.keepalive_count)||data.keepalive_count<1||data.keepalive_count>10){error.textContent='Missed replies must be between 1 and 10.';return}if(data.jump_id){let current=serverById(data.jump_id);const seen=new Set();while(current&&!seen.has(String(current.id))){if(id&&String(current.id)===String(id)){error.textContent='This Firewall creates a connection loop. Choose another session.';return}seen.add(String(current.id));current=current.jump_id?serverById(current.jump_id):null}}const button=$('saveServerButton');button.disabled=true;button.textContent='Saving...';try{await request(`/api/servers${id?`/${encodeURIComponent(id)}`:''}`,{method:id?'PUT':'POST',body:data});clearSensitiveFields();$('serverDialog').close();toast(id?'Session changes saved.':'Session added.');await refresh(true)}catch(err){error.textContent=errorMessage(err)}finally{button.disabled=false;button.textContent='Save session'}}
async function saveTunnel(event){event.preventDefault();const form=$('tunnelForm');if(!form.reportValidity())return;const id=field(form,'id').value;const kind=field(form,'kind').value;const data={name:field(form,'name').value.trim(),server_id:field(form,'server_id').value,kind,local_port:Number(field(form,'local_port').value),pool_size:Number(field(form,'pool_size').value),remote_host:kind==='local'?field(form,'remote_host').value.trim():'',remote_port:kind==='local'?Number(field(form,'remote_port').value):0,autostart:field(form,'autostart').checked};const error=$('tunnelFormError');error.textContent='';if(!data.name){error.textContent='Enter a Forwarding Name.';return}if(!validatePort(data.local_port,1024)){error.textContent='Local port must be between 1024 and 65535.';return}if(state.tunnels.some(t=>String(t.id)!==String(id)&&Number(t.local_port)===data.local_port)){error.textContent='This local port is already assigned to another forwarding configuration. Choose another port.';return}if(!serverById(data.server_id)){error.textContent='Choose a saved session.';return}if(!Number.isInteger(data.pool_size)||data.pool_size<1||data.pool_size>4){error.textContent='Choose between 1 and 4 SSH sessions.';return}if(kind==='local'&&(!validateHost(data.remote_host)||!validatePort(data.remote_port))){error.textContent='Enter a valid destination hostname and port.';return}const button=$('saveTunnelButton');button.disabled=true;button.textContent='Saving...';try{await request(`/api/tunnels${id?`/${encodeURIComponent(id)}`:''}`,{method:id?'PUT':'POST',body:data});$('tunnelDialog').close();toast(id?'Forwarding changes saved.':'Forwarding added.');await refresh(true)}catch(err){error.textContent=errorMessage(err)}finally{button.disabled=false;button.textContent='Save forwarding'}}
for(const n of document.querySelectorAll('[data-view]'))n.addEventListener('click',()=>goView(n.dataset.view));for(const n of document.querySelectorAll('[data-go-view]'))n.addEventListener('click',()=>goView(n.dataset.goView));for(const n of document.querySelectorAll('[data-close-dialog]'))n.addEventListener('click',()=>$(n.dataset.closeDialog).close());$('primaryAction').addEventListener('click',()=>currentView==='servers'?openServer():openTunnel());$('refreshButton').addEventListener('click',()=>refresh(true));$('retryButton').addEventListener('click',()=>refresh(true));$('lockedRetry').addEventListener('click',retryLockedPanel);$('tunnelSearch').addEventListener('input',renderTunnels);$('sessionSearch').addEventListener('input',renderServers);$('logSearch').addEventListener('input',renderLogs);$('serverAuth').addEventListener('change',updateAuthForm);$('serverDialog').addEventListener('close',clearSensitiveFields);document.querySelectorAll('input[name="kind"]').forEach(n=>n.addEventListener('change',updateTunnelForm));$('serverForm').addEventListener('submit',saveServer);$('tunnelForm').addEventListener('submit',saveTunnel);for(const id of ['dashboardTunnels','allTunnels'])$(id).addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(button&&!button.disabled){if(button.dataset.action==='add-forwarding')openTunnel(null,button.dataset.id);else tunnelAction(button.dataset.action,button.dataset.id)}});$('serverGrid').addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(button&&!button.disabled)serverAction(button.dataset.action,button.dataset.id)});document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh(true)});setInterval(()=>{if(!document.hidden&&authorized)refresh()},5000);
async function bootstrap(){const parameters=new URLSearchParams(location.hash.slice(1));const token=parameters.get('token');if(token){history.replaceState(null,'',location.pathname+location.search);try{await request('/api/session',{method:'POST',body:{token}});authorized=true;$('lockedScreen').hidden=true}catch(err){showLocked(errorMessage(err));return}}await refresh(true)}
renderPlatform();
bootstrap();

// Proof tickets belong to an exact editor snapshot. Late replies never restore
// trust after another field edit, cancellation, or opening a different session.
let endpointEditGeneration=0;
function endpointEdited(){
  endpointEditGeneration++;const form=$('serverForm');delete form.dataset.trustTicket;
  const changed=field(form,'host').value.trim()!==form.dataset.originalHost||String(Number(field(form,'port').value))!==form.dataset.originalPort;
  $('hostKeyHelp').textContent=changed?'This endpoint is unverified. Check it with the previous trusted key, or enter a host key obtained from a trusted source.':form.dataset.originalTrusted==='true'?'The saved endpoint has a trusted key.':'Obtain the trusted host public key from the server administrator.';
}
$('serverForm').addEventListener('input',endpointEdited);
$('serverForm').addEventListener('change',endpointEdited);
$('serverDialog').addEventListener('close',()=>{endpointEditGeneration++;delete $('serverForm').dataset.trustTicket});
$('verifyEndpoint').addEventListener('click',async()=>{
  const form=$('serverForm'),id=field(form,'id').value,generation=++endpointEditGeneration;
  const snapshot=JSON.stringify(Array.from(form.elements).map(e=>[e.name,e.value]));
  const button=$('verifyEndpoint');button.disabled=true;$('serverFormError').textContent='';$('hostKeyHelp').textContent='Checking strict host-key continuity and SSH authentication…';
  try{
    const result=await request(`/api/servers/${encodeURIComponent(id)}/verify-endpoint`,{method:'POST',body:{host:field(form,'host').value.trim(),port:Number(field(form,'port').value)}});
    if(generation!==endpointEditGeneration||!$('serverDialog').open||snapshot!==JSON.stringify(Array.from(form.elements).map(e=>[e.name,e.value])))return;
    form.dataset.trustTicket=result.ticket;$('hostKeyHelp').textContent=result.message;
  }catch(error){if(generation===endpointEditGeneration)$('hostKeyHelp').textContent=errorMessage(error)}finally{button.disabled=false}
});
let bulkBusy=false;
for(const button of document.querySelectorAll('[data-bulk-scope]'))button.addEventListener('click',async()=>{
  if(bulkBusy||busy.size||sessionBusy.size)return;bulkBusy=true;
  const controls=document.querySelectorAll('[data-bulk-scope]');controls.forEach(b=>b.disabled=true);
  try{
    const disconnect=button.dataset.bulkAction==='disconnect';
    const scope=button.dataset.bulkScope==='servers'?'Disconnect all port forwarding and all standalone SSH sessions, including Firewall sessions.':'Disconnect all port forwarding. Standalone SSH sessions will keep running.';
    if(disconnect&&!await confirmDelete('Disconnect all?',scope+' This may interrupt your internet connection. Saved settings will remain.','Disconnect'))return;
    const result=await request(`/api/bulk/${button.dataset.bulkScope}/${button.dataset.bulkAction}`,{method:'POST'});
    $('bulkTitle').textContent=disconnect?'Disconnection results':'Connection requests';
    $('bulkResults').textContent=`${result.summary.succeeded} of ${result.summary.requested} ${disconnect?'connections stopped':'requests accepted'}; ${result.summary.failed} failed.\n\n`+result.results.map(r=>`${r.name}: ${r.ok?(disconnect?'Disconnected':'Requested; monitor connection status'):r.error}`).join('\n');
    $('bulkDialog').showModal();await refresh(true);
  }catch(error){toast(errorMessage(error),true)}finally{bulkBusy=false;controls.forEach(b=>b.disabled=false)}
});
let importTicket=null;
$('importConfig').addEventListener('click',()=>{$('configFile').value='';$('configFile').click()});
$('configFile').addEventListener('change',async event=>{
  importTicket=null;const file=event.target.files?.[0];if(!file)return;
  try{
    if(file.size>262144)throw new Error('Configuration files must be 256 KiB or smaller.');
    const result=await request('/api/config/preview',{method:'POST',body:JSON.parse(await file.text())});
    importTicket=result.ticket;$('importError').textContent='';
    $('importPreview').textContent=`File: ${file.name}\n\n`+JSON.stringify(result.summary,null,2)+'\n\n'+result.warnings.join('\n')+'\n\n'+(result.changes||[]).join('\n');
    $('importDialog').showModal();
  }catch(error){toast(errorMessage(error),true)}
});
$('applyImport').addEventListener('click',async()=>{
  const button=$('applyImport');button.disabled=true;
  try{await request('/api/config/apply',{method:'POST',body:{ticket:importTicket}});importTicket=null;$('importDialog').close();toast('Configuration merged. Imported connections remain stopped.');await refresh(true)}catch(error){$('importError').textContent=errorMessage(error)}finally{button.disabled=false}
});
$('exportConfig').addEventListener('click',async()=>{
  try{
    const document=await request('/api/config/export');
    if(window.webkit?.messageHandlers?.hopharborPanel||window.chrome?.webview){postNativePanelMessage({action:'exportConfiguration',document});return}
    const url=URL.createObjectURL(new Blob([JSON.stringify(document,null,2)+'\n'],{type:'application/json'}));
    const link=el('a');link.href=url;link.download='HopHarbor-configuration.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(error){toast(errorMessage(error),true)}
});
window.addEventListener('hopharbor-file-result',event=>{if(event.detail?.status==='saved')toast('Configuration exported.');else if(event.detail?.status==='error')toast('Could not save the configuration file.',true)});
function renderRelease() {
  $('undoImport').hidden = !state.service.import_undo_available;
  const release = state.service.release || {};
  const noticeVersion = newReleaseVersion();
  let text = 'Release information has not been checked.';
  if (noticeVersion) text = `Version ${noticeVersion} is available.`;
  else if (['available', 'current', 'older'].includes(release.status) && stableVersion(release.latest_version)) {
    text = `Published stable release: ${release.latest_version}.`;
  } else if (release.status === 'unavailable') {
    text = 'Release information is unavailable. Try again later.';
  }
  $('releaseStatus').textContent = text + (release.checking ? ' Checking…' : '');
  $('releaseLink').href = officialReleaseURL(release.url) || OFFICIAL_RELEASES;
  $('releaseLink').textContent = noticeVersion ? 'View official release' : 'Official releases';
  $('checkRelease').disabled = !!release.checking;
  $('updateNotice').hidden = !noticeVersion;
  renderUpdatesSummary();
  positionUpdates();
  maybeShowReleaseNotice();
}
$('checkRelease').addEventListener('click',async()=>{try{state.service.release=await request('/api/release/check',{method:'POST'});renderRelease()}catch(error){toast(errorMessage(error),true)}});

$('undoImport').addEventListener('click',async()=>{try{await request('/api/config/undo',{method:'POST'});toast('Last import undone.');await refresh(true)}catch(error){toast(errorMessage(error),true)}});

const RELEASE_NOTICE_KEY = 'hopharbor.lastSeenRelease';
const OFFICIAL_RELEASES = 'https://github.com/kiyanibehzad/HopHarbor/releases';
const OFFICIAL_RELEASE_TAG = /^https:\/\/github\.com\/kiyanibehzad\/HopHarbor\/releases\/tag\/v?\d{1,6}\.\d{1,6}\.\d{1,6}$/;
let releaseNoticeSeen = '';
try { releaseNoticeSeen = localStorage.getItem(RELEASE_NOTICE_KEY) || ''; } catch {}

function officialReleaseURL(value) {
  return typeof value === 'string' && OFFICIAL_RELEASE_TAG.test(value) ? value : null;
}

function stableVersion(value) {
  const match = typeof value === 'string' && /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/.exec(value);
  return match ? match.slice(1).map(Number) : null;
}

function versionAfter(value, other) {
  const a = stableVersion(value), b = stableVersion(other);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return false;
}

function newReleaseVersion() {
  const release = state.service.release || {};
  const installed = window.HopHarborNativeVersion?.version || state.service.version;
  const url = officialReleaseURL(release.url);
  const version = stableVersion(release.latest_version);
  if (!['available', 'current', 'older'].includes(release.status) || !url || !version) return null;
  const tagVersion = stableVersion(url.slice(url.lastIndexOf('/') + 1));
  if (!tagVersion || tagVersion.join('.') !== version.join('.')) return null;
  return versionAfter(release.latest_version, installed) ? version.join('.') : null;
}

function acknowledgeRelease() {
  const version = newReleaseVersion();
  if (version && (!stableVersion(releaseNoticeSeen) || versionAfter(version, releaseNoticeSeen))) {
    releaseNoticeSeen = version;
    try { localStorage.setItem(RELEASE_NOTICE_KEY, version); } catch {}
  }
}

function renderUpdatesSummary() {
  const version = newReleaseVersion();
  const notice = version ? ` Version ${version} is available.` : '';
  const status = $('serviceLabel').title || 'Connecting to local service';
  const label = `${status}. About and updates.${notice}`;
  $('updatesToggle').title = label;
  $('updatesToggle').setAttribute('aria-label', label);
}

function positionUpdates() {
  if ($('updatesToggle').getAttribute('aria-expanded') !== 'true') return;
  const panel = $('updatesContent');
  const anchor = $('updatesToggle').getBoundingClientRect();
  const width = Math.min(260, window.innerWidth - 24);
  panel.style.width = `${width}px`;
  const height = panel.getBoundingClientRect().height;
  let left = window.innerWidth <= 580 ? anchor.right - width : anchor.left;
  left = Math.max(12, Math.min(left, window.innerWidth - width - 12));
  let top = anchor.top - height - 10;
  if (top < 12) top = anchor.bottom + 10;
  top = Math.max(12, Math.min(top, window.innerHeight - height - 12));
  panel.style.left = `${left}px`;
  panel.style.top = `${top}px`;
}

function openUpdates(focus = false) {
  closePopover();
  $('updatesPanel').classList.add('updates-open');
  $('updatesToggle').setAttribute('aria-expanded', 'true');
  positionUpdates();
  acknowledgeRelease();
  if (focus) $('checkRelease').focus({preventScroll: true});
}

function closeUpdates(returnFocus = false) {
  if ($('updatesToggle').getAttribute('aria-expanded') === 'true') acknowledgeRelease();
  $('updatesPanel').classList.remove('updates-open');
  $('updatesToggle').setAttribute('aria-expanded', 'false');
  if (returnFocus) $('updatesToggle').focus({preventScroll: true});
}

function maybeShowReleaseNotice() {
  const version = newReleaseVersion();
  if (!version || !loaded || !authorized || document.hidden || activePopover || document.querySelector('dialog[open]')) return;
  if (stableVersion(releaseNoticeSeen) && !versionAfter(version, releaseNoticeSeen)) return;
  // Automatic notices never move focus, activate a window, or navigate a URL.
  openUpdates(false);
}

$('updatesToggle').addEventListener('click', () => {
  if ($('updatesToggle').getAttribute('aria-expanded') === 'true') closeUpdates();
  else openUpdates(true);
});
$('updatesClose').addEventListener('click', () => closeUpdates(true));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && $('updatesToggle').getAttribute('aria-expanded') === 'true') {
    closeUpdates(true);
    event.preventDefault();
  }
});
document.addEventListener('click', event => {
  if (!$('updatesPanel').contains(event.target)) closeUpdates();
});
document.addEventListener('close', maybeShowReleaseNotice, true);
document.addEventListener('visibilitychange', maybeShowReleaseNotice);
window.addEventListener('resize', positionUpdates);
window.addEventListener('storage', event => {
  if (event.key === RELEASE_NOTICE_KEY) releaseNoticeSeen = event.newValue || '';
});
