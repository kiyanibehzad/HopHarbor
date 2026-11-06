// Loaded only by the isolated native WKWebView fixture, never by the app.
function checkSessionLayout(longText,geometryOnly=false) {
  const require=(ok,message)=>{if(!ok)throw new Error(message)};
  const saved=state.servers.map(s=>({...s}));
  const savedTunnels=state.tunnels;
  const rect=node=>{const r=node.getBoundingClientRect();return {top:r.top,left:r.left,width:r.width,height:r.height}};
  const geometry=()=>Array.from(document.querySelectorAll('.server-card')).map(card=>[
    card,...card.querySelectorAll('.server-card-head,.session-title,.server-card-head .secondary-text,.session-statusbar,.server-card-details,.server-card-details>div:nth-child(3),.session-actions,.server-card-bottom')
  ].map(rect));
  closeUpdates();closePopover();goView('servers');
  if(longText){
    state.servers[0].name='Synthetic research network with a long descriptive Firewall name '.repeat(3);
    state.servers[1].name='Synthetic workstation with a long descriptive session name '.repeat(3);
  }
  renderServers();
  if(!geometryOnly){
  const initialColor=sessionColor(state.servers[0]);renderServers();
  for(const [id,color]of Object.entries(state.service.color_vectors||{}))require(sessionColor({id})===color&&sessionColor({id:'remapped',portable_id:id})===color,'UI and portable legacy colors disagree');
  require(sessionColor(state.servers[0])===initialColor&&!('color' in state.servers[0]),'Legacy display rewrites or changes color');
  openServer(state.servers[0]);
  require($('serverColor').value.toUpperCase()===initialColor,'Legacy Editor color differs');
  $('serverDialog').close();openServer();
  const random=$('serverColor').value.toUpperCase();
  require(SESSION_COLORS.includes(random),'New Session color is outside palette');
  render();require($('serverColor').value.toUpperCase()===random,'Refresh rerolls New Session color');
  $('serverColor').value='#c67e9b';render();
  require($('serverColor').value==='#c67e9b','Refresh overwrites chosen Editor color');
  $('serverDialog').close();
  $('session-color-sessions-sample_firewall').click();$('sessionColorChoice').value='#7d9dd3';render();
  require(!$('sessionColorPanel').hidden&&$('sessionColorChoice').value==='#7d9dd3','Refresh disrupts active-session color picker');
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
  require(document.activeElement.id==='session-color-sessions-sample_firewall','Color Escape/focus failed');
  state.tunnels=[{id:'color-demo',server_id:'sample_firewall',kind:'socks',name:'Synthetic color forward',local_port:24001,pool_size:1,status:'stopped'}];
  renderTunnels();
  require($('session-color-forwards-sample_firewall').querySelector('.session-color-stripe').style.backgroundColor===$('session-color-sessions-sample_firewall').querySelector('.session-color-stripe').style.backgroundColor,'Forwarding group color differs from Session');
  state.tunnels=savedTunnels;renderTunnels();
  }
  const before=geometry();
  let maxDelta=0,pairs=0;
  for(let i=1;i<before.length;i++){
    if(Math.abs(before[i][0].top-before[i-1][0].top)>.5)continue;
    pairs++;
    for(let j=0;j<before[i].length;j++)maxDelta=Math.max(maxDelta,Math.abs(before[i][j].top-before[i-1][j].top));
    maxDelta=Math.max(maxDelta,Math.abs(before[i][0].height-before[i-1][0].height));
  }
  require(maxDelta<=.5,`Card row alignment differs by ${maxDelta}px`);
  require(document.documentElement.scrollWidth<=innerWidth+1,'Horizontal document overflow');
  for(const card of document.querySelectorAll('.server-card')){
    require(card.scrollWidth<=card.clientWidth+1,`Card overflow ${card.querySelector('.primary-text').textContent.slice(0,30)} ${card.scrollWidth}/${card.clientWidth}: `+JSON.stringify(Array.from(card.children).map(n=>({name:n.className,scroll:n.scrollWidth,width:n.clientWidth}))));
    require(card.querySelectorAll('.session-actions button').length===3,'Session controls changed');
    const nameRect=card.querySelector('.primary-text').getBoundingClientRect();
    const text=card.querySelector('.session-name-block').getBoundingClientRect();
    require(Math.abs(nameRect.left-card.querySelector('.secondary-text').getBoundingClientRect().left)<.5,'Name and IP do not align');
    const symbol=card.querySelector('.session-status-icon').getBoundingClientRect();
    require(symbol.width===36&&symbol.height===36&&Math.abs((symbol.top+symbol.height/2)-(text.top+text.height/2))<.5,'Server icon is not centered on name and IP');
    require(text.height<=38.5,'Name and IP are not compact');
    const title=card.querySelector('.session-title'),button=card.querySelector('.firewall-indicator');
    if(button){
      const badge=button.getBoundingClientRect(),name=card.querySelector('.primary-text').getBoundingClientRect();
      require(title.scrollWidth<=title.clientWidth+1&&name.width>0&&badge.left>=name.right,'Inline Firewall badge overlaps or hides name');
      require(Math.abs((badge.top+badge.height/2)-(name.top+name.height/2))<.5,'Firewall badge is not beside the title');
    }
  }
  if(geometryOnly){
    const original={...state.servers[0]},statusColors={};
    const head=rect(document.querySelector('.server-card-head'));
    for(const [status,css,label]of [['connected','connected','Connected'],['connecting','starting','Connecting'],['degraded','degraded','Partially connected'],['error','error','Connection error'],['disconnected','stopped','Disconnected'],['in_use_as_firewall','firewall','no own SSH connection']]){
      Object.assign(state.servers[0],{connection_status:status,firewall_in_use:status==='in_use_as_firewall'});renderServers();
      const symbol=$('session-status-sessions-sample_firewall');
      require(symbol.classList.contains('status-'+css)&&symbol.getAttribute('aria-label').includes(label)&&symbol.title.includes(label),'Status icon text/class mismatch');
      statusColors[css]=getComputedStyle(symbol).color;
      symbol.focus();
      require(getComputedStyle(symbol.nextElementSibling).display==='block'&&symbol.nextElementSibling.textContent.includes(label),`Keyboard status tooltip unavailable: ${status}, ${innerWidth}, ${document.documentElement.dataset.appearance}, focus=${document.activeElement.id}, window=${document.hasFocus()}, display=${getComputedStyle(symbol.nextElementSibling).display}`);
      render();
      require(document.activeElement.id===symbol.id&&$(symbol.id).title.includes(label),'Status icon focus/text lost during refresh');
      require(JSON.stringify(rect(document.querySelector('.server-card-head')))===JSON.stringify(head),'Status changes move header geometry');
      require(!document.querySelector('.session-statusbar .badge'),'Separate Session status badge remains');
    }
    require(new Set([statusColors.connected,statusColors.starting,statusColors.error,statusColors.stopped]).size===4&&statusColors.starting===statusColors.degraded,'Live status colors are not distinct or degraded is not amber');
    state.servers[0]=original;renderServers();
    state.tunnels=[{id:'color-demo',server_id:'sample_firewall',kind:'socks',name:'Synthetic color forward',local_port:24001,pool_size:1,status:'stopped'}];
    goView('tunnels');
    require($('session-status-forwards-sample_firewall').title===$('session-status-sessions-sample_firewall').title,'Forwarding group status meaning differs');
    require(document.documentElement.scrollWidth<=innerWidth+1,'Forwarding header overflows');
    state.servers=saved;state.tunnels=savedTunnels;goView('servers');
    return {width:innerWidth,mode:document.documentElement.dataset.appearance,longText,pairs,maxDelta,firewallAndTools:true,geometryOnly:true};
  }
  const indicator=document.querySelector('.firewall-indicator');
  require(indicator.textContent==='Firewall in use'&&indicator.title.includes('4 dependent sessions')&&indicator.classList.contains('in-use'),'Firewall text/state lost');
  indicator.click();
  const panel=$('firewallDetails'),p=panel.getBoundingClientRect();
  require(!panel.hidden&&document.activeElement===panel,'Firewall details focus missing');
  require(getComputedStyle(panel).outlineStyle==='none','Native focus ring surrounds Firewall region');
  require(p.left>=0&&p.right<=innerWidth+1&&p.top>=0&&p.bottom<=innerHeight+1,'Firewall details outside viewport');
  require(panel.textContent.includes('4 dependent sessions')&&panel.textContent.includes('Firewall in use')&&panel.textContent.includes('keep running'),'Firewall meaning lost');
  const items=firewallDependents(state.servers[0]);
  require(items.length===4&&new Set(items.map(item=>item.server.id)).size===4,'Dependent sessions duplicated or omitted');
  require(items.filter(item=>item.active).length===3&&items.find(item=>item.server.id==='sample_stopped').active===false,'Stopped session marked active');
  require(items.find(item=>item.server.id==='sample_second').label==='Firewall in use'&&items.find(item=>item.server.id==='sample_third').label==='Connecting','Relay/transitive state lost');
  require($('firewallDependents').textContent.includes('Synthetic transitive worker')&&$('firewallDependents').textContent.includes('Saved · disconnected · 1'),'Live list missing names or inactive group');
  require(JSON.stringify(before)===JSON.stringify(geometry()),'Opening Firewall details moves cards');
  renderServers();
  require(!panel.hidden&&document.activeElement===panel&&$('firewall-info-sample_firewall').getAttribute('aria-expanded')==='true','Refresh disrupts open Firewall details');
  const live=state.servers.map(s=>({...s}));
  state.servers=state.servers.filter(s=>s.id!=='sample_stopped');state.servers[0].dependent_session_count=3;
  renderServers();
  require(!$('firewallDependents').textContent.includes('Saved · disconnected')&&firewallDependents(state.servers[0]).length===3,'Active-only list has phantom inactive entries');
  delete state.servers.find(s=>s.id==='sample_third').firewall_path;
  require(firewallDependents(state.servers[0]).some(item=>item.server.id==='sample_third'),'Transitive jump graph fallback failed');
  const worker=state.servers.find(s=>s.id==='sample_third');worker.connection_status='error';renderServers();
  require($('firewallDependents').textContent.includes('Connection error'),'Requested failing session marked connected');
  state.servers=live.map(s=>({...s}));
  for(const server of state.servers)Object.assign(server,{desired_running:false,active_forward_count:0,active_ssh_count:0,firewall_in_use:false,connection_status:'disconnected'});
  state.servers[0].dependent_forward_count=0;
  renderServers();
  require(panel.textContent.includes('No other active SSH connections')&&$('firewallDependents').textContent.includes('Saved · disconnected · 4'),'Open Firewall list is stale after refresh');
  require($('firewall-info-sample_firewall').textContent==='Firewall in use'&&!$('firewall-info-sample_firewall').classList.contains('in-use'),'Role caption or idle live-state marker is incorrect');
  state.servers=live;renderServers();
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
  require(panel.hidden&&document.activeElement.id==='firewall-info-sample_firewall','Firewall Escape/focus failed');
  renderServers();
  require(document.activeElement.id==='firewall-info-sample_firewall','Refresh loses focused Firewall button');
  for(const view of ['dashboard','tunnels','servers','logs']){
    goView(view);$('toolsToggle').click();
    const menu=$('toolsMenu'),box=menu.getBoundingClientRect();
    require(!menu.hidden&&document.activeElement===$('importConfig'),'Tools unavailable/focus missing');
    const focus=getComputedStyle($('importConfig'));
    if($('importConfig').matches(':focus-visible'))require(focus.outlineWidth==='2px'&&focus.outlineOffset==='-3px','Tools keyboard focus is not the compact inset outline');
    require(box.left>=0&&box.right<=innerWidth+1&&box.top>=0&&box.bottom<=innerHeight+1,'Tools outside viewport');
    require(document.elementFromPoint(box.left+20,box.top+20)?.closest('#toolsMenu')===menu,'Tools obscured');
    document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
    require(menu.hidden&&document.activeElement===$('toolsToggle'),'Tools Escape/focus failed');
    $('toolsToggle').click();$('pageTitle').click();require(menu.hidden,'Tools outside click failed');
    $('toolsToggle').click();$('refreshButton').focus();require(menu.hidden,'Tools focus exit failed');
  }
  state.service.import_undo_available=true;renderRelease();require(!$('undoImport').hidden,'Available Undo missing');
  state.service.import_undo_available=false;renderRelease();require($('undoImport').hidden,'Unavailable Undo shown');
  require(!document.querySelector('#view-servers #importConfig,#view-servers #exportConfig,#view-servers #undoImport'),'Configuration actions remain in Sessions toolbar');
  require(document.querySelectorAll('#view-servers [data-bulk-action]').length===3,'Session bulk actions moved');
  goView('servers');document.querySelector('.firewall-indicator').click();state.servers=[];renderServers();
  require(panel.hidden&&document.activeElement===document.querySelector('[data-view="servers"]'),'Removed Firewall leaves stale details or hidden focus');
  state.servers=saved;closePopover();goView('servers');
  return {width:innerWidth,mode:document.documentElement.dataset.appearance,longText,pairs,maxDelta,firewallAndTools:true};
}
