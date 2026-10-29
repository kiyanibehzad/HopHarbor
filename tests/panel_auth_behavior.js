'use strict';
// Exercise the real panel script with a small DOM and synthetic service. No network,
// browser profile, installed application or private settings are accessed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');

class Element {
  constructor(id = '') {
    this.id = id;
    this.value = '';
    this.hidden = id === 'lockedScreen';
    this.disabled = false;
    this.dataset = {};
    this.style = {};
    this.textContent = '';
    this.children = [];
    this.listeners = new Map();
    const classes = new Set();
    this.classList = {
      add: name => classes.add(name),
      remove: name => classes.delete(name),
      toggle: (name, on) => on ? classes.add(name) : classes.delete(name)
    };
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute() {}
  removeAttribute() {}
  querySelectorAll() { return []; }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  async click() {
    for (const callback of this.listeners.get('click') || []) await callback({target: this});
  }
}

async function harness({bridge = true, hash = '', cookie = true, status = null} = {}) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, new Element(id));
    return elements.get(id);
  };
  const messages = [], requests = [], intervals = [], storage = new Map();
  const service = {cookie, status, token: 'synthetic-bootstrap-token', mutations: 0};
  const location = {hash, pathname: '/', search: ''};
  const document = {
    hidden: false,
    activeElement: null,
    documentElement: {dataset: {appearance: 'system'}},
    getElementById: element,
    createElement: name => new Element(name),
    querySelectorAll: () => [],
    addEventListener() {}
  };
  const window = {
    matchMedia: () => ({matches: false, addEventListener() {}}),
    addEventListener() {}
  };
  if (bridge) window.webkit = {messageHandlers: {hopharborPanel: {
    postMessage: message => messages.push(JSON.parse(JSON.stringify(message)))
  }}};
  const context = vm.createContext({
    window, document, location, URLSearchParams, AbortController,
    history: {replaceState: () => { location.hash = ''; }},
    localStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key)
    },
    setTimeout, clearTimeout,
    setInterval: callback => { intervals.push(callback); return intervals.length; },
    icon: name => new Element(name),
    fetch: async (path, options) => {
      const method = options.method || 'GET';
      const body = options.body ? JSON.parse(options.body) : null;
      requests.push({path, method, body});
      let code, data;
      if (path === '/api/session') {
        code = body?.token === service.token ? 200 : 401;
        if (code === 200) service.cookie = true;
        data = code === 200 ? {ok: true} : {error: 'Invalid panel access token.'};
      } else {
        code = service.status ?? (service.cookie ? 200 : 401);
        if (code === 200 && method !== 'GET') service.mutations++;
        data = code === 200 ? {servers: [], tunnels: [], logs: [], service: {version: 'test', build: 1}}
          : {error: code === 403 ? 'Requests from outside this panel are not allowed.'
            : 'Panel authentication is required. Reopen the app.'};
      }
      return {ok: code >= 200 && code < 300, status: code, text: async () => JSON.stringify(data)};
    }
  });
  new vm.Script(source, {filename: 'web/app.js'}).runInContext(context);
  const flush = () => new Promise(resolve => setImmediate(resolve));
  await flush();
  return {
    service, elements, messages, requests, intervals, storage, location, context,
    evaluate: code => vm.runInContext(code, context),
    flush,
    retry: async () => { await element('lockedRetry').click(); await flush(); }
  };
}

const cases = {
  async expired_cookie_requests_one_native_recovery() {
    const h = await harness();
    assert.deepEqual(h.messages, [{action: 'ready'}]);
    h.messages.length = 0;
    h.service.cookie = false;
    await h.evaluate('refresh(true)');
    assert.equal(h.elements.get('lockedScreen').hidden, false);
    assert.equal(h.evaluate('authorized'), false);
    assert.deepEqual(h.messages, [{action: 'reauthenticate', reason: 'authentication'}]);
    // Concurrent or late failures from this document must not trigger a reload loop.
    await h.evaluate("request('/api/state').catch(()=>{})");
    for (const poll of h.intervals) poll();
    await h.flush();
    assert.equal(h.messages.length, 1);
  },
  async manual_retry_requests_fresh_native_bootstrap() {
    const h = await harness({cookie: false});
    const before = h.requests.length;
    await h.retry();
    assert.equal(h.requests.length, before);
    assert.deepEqual(h.messages, [
      {action: 'reauthenticate', reason: 'authentication'},
      {action: 'reauthenticate', reason: 'retry'}
    ]);
    assert.equal(h.elements.get('lockedScreen').hidden, false);
  },
  async csrf_rejection_never_recovers_automatically() {
    const h = await harness({status: 403});
    assert.equal(h.evaluate('authorized'), false);
    assert.equal(h.elements.get('lockedScreen').hidden, false);
    assert.deepEqual(h.messages, []);
  },
  async rejected_bootstrap_never_starts_automatic_recovery() {
    const h = await harness({hash: '#token=wrong-synthetic-token', cookie: false});
    assert.deepEqual(h.messages, []);
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].path, '/api/session');
    assert.equal(h.location.hash, '');
    assert.equal(h.evaluate('authorized'), false);
    assert.deepEqual([...h.storage.values()], []);
    await h.retry();
    assert.deepEqual(h.messages, [{action: 'reauthenticate', reason: 'retry'}]);
    assert.equal(h.requests.length, 1);
  },
  async ready_follows_authenticated_state_and_render() {
    const h = await harness({hash: '#token=synthetic-bootstrap-token', cookie: false});
    assert.deepEqual(h.requests.map(x => [x.method, x.path]), [
      ['POST', '/api/session'], ['GET', '/api/state']
    ]);
    assert.equal(h.elements.get('metricServers').textContent, '0');
    assert.deepEqual(h.messages, [{action: 'ready'}]);
    await h.evaluate('refresh(true)');
    assert.equal(h.messages.length, 1);
    assert.equal(h.location.hash, '');
    assert.deepEqual([...h.storage.values()], []);
    // A state response that cannot render must not tell the native shell it recovered.
    const broken = await harness({cookie: false});
    broken.messages.length = 0;
    broken.service.cookie = true;
    await broken.evaluate("authorized=true;render=()=>{throw new Error('synthetic render failure')};refresh(true)");
    assert.deepEqual(broken.messages, []);
  },
  async rejected_mutation_is_not_replayed() {
    const h = await harness();
    h.messages.length = 0;
    h.service.cookie = false;
    const before = h.requests.length;
    await h.evaluate("request('/api/tunnels/synthetic/start',{method:'POST',body:{}}).catch(()=>{})");
    await h.flush();
    assert.deepEqual(h.requests.slice(before).map(x => [x.method, x.path]), [
      ['POST', '/api/tunnels/synthetic/start']
    ]);
    assert.equal(h.service.mutations, 0);
    assert.deepEqual(h.messages, [{action: 'reauthenticate', reason: 'authentication'}]);
  },
  async plain_browser_keeps_cookie_retry_without_native_access() {
    const h = await harness({bridge: false, cookie: false});
    assert.deepEqual(h.messages, []);
    await h.retry();
    assert.equal(h.evaluate('authorized'), false);
    assert.equal(h.elements.get('lockedScreen').hidden, false);
    h.service.cookie = true;
    await h.retry();
    assert.equal(h.evaluate('authorized'), true);
    assert.equal(h.elements.get('lockedScreen').hidden, true);
    assert.equal(h.elements.get('metricServers').textContent, '0');
    assert.ok(h.requests.every(x => x.method === 'GET' && x.path === '/api/state'));
    assert.deepEqual(h.messages, []);
  }
};

(async () => {
  const selected = process.argv[3];
  const names = selected ? [selected] : Object.keys(cases);
  for (const name of names) {
    assert.equal(typeof cases[name], 'function', 'Unknown panel test');
    await cases[name]();
    process.stdout.write(name + ': passed\n');
  }
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1; });
