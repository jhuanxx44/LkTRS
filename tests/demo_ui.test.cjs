// Deterministic request ordering tests for the dependency-free browser client.
// Crypto and browser rendering are covered by the real workflow, not this DOM stub.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return {promise, resolve, reject};
}
function fixture(fetch) {
  class Element {
    constructor() { this.children = []; this.dataset = {}; this.style = {}; this.handlers = {}; this.classList = {toggle(){}}; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute() {}
    addEventListener(name, handler) { this.handlers[name] = handler; }
  }
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const context = vm.createContext({
    document: {getElementById:get, createElement:()=>new Element(), createTextNode:text=>({textContent:text})},
    window: {location:{}, confirm:()=>false},
    fetch, setTimeout(){}, console,
  });
  const source = fs.readFileSync(path.join(__dirname, '../src/nativeproof/cmd/lktrs-demo/web/app.js'), 'utf8');
  // Keep production initialization; its first tick consumes the first fetch.
  vm.runInContext(source, context);
  return {get, eval:code=>vm.runInContext(code, context)};
}
const idle = {steps:Array.from({length:8},()=>({title:'stage',detail:'detail'})),next:0,busy:false,run:'',reports:[],checks:[],error:'',phase:'ready',alice_used:0,bob_used:0,token:'test'};
const response = s => ({ok:true,json:async()=>s});
const flush = () => new Promise(resolve => setImmediate(resolve));

test('failed autoplay request restores manual controls even with unchanged state', async () => {
  const f = fixture(async (_url, options) => options?.method === "POST" ? {ok:false,text:async()=>'conflict'} : response(idle));
  await flush();
  f.eval('auto = true; render(state)');
  await f.eval('action("/api/advance", {step:0})');
  await f.eval('poll()');
  assert.equal(f.get('next').disabled, false);
  assert.equal(f.get('auto').textContent, '连续运行全部步骤');
  assert.match(f.get('error').textContent, /conflict/);
});

test('poll started before a mutation cannot overwrite its newer busy state', async () => {
  const stale = deferred();
  let gets = 0, posts = 0;
  const busy = {...idle,busy:true,started:Date.now(),phase:'proving'};
  const f = fixture(async (_url, options) => {
    if (options?.method === "POST") { posts++; return {ok:true}; }
    gets++;
    if (gets === 2) return stale.promise;
    return response(gets === 1 ? idle : busy);
  });
  await flush();
  const earlier = f.eval('poll()');
  f.eval('auto = true');
  await f.eval('action("/api/advance", {step:0})');
  stale.resolve(response(idle));
  await earlier;
  assert.equal(posts, 1, 'stale idle response triggered a duplicate action');
  assert.equal(f.eval('state.busy'), true);
  assert.equal(f.get('next').disabled, true);
});

test('pending mutation immediately disables another manual action', async () => {
  const pending = deferred();
  const f = fixture(async (_url, options) => options?.method === "POST" ? pending.promise : response(idle));
  await flush();
  const action = f.eval('action("/api/advance", {step:0})');
  assert.equal(f.get('next').disabled, true);
  pending.resolve({ok:true});
  await action;
});

test('reset cancellation preserves the current session without posting', async () => {
  let posts = 0;
  const f = fixture(async (_url, options) => {
    if (options?.method === 'POST') { posts++; return {ok:true}; }
    return response({...idle,run:'existing-run',next:1});
  });
  await flush();
  f.get('reset').handlers.click();
  await flush();
  assert.equal(posts, 0);
  assert.equal(f.eval('state.run'), 'existing-run');
});

test('connection recovery restores controls for an unchanged snapshot', async () => {
  let disconnected = false;
  const f = fixture(async () => {
    if (disconnected) throw new Error('offline');
    return response(idle);
  });
  await flush();
  disconnected = true;
  await f.eval('poll()');
  assert.equal(f.get('next').disabled, true);
  disconnected = false;
  await f.eval('poll()');
  assert.equal(f.get('next').disabled, false);
  assert.equal(f.get('error').hidden, true);
});
