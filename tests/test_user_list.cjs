const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../static/keep-user-list.js'), 'utf8');

function fixture(initial = []) {
  let document, blurCount = 0, parserCount = 0, timerId = 0;
  const calls = [], events = [], navigation = [], timers = new Map(), pages = new Map();
  class Node {
    constructor(tag, classes = []) {
      this.tagName = tag.toUpperCase(); this.classes = new Set(classes); this.children = [];
      this.parentElement = null; this.dataset = {}; this.hidden = false; this.value = '';
      this.textContent = ''; this.owner = null;
    }
    set innerHTML(_) { throw new Error('User HTML must never be rebuilt'); }
    get childNodes() { return this.children; }
    get firstChild() { return this.children[0] || null; }
    get nextSibling() { return this.parentElement?.children[this.parentElement.children.indexOf(this) + 1] || null; }
    get isConnected() { return this === document.body || Boolean(this.parentElement?.isConnected); }
    matches(selector) {
      if (selector.startsWith('.')) return this.classes.has(selector.slice(1));
      if (selector === 'form[data-save-key]') return this.tagName === 'FORM' && this.dataset.saveKey !== undefined;
      return this.tagName.toLowerCase() === selector;
    }
    querySelectorAll(selector) {
      return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    contains(node) { return this === node || this.children.some(child => child.contains(node)); }
    closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
    insertBefore(child, reference) {
      if (child === reference) return child;
      if (child.parentElement) child.remove();
      const position = reference === null ? this.children.length : this.children.indexOf(reference);
      assert.notEqual(position, -1);
      this.children.splice(position, 0, child); child.parentElement = this;
      return child;
    }
    append(...children) { for (const child of children) this.insertBefore(child, null); }
    remove() {
      if (!this.parentElement) return;
      if (this.isConnected && this.contains(document.activeElement)) { blurCount++; document.activeElement = document.body; }
      this.parentElement.children.splice(this.parentElement.children.indexOf(this), 1); this.parentElement = null;
    }
    cloneNode(deep) {
      const copy = new Node(this.tagName, [...this.classes]);
      Object.assign(copy, {dataset:{...this.dataset}, hidden:this.hidden, value:this.value, textContent:this.textContent});
      if (deep) copy.append(...this.children.map(child => child.cloneNode(true)));
      return copy;
    }
  }
  function card(key, {open = false, name = key} = {}) {
    const result = new Node('article', ['user-card']); result.name = name;
    const heading = new Node('button'); heading.textContent = name;
    const editor = new Node('div', ['user-editor']); editor.hidden = !open;
    const form = new Node('form'); form.dataset.saveKey = key;
    const input = new Node('input'); input.value = name; input.selectionStart = 2; input.selectionEnd = 4;
    form.append(input); editor.append(form); result.append(heading, editor);
    result.editor = editor; result.form = form; result.input = input;
    return result;
  }
  function list(items, {empty = false} = {}) {
    const result = new Node('section', ['admin-card-list']);
    result.append(...items);
    if (empty) result.append(new Node('div', ['empty']));
    return result;
  }
  const live = list(initial.map(item => typeof item === 'string' ? card(item) : item));
  const body = new Node('body'), search = new Node('input'); search.value = 'viewer'; body.append(search, live);
  const documentListeners = new Map(), windowListeners = new Map();
  document = {body, activeElement:search,
    querySelectorAll: selector => body.querySelectorAll(selector),
    importNode: (node, deep) => node.cloneNode(deep),
    dispatchEvent(event) { events.push(event.type); for (const listener of documentListeners.get(event.type) || []) listener(event); },
    addEventListener(type, listener) { documentListeners.set(type, [...(documentListeners.get(type) || []), listener]); }
  };
  const location = {origin:'https://keep.example', pathname:'/settings/users',
    reload() { navigation.push('reload'); }, assign(url) { navigation.push(url); }};
  Object.defineProperty(location, 'href', {get:() => 'https://keep.example/settings/users', set:url => navigation.push(url)});
  const window = {location, scrollX:0, scrollY:340,
    scrollTo(position) { this.scrollX = position.left; this.scrollY = position.top; },
    addEventListener(type, listener) { windowListeners.set(type, [...(windowListeners.get(type) || []), listener]); }
  };
  const fetch = (url, options) => new Promise((resolve, reject) => calls.push({url, options, resolve, reject}));
  class DOMParser {
    parseFromString(text, type) {
      parserCount++; assert.equal(type, 'text/html');
      const page = pages.get(text); if (!page) throw new Error('Invalid HTML'); return page;
    }
  }
  class CustomEvent { constructor(type) { this.type = type; } }
  vm.runInNewContext(source, {window, document, fetch, AbortController, URL, DOMParser, CustomEvent,
    setTimeout(fn, delay) { const id = ++timerId; timers.set(id, {fn, delay}); return id; },
    clearTimeout(id) { timers.delete(id); }});
  return {window, document, live, search, card, list, calls, events, timers, navigation,
    cards:() => [...live.querySelectorAll('.user-card')],
    keys:() => [...live.querySelectorAll('.user-card')].map(node => node.querySelector('form[data-save-key]').dataset.saveKey),
    blurCount:() => blurCount, parserCount:() => parserCount,
    page(nodes, options) {
      const root = new Node('body'); root.append(list(nodes, options));
      return {querySelectorAll:selector => root.querySelectorAll(selector)};
    },
    respond(index, page, extra = {}) {
      const token = `server page ${index}`; pages.set(token, page);
      calls[index].resolve({status:200, ok:true, redirected:false, type:'basic',
        url:'https://keep.example/settings/users', headers:{get:() => 'text/html; charset=utf-8'},
        text:async() => token, ...extra});
    },
    fire(type) { for (const listener of windowListeners.get(type) || []) listener(); },
    timeout() { for (const [id, timer] of [...timers]) { timers.delete(id); assert.equal(timer.delay, 15000); timer.fn(); } }
  };
}

async function settle() { for (let i = 0; i < 10; i++) await Promise.resolve(); }

test('refresh uses one same-origin HTML GET and merges fresh closed cards in server order', async () => {
  const f = fixture(['user-7', 'user-8', 'user-9']);
  const previous = f.cards();
  assert.equal(f.calls.length, 0);
  const pending = f.window.KeepUsers.refresh();
  const {url, options} = f.calls[0];
  assert.equal(url, '/settings/users'); assert.equal(options.method, 'GET');
  assert.equal(options.credentials, 'same-origin'); assert.equal(options.mode, 'same-origin');
  assert.equal(options.cache, 'no-store'); assert.equal(options.redirect, 'error'); assert.equal(options.headers.Accept, 'text/html');
  f.respond(0, f.page([f.card('user-10'), f.card('user-8', {name:'Updated name'}), f.card('user-7')]));
  assert.equal(await pending, true);
  assert.deepEqual(f.keys(), ['user-10', 'user-8', 'user-7']);
  assert.equal(f.cards()[0].hidden, false); assert.equal(f.cards()[1].querySelector('button').textContent, 'Updated name');
  assert.equal(previous.every(node => !node.isConnected), true);
  assert.equal(f.search.value, 'viewer'); assert.equal(f.document.activeElement, f.search); assert.equal(f.window.scrollY, 340);
  assert.deepEqual(f.events, ['keep-users-updated']); assert.deepEqual(f.navigation, []); assert.equal(f.timers.size, 0);
});

test('all open editors survive reordered results without blur, overwritten inputs or selection loss', async () => {
  const f = fixture();
  const first = f.card('user-7', {open:true}), second = f.card('user-8', {open:true});
  f.live.append(first, second, f.card('user-9'));
  first.input.value = 'Unsaved name'; second.input.value = 'Other unsaved name'; f.document.activeElement = first.input;
  const pending = f.window.KeepUsers.refresh();
  f.respond(0, f.page([f.card('user-8'), f.card('user-10'), f.card('user-7'), f.card('user-9')]));
  assert.equal(await pending, true);
  assert.deepEqual(f.keys(), ['user-8', 'user-10', 'user-7', 'user-9']);
  assert.equal(f.cards()[0], second); assert.equal(f.cards()[2], first);
  assert.equal(first.input.value, 'Unsaved name'); assert.equal(second.input.value, 'Other unsaved name');
  assert.equal(f.document.activeElement, first.input); assert.equal(f.blurCount(), 0);
  assert.equal(first.input.selectionStart, 2); assert.equal(first.input.selectionEnd, 4);
  assert.equal(first.editor.hidden, false); assert.equal(second.editor.hidden, false);
});

test('an open card omitted by the server stays editable, including when it contains focus', async () => {
  const f = fixture(), open = f.card('user-local:abc', {open:true});
  f.live.append(open, f.card('user-7')); f.document.activeElement = open.input; open.input.value = 'Still editing';
  const pending = f.window.KeepUsers.refresh(); f.respond(0, f.page([f.card('user-8')]));
  assert.equal(await pending, true); assert.deepEqual(f.keys(), ['user-8', 'user-local:abc']);
  assert.equal(f.cards()[1], open); assert.equal(open.input.value, 'Still editing');
  assert.equal(f.document.activeElement, open.input); assert.equal(f.blurCount(), 0);
});

test('the commit uses current editing state and scroll after a user acts during the request', async () => {
  const f = fixture(['user-7']), old = f.cards()[0];
  const pending = f.window.KeepUsers.refresh();
  old.editor = old.querySelector('.user-editor'); old.input = old.querySelector('input');
  old.editor.hidden = false; old.input.value = 'Typed during fetch'; f.document.activeElement = old.input;
  f.search.value = 'new search'; f.window.scrollY = 910;
  f.respond(0, f.page([f.card('user-7'), f.card('user-8')]));
  assert.equal(await pending, true); assert.equal(f.cards()[0], old);
  assert.equal(old.input.value, 'Typed during fetch'); assert.equal(f.search.value, 'new search');
  assert.equal(f.window.scrollY, 910); assert.equal(f.document.activeElement, old.input); assert.equal(f.blurCount(), 0);
});

test('focused form elements are preserved even if their editor is already closed', async () => {
  const f = fixture(), card = f.card('user-7'); f.live.append(card); f.document.activeElement = card.input;
  const pending = f.window.KeepUsers.refresh(); f.respond(0, f.page([f.card('user-7')]));
  assert.equal(await pending, true); assert.equal(f.cards()[0], card);
  assert.equal(f.document.activeElement, card.input); assert.equal(f.blurCount(), 0);
});

test('authentication, redirects, foreign URLs and non-HTML responses fail without changing cards', async () => {
  for (const extra of [{status:401,ok:false}, {status:403,ok:false}, {status:500,ok:false}, {status:202},
    {redirected:true}, {type:'opaqueredirect'}, {url:'https://keep.example/login'},
    {url:'https://other.example/settings/users'}, {headers:{get:() => 'application/json'}}]) {
    const f = fixture(['user-7']), old = f.cards()[0];
    const pending = f.window.KeepUsers.refresh(); f.respond(0, f.page([f.card('user-8')]), extra);
    assert.equal(await pending, false); assert.equal(f.cards()[0], old);
    assert.deepEqual(f.events, []); assert.deepEqual(f.navigation, []);
  }
});

test('missing lists, duplicate or invalid keys and embedded scripts reject the whole response', async () => {
  for (const kind of ['missing', 'multiple', 'duplicate', 'invalid', 'missing-form', 'script', 'empty-invalid']) {
    const f = fixture(['user-7']), old = f.cards()[0];
    let page;
    if (kind === 'missing') page = {querySelectorAll:() => []};
    else if (kind === 'multiple') page = {querySelectorAll:() => [f.list([]), f.list([])]};
    else if (kind === 'duplicate') page = f.page([f.card('user-8'), f.card('user-8')]);
    else if (kind === 'invalid') page = f.page([f.card('not-a-user')]);
    else if (kind === 'empty-invalid') page = f.page([]);
    else {
      const card = f.card('user-8');
      if (kind === 'missing-form') card.querySelector('form[data-save-key]').remove();
      else { const script = f.card('user-9').querySelector('button'); script.tagName = 'SCRIPT'; card.append(script); }
      page = f.page([card]);
    }
    const pending = f.window.KeepUsers.refresh(); f.respond(0, page);
    assert.equal(await pending, false, kind); assert.equal(f.cards()[0], old, kind); assert.deepEqual(f.events, []);
  }
});

test('an explicit server empty state removes stale closed cards', async () => {
  const f = fixture(['user-7']);
  const pending = f.window.KeepUsers.refresh(); f.respond(0, f.page([], {empty:true}));
  assert.equal(await pending, true); assert.deepEqual(f.keys(), []);
  assert.ok(f.live.querySelector('.empty')); assert.deepEqual(f.events, ['keep-users-updated']);
});

test('concurrent refreshes share the same result and a later refresh can run again', async () => {
  const f = fixture(['user-7']);
  const first = f.window.KeepUsers.refresh(), second = f.window.KeepUsers.refresh();
  assert.equal(first, second); assert.equal(f.calls.length, 1);
  f.respond(0, f.page([f.card('user-8')])); assert.equal(await first, true);
  const third = f.window.KeepUsers.refresh(); assert.equal(f.calls.length, 2);
  f.respond(1, f.page([f.card('user-9')])); assert.equal(await third, true); assert.deepEqual(f.keys(), ['user-9']);
});

test('network failure is retryable and cannot mutate existing forms', async () => {
  const f = fixture(['user-7']), old = f.cards()[0];
  const pending = f.window.KeepUsers.refresh(); f.calls[0].reject(new Error('Offline'));
  assert.equal(await pending, false); assert.equal(f.cards()[0], old);
  const next = f.window.KeepUsers.refresh(); f.respond(1, f.page([f.card('user-8')]));
  assert.equal(await next, true); assert.deepEqual(f.navigation, []);
});

test('the fifteen-second timeout aborts and ignores late fetch responses', async () => {
  const f = fixture(['user-7']), old = f.cards()[0];
  const pending = f.window.KeepUsers.refresh(); f.timeout();
  assert.equal(await pending, false); assert.equal(f.calls[0].options.signal.aborted, true);
  f.respond(0, f.page([f.card('user-8')])); await settle();
  assert.equal(f.cards()[0], old); assert.deepEqual(f.events, []); assert.equal(f.timers.size, 0);
});

test('pagehide cancels body loading and pageshow permits a fresh request without navigation', async () => {
  const f = fixture(['user-7']), old = f.cards()[0]; let resolveBody;
  const pending = f.window.KeepUsers.refresh();
  f.respond(0, f.page([f.card('user-8')]), {text:() => new Promise(resolve => { resolveBody = resolve; })});
  await settle(); f.fire('pagehide'); assert.equal(await pending, false);
  assert.equal(f.calls[0].options.signal.aborted, true); assert.equal(f.cards()[0], old);
  resolveBody('late body'); await settle(); assert.deepEqual(f.events, []);
  assert.equal(await f.window.KeepUsers.refresh(), false); assert.equal(f.calls.length, 1);
  f.fire('pageshow'); const next = f.window.KeepUsers.refresh();
  f.respond(1, f.page([f.card('user-9')])); assert.equal(await next, true);
  assert.deepEqual(f.navigation, []);
});
