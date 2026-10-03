// Run with: node --test tests/test_interactions.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../static/keep-interactions.js'), 'utf8');
function element() {
  const classes = new Set();
  const attrs = new Map();
  return {
    dataset: {}, textContent: 'Save', disabled: false, isConnected: true,
    classList: { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x), toggle: (x, on) => on ? classes.add(x) : classes.delete(x) },
    getAttribute: k => attrs.get(k), setAttribute: (k, v) => attrs.set(k, v), removeAttribute: k => attrs.delete(k),
    getClientRects: () => [{}], getBoundingClientRect: () => ({ left: 0, top: 0 }),
    remove() { this.isConnected = false; }, focus() { this.focused = true; }
  };
}
function fixture({ reduced = true, success = false, error = false, saved = null, form = false, topButton = null, accountMenu = null, editor = null } = {}) {
  const button = element();
  const listeners = {};
  const windowListeners = {};
  const documentListeners = {};
  const rootClasses = new Set();
  const formElement = { closest: () => editor, dataset: { saveKey: 'user-7' }, querySelector: () => button, addEventListener: (n, f) => listeners[n] = f };
  let stored = saved && JSON.stringify(saved);
  const cards = [];
  const document = {
    body: {}, activeElement: {},
    documentElement: { classList: { add: x => rootClasses.add(x), remove: x => rootClasses.delete(x), contains: x => rootClasses.has(x) } },
    addEventListener: (n, f) => documentListeners[n] = f,
    querySelectorAll: selector => selector === '[data-user-toggle]' ? (editor ? [editor.querySelector(selector)] : []) : selector.startsWith('form') ? (form ? [formElement] : []) : cards.filter(c => c.isConnected),
    querySelector: selector => selector.startsWith('#settings') ? (success ? {} : null) : (error ? {} : null),
    getElementById: id => id === 'back-to-top' ? topButton : id === 'account-menu' ? accountMenu : null
  };
  const window = {
    innerHeight: 800, matchMedia: () => ({ matches: reduced }),
    addEventListener: (n, f) => windowListeners[n] = f,
    scrollTo() {}
  };
  const context = {
    window, document, location: { pathname: '/settings/users' }, scrollY: 120,
    sessionStorage: { getItem: () => stored, setItem: (_, v) => stored = v, removeItem: () => stored = null },
    requestAnimationFrame: f => f(),
    setTimeout: (f, ms) => { if (ms < 1000) f(); return 1; }
  };
  vm.runInNewContext(source, context);
  return { context, window, document, cards, button, listeners, windowListeners, documentListeners, rootClasses, stored: () => stored };
}
test('pointer focus rings stay quiet until keyboard navigation resumes', () => {
  const f = fixture();
  f.documentListeners.pointerdown();
  assert.equal(f.rootClasses.has('pointer-input'), true);
  f.documentListeners.keydown({ metaKey: false, ctrlKey: false, altKey: false });
  assert.equal(f.rootClasses.has('pointer-input'), false);
});
test('reduced motion removes the confirmed card without animation and restores keyboard focus', async () => {
  const f = fixture();
  const card = element(), next = element(), nextButton = element();
  f.cards.push(card, next);
  f.document.activeElement = f.document.body;
  next.querySelector = () => nextButton;
  card.animate = next.animate = () => { throw Error('Motion must be skipped'); };
  let updates = 0;
  await f.window.KeepUI.finishMediaAction(card, f.button, () => updates++, 'Kept ✓', true);
  assert.equal(card.isConnected, false);
  assert.equal(updates, 1);
  assert.equal(f.button.textContent, 'Kept ✓');
  assert.equal(nextButton.focused, true);
});
test('normal motion waits for exit, removes once, then animates neighboring cards', async () => {
  const f = fixture({ reduced: false });
  const card = element(), next = element();
  f.cards.push(card, next);
  let exitDone;
  card.animate = () => ({ finished: new Promise(resolve => exitDone = resolve) });
  let transitions = 0;
  next.animate = () => { transitions++; return { cancel() {} }; };
  let position = 100;
  next.getBoundingClientRect = () => ({ left: 0, top: position });
  const result = f.window.KeepUI.finishMediaAction(card, f.button, () => position = 0, 'Removed ✓');
  await Promise.resolve();
  assert.equal(card.isConnected, true);
  exitDone();
  await result;
  assert.equal(card.isConnected, false);
  assert.equal(transitions, 1);
});
test('client-side validation cancellation leaves the save button enabled', () => {
  const f = fixture({ form: true });
  f.listeners.submit({ defaultPrevented: true });
  assert.equal(f.button.disabled, false);
  assert.equal(f.button.textContent, 'Save');
  assert.equal(f.stored(), null);
});
test('native submission records no fields, prevents duplicates, and recovers on back navigation', () => {
  const f = fixture({ form: true });
  f.listeners.submit({ defaultPrevented: false });
  assert.equal(f.button.textContent, 'Saving…');
  assert.equal(f.button.disabled, true);
  assert.deepEqual(Object.keys(JSON.parse(f.stored())).sort(), ['at', 'key', 'path', 'scroll']);
  let prevented = false;
  f.listeners.submit({ defaultPrevented: false, preventDefault: () => prevented = true });
  assert.equal(prevented, true);
  f.windowListeners.pageshow({ persisted: true });
  assert.equal(f.button.textContent, 'Save');
  assert.equal(f.button.disabled, false);
});
test('Saved feedback requires a fresh matching submission and server success without errors', () => {
  const saved = { key: 'user-7', path: '/settings/users', at: Date.now(), scroll: 120 };
  assert.equal(fixture({ form: true, saved, success: true }).button.textContent, 'Saved ✓');
  assert.equal(fixture({ form: true, saved }).button.textContent, 'Save');
  assert.equal(fixture({ form: true, saved, success: true, error: true }).button.textContent, 'Save');
  assert.equal(fixture({ form: true, saved: { ...saved, at: Date.now() - 60000 }, success: true }).button.textContent, 'Save');
});
function posterFixture() {
  const poster = element();
  const events = {};
  poster.parentElement = element();
  poster.addEventListener = (name, fn) => events[name] = fn;
  poster.removeEventListener = name => delete events[name];
  let fades = 0;
  poster.animate = () => fades++;
  return { poster, events, fades: () => fades };
}
test('cached artwork appears immediately without a fade', () => {
  const f = fixture({ reduced: false }), p = posterFixture();
  Object.assign(p.poster, { complete: true, naturalWidth: 300 });
  f.window.KeepUI.preparePoster(p.poster);
  assert.equal(p.fades(), 0);
  assert.equal(p.poster.parentElement.classList.contains('poster-loading'), false);
  assert.equal(Object.keys(p.events).length, 0);
});
test('delayed artwork fades once and removes its loading state', () => {
  const f = fixture({ reduced: false }), p = posterFixture();
  f.window.KeepUI.preparePoster(p.poster);
  assert.equal(p.poster.parentElement.classList.contains('poster-loading'), true);
  p.poster.naturalWidth = 300;
  const loaded = p.events.load;
  loaded(); loaded();
  assert.equal(p.fades(), 1);
  assert.equal(p.poster.parentElement.classList.contains('poster-loading'), false);
});
test('broken artwork reveals a stable fallback and reduced motion skips fades', () => {
  for (const broken of [true, false]) {
    const f = fixture(), p = posterFixture();
    f.window.KeepUI.preparePoster(p.poster);
    p.poster.naturalWidth = broken ? 0 : 300;
    p.events[broken ? 'error' : 'load']();
    assert.equal(p.fades(), 0);
    assert.equal(p.poster.parentElement.classList.contains('poster-unavailable'), broken);
    assert.equal(!!p.poster.hidden, broken);
  }
});

test('back-to-top uses separate reveal/hide thresholds and restores focus with the requested motion', () => {
  for (const reduced of [true, false]) {
    const button = element(), events = {}, main = element();
    button.addEventListener = (name, fn) => events[name] = fn;
    const f = fixture({ reduced, topButton: button });
    assert.equal(button.disabled, true);
    f.context.scrollY = 900;
    f.windowListeners.scroll();
    assert.equal(button.disabled, false);
    assert.equal(button.classList.contains('visible'), true);
    f.context.scrollY = 500;
    f.windowListeners.scroll();
    assert.equal(button.disabled, false);
    let scroll;
    f.window.scrollTo = options => scroll = options;
    f.document.getElementById = () => main;
    events.click();
    assert.equal(main.focused, true);
    assert.equal(scroll.top, 0);
    assert.equal(scroll.behavior, reduced ? 'instant' : 'smooth');
    f.context.scrollY = 100;
    f.windowListeners.scroll();
    assert.equal(button.disabled, true);
    assert.equal(button.classList.contains('visible'), false);
  }
});

test('saved account editor reopens so feedback remains visible', () => {
  const editor = element(), panel = {hidden:true}, toggle=element(), label={};
  toggle.setAttribute('aria-label','Edit Alex');
  toggle.querySelector=()=>label;
  const events={};toggle.addEventListener=(n,f)=>events[n]=f;
  toggle.closest=()=>editor;
  editor.querySelector=s=>s==='[data-user-toggle]'?toggle:panel;
  fixture({ form: true, success: true, editor, saved: { key: 'user-7', path: '/settings/users', at: Date.now(), scroll: 100 } });
  assert.equal(panel.hidden, false);
  assert.equal(toggle.getAttribute('aria-expanded'),'true');
  assert.equal(label.textContent,'Close');
  events.click();assert.equal(panel.hidden,true);assert.equal(label.textContent,'Edit');
  events.click();assert.equal(panel.hidden,false);assert.equal(toggle.getAttribute('aria-label'),'Close settings for Alex');
});
test('account navigation toggles explicitly and preserves link clicks and dialog focus', () => {
  const handlers = {};
  const toggle = element();
  toggle.addEventListener = (name, handler) => handlers[name] = handler;
  const links = { hidden: true };
  const child = { closest: () => null };
  const accountMenu = { querySelector: selector => selector === '.account-toggle' ? toggle : links, contains: target => target === child || target === toggle };
  const f = fixture({ accountMenu });
  handlers.click();
  assert.equal(links.hidden, false);
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  f.document.activeElement = f.document.body;
  f.documentListeners.click({ target: child });
  assert.equal(links.hidden, false, 'Clicking a link must leave it available for native activation');
  f.documentListeners.focusin({ target: child });
  assert.equal(links.hidden, false);
  f.documentListeners.keydown({ key: 'Escape', target: { closest: () => ({}) } });
  assert.equal(links.hidden, false);
  f.documentListeners.keydown({ key: 'Escape', target: child });
  assert.equal(links.hidden, true);
  assert.equal(toggle.focused, true);
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  handlers.click();
  f.documentListeners.focusin({ target: { closest: () => ({}) } });
  assert.equal(links.hidden, false);
  f.documentListeners.focusin({ target: { closest: () => null } });
  assert.equal(links.hidden, true);
  handlers.click();
  f.documentListeners.click({ target: { closest: () => null } });
  assert.equal(links.hidden, true);
  handlers.click(); handlers.click();
  assert.equal(links.hidden, true);
});
