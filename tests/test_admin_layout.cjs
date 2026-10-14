const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(localUser, response, options = {}) {
  const element = () => ({listeners: {}, children: [], addEventListener(name, fn) { this.listeners[name] = fn; },
    setAttribute() {}, focus() { this.focused = true; },
    append(...children) {
      for (const child of children) {
        if (child.parentElement) child.parentElement.children = child.parentElement.children.filter(item => item !== child);
        child.parentElement = this;
        this.children.push(child);
      }
    }, hidden: false});
  const submit = Object.assign(element(), {disabled: false, textContent: 'Add and invite'});
  const form = Object.assign(element(), {action: localUser ? '/settings/users/local' : '/settings/recipients',
    getAttribute: name => name === 'action' ? localUser ? '/settings/users/local' : '/settings/recipients' : null,
    classList: {contains: name => localUser && name === 'add-user-form'},
    elements: [{value: 'test-csrf'}, {value: 'person@example.com'}],
    querySelector: () => submit});
  const content = Object.assign(element(), {prepend(error) { this.error = error; }});
  const creation = {querySelector: selector => selector === 'summary span' ? {textContent: 'Add local user'} : content,
    remove() { this.removed = true; }};
  const open = Object.assign(element(), {disabled: true});
  const dialog = Object.assign(element(), {querySelector: () => form, open: false,
    showModal() { this.open = true; }, close() { this.open = false; this.listeners.close?.(); }});
  const toastClasses = new Set();
  const toast = Object.assign(element(), {classList: {add: name => toastClasses.add(name),
    remove: name => toastClasses.delete(name), contains: name => toastClasses.has(name)}});
  const body = Object.assign(element(), {classList: {contains: name => name === 'admin-ui' || name === 'notifications-ui' && options.notificationsPage}});
  body.append(toast);
  const document = {body, getElementById: id => id === 'toast' ? toast : null,
    querySelector: selector => ({'.creation-panel': creation, '.admin-list-search': {}, '.admin-add-button': open}[selector] || null),
    querySelectorAll: () => [], createElement: tag => tag === 'dialog' ? dialog : element()};
  const calls = [], navigations = [], toasts = [];
  const window = options.noToast ? {} : {showToast: (message, tone) => {toasts.push([message, tone]);toast.classList.add('visible');}};
  vm.runInNewContext(fs.readFileSync('static/keep-admin-layout.js', 'utf8'), {
    document, window, URL, FormData: class { constructor(target) { this.form = target; } },
    DOMParser: class { parseFromString() { return {querySelector: () => null}; } },
    location: {pathname: options.notificationsPage ? '/settings/notifications' : '/settings/users', assign: url => navigations.push(url)},
    fetch: async (...args) => { calls.push(args); return response; },
  });
  return {form, submit, content, open, dialog, body, toast, calls, navigations, toasts, setResponse(next) { response = next; }};
}

test('local user submission preserves the native POST for setup pages and email redirects', async () => {
  const f = fixture(true);
  assert.equal(f.open.disabled, false);
  f.open.listeners.click();
  assert.equal(f.dialog.open, true);
  let prevented = false;
  await f.form.listeners.submit({preventDefault() { prevented = true; }});
  assert.equal(prevented, false);
  assert.equal(f.calls.length, 0);
  assert.equal(f.submit.disabled, false);
  assert.equal(f.form.elements[0].value, 'test-csrf');
});

test('recipient creation still submits with CSRF form data and follows a successful settings redirect', async () => {
  const url = 'https://keep.example.com/settings/users?notice=recipient';
  const f = fixture(false, {ok: true, url, text: async () => '<html></html>'});
  let prevented = false;
  await f.form.listeners.submit({preventDefault() { prevented = true; }});
  assert.equal(prevented, true);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], '/settings/recipients');
  assert.equal(f.calls[0][1].body.form, f.form);
  assert.equal(f.calls[0][1].credentials, 'same-origin');
  assert.deepEqual(f.navigations, [url]);
});

test('recipient creation retains its error and retry behavior', async () => {
  const f = fixture(false, {ok: false, url: 'https://keep.example.com/settings/recipients', text: async () => 'Rejected'});
  await f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.content.error.hidden, false);
  assert.match(f.content.error.textContent, /Could not confirm/);
  assert.equal(f.submit.disabled, false);
  assert.equal(f.submit.textContent, 'Add and invite');
  assert.equal(f.navigations.length, 0);
  assert.deepEqual(f.toasts, []);
});

test('notification recipient creation errors show a red toast and retain dialog guidance for retry', async () => {
  const f = fixture(false, {ok: false, url: 'https://keep.example.com/settings/recipients', text: async () => 'Rejected'}, {notificationsPage: true});
  f.open.listeners.click();
  await f.form.listeners.submit({preventDefault() {}});
  assert.deepEqual(f.toasts, [['Could not confirm the request. Please try again.', 'error']]);
  assert.equal(f.toast.parentElement, f.dialog);
  assert.equal(f.dialog.children.includes(f.toast), true);
  assert.equal(f.body.children.includes(f.toast), false);
  assert.equal(f.toast.classList.contains('visible'), true);
  assert.equal(f.content.error.hidden, false);
  assert.equal(f.submit.disabled, false);
  assert.equal(f.submit.textContent, 'Add and invite');
  assert.equal(f.form.elements[0].value, 'test-csrf');
  const url = 'https://keep.example.com/settings/notifications';
  f.setResponse({ok: true, url, text: async () => '<html></html>'});
  await f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.calls.length, 2);
  assert.deepEqual(f.navigations, [url]);
  assert.equal(f.content.error.hidden, true);
  assert.equal(f.toasts.length, 1);
});

test('closing the recipient dialog hides its toast and restores it to the page', async () => {
  const f = fixture(false, {ok: false, url: 'https://keep.example.com/settings/recipients', text: async () => 'Rejected'}, {notificationsPage: true});
  f.open.listeners.click();
  await f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.toast.parentElement, f.dialog);
  f.dialog.close();
  assert.equal(f.toast.parentElement, f.body);
  assert.equal(f.dialog.children.includes(f.toast), false);
  assert.equal(f.body.children.filter(child => child === f.toast).length, 1);
  assert.equal(f.toast.classList.contains('visible'), false);
  assert.equal(f.open.focused, true);
});

test('a failed Add response after the dialog closes leaves the red toast on the page', async () => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  const f = fixture(false, pending, {notificationsPage: true});
  f.open.listeners.click();
  const submission = f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.calls.length, 1);
  assert.equal(f.submit.disabled, true);
  f.dialog.close();
  assert.equal(f.dialog.open, false);
  finish({ok: false, url: 'https://keep.example.com/settings/recipients', text: async () => 'Rejected'});
  await submission;
  assert.deepEqual(f.toasts, [['Could not confirm the request. Please try again.', 'error']]);
  assert.equal(f.toast.parentElement, f.body);
  assert.equal(f.dialog.children.includes(f.toast), false);
  assert.equal(f.body.children.filter(child => child === f.toast).length, 1);
  assert.equal(f.toast.classList.contains('visible'), true);
  assert.equal(f.content.error.hidden, false);
  assert.equal(f.submit.disabled, false);
});

test('notification recipient errors retain inline retry guidance without a toast helper', async () => {
  const f = fixture(false, {ok: false, url: 'https://keep.example.com/settings/recipients', text: async () => 'Rejected'}, {notificationsPage: true, noToast: true});
  await f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.content.error.hidden, false);
  assert.match(f.content.error.textContent, /Could not confirm/);
  assert.equal(f.submit.disabled, false);
  assert.equal(f.navigations.length, 0);
  assert.deepEqual(f.toasts, []);
  assert.equal(f.toast.parentElement, f.body);
});

test('the hidden action control does not replace the recipient submission URL', async () => {
  const f = fixture(false, {ok: true, url: 'https://keep.example.com/settings/users', text: async () => '<html></html>'});
  f.form.action = {name: 'action', value: 'add', toString: () => '[object HTMLInputElement]'};
  await f.form.listeners.submit({preventDefault() {}});
  assert.equal(f.calls[0][0], '/settings/recipients');
  assert.equal(f.calls[0][1].body.form, f.form);
});

function activityNavigation(value) {
  const navigations = [];
  const select = {value, addEventListener(name, handler) { this[name] = handler; }};
  vm.runInNewContext(fs.readFileSync('static/keep-admin-layout.js', 'utf8'), {
    document: {body: {classList: {contains: () => true}},
      querySelector: selector => selector === '.activity-mobile-filter select' ? select : null,
      querySelectorAll: () => []},
    URLSearchParams,
    location: {assign: url => navigations.push(url), set href(url) { navigations.push(url); }},
  });
  select.change();
  assert.equal(navigations.length, 1);
  return new URL(navigations[0], 'https://keep.example.com');
}

test('mobile activity filters navigate locally and reset pagination', () => {
  for (const filter of ['all', 'users', 'api', 'email', 'keeps', 'library']) {
    const destination = activityNavigation(filter);
    assert.equal(destination.origin, 'https://keep.example.com');
    assert.equal(destination.pathname, '/settings/activity');
    assert.deepEqual([...destination.searchParams], [['filter', filter]]);
    assert.equal(destination.hash, '');
  }
});

test('DOM-controlled activity values cannot supply a URL or extra parameters', () => {
  for (const value of ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
    'https://other.example/', '//other.example/', 'keeps&page=2#fragment',
    '%26page%3D2', '\n javascript:alert(1)']) {
    const destination = activityNavigation(value);
    assert.equal(destination.origin, 'https://keep.example.com');
    assert.equal(destination.pathname, '/settings/activity');
    assert.deepEqual([...destination.searchParams], [['filter', value]]);
    assert.equal(destination.hash, '');
  }
});
