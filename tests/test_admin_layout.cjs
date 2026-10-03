const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(localUser, response) {
  const element = () => ({listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; },
    setAttribute() {}, focus() {}, append() {}, hidden: false});
  const submit = Object.assign(element(), {disabled: false, textContent: 'Add and invite'});
  const form = Object.assign(element(), {action: localUser ? '/settings/users/local' : '/settings/recipients',
    classList: {contains: name => localUser && name === 'add-user-form'},
    elements: [{value: 'test-csrf'}, {value: 'person@example.com'}],
    querySelector: () => submit});
  const content = Object.assign(element(), {prepend(error) { this.error = error; }});
  const creation = {querySelector: selector => selector === 'summary span' ? {textContent: 'Add local user'} : content,
    remove() { this.removed = true; }};
  const open = Object.assign(element(), {disabled: true});
  const dialog = Object.assign(element(), {querySelector: () => form, open: false,
    showModal() { this.open = true; }, close() { this.open = false; }});
  const document = {body: {classList: {contains: () => true}, append() {}},
    querySelector: selector => ({'.creation-panel': creation, '.admin-list-search': {}, '.admin-add-button': open}[selector] || null),
    querySelectorAll: () => [], createElement: tag => tag === 'dialog' ? dialog : element()};
  const calls = [], navigations = [];
  vm.runInNewContext(fs.readFileSync('static/keep-admin-layout.js', 'utf8'), {
    document, URL, FormData: class { constructor(target) { this.form = target; } },
    DOMParser: class { parseFromString() { return {querySelector: () => null}; } },
    location: {pathname: '/settings/users', assign: url => navigations.push(url)},
    fetch: async (...args) => { calls.push(args); return response; },
  });
  return {form, submit, content, open, dialog, calls, navigations};
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
});
