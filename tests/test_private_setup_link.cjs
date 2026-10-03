const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(clipboard) {
  const input = {value: 'https://keep.example.com/auth/local/setup/synthetic-token',
    focus() { this.focused = true; }, select() { this.selected = true; }};
  const copy = {addEventListener(name, fn) { this[name] = fn; }};
  const status = {textContent: ''};
  const document = {getElementById: id => ({'private-setup-url': input, 'copy-setup-url': copy, 'copy-setup-status': status}[id])};
  vm.runInNewContext(fs.readFileSync('static/keep-private-setup-link.js', 'utf8'), {document, navigator: {clipboard}});
  return {input, copy, status};
}

test('the private setup URL is copied only after the user requests it', async () => {
  const copied = [];
  const f = fixture({writeText: async value => copied.push(value)});
  assert.deepEqual(copied, []);
  await f.copy.click();
  assert.deepEqual(copied, [f.input.value]);
  assert.match(f.status.textContent, /Setup URL copied/);
  assert.equal(f.input.selected, undefined);
});

for (const [name, clipboard] of [['denied', {writeText: async () => { throw Error('denied'); }}], ['unavailable', undefined]]) {
  test(`manual copy fallback selects the URL when clipboard access is ${name}`, async () => {
    const f = fixture(clipboard);
    await f.copy.click();
    assert.equal(f.input.focused, true);
    assert.equal(f.input.selected, true);
    assert.match(f.status.textContent, /device’s copy command/);
    assert.match(f.input.value, /synthetic-token$/);
  });
}
