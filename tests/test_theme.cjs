const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function fixture(choice, systemDark) {
  const dataset = {theme: choice};
  const media = {matches: systemDark, listener: null,
    addEventListener(name, callback) { this.listener = callback; }};
  const meta = {content: '', setAttribute(name, value) { this.content = value; }};
  const document = {documentElement: {dataset}, querySelector: () => meta,
    addEventListener(name, callback) { this.changeListener = callback; }};
  const window = {matchMedia: () => media};
  vm.runInNewContext(fs.readFileSync('static/keep-theme.js', 'utf8'), {document, window});
  return {dataset, media, meta, apply: window.keepApplyTheme, change: document.changeListener};
}

test('System follows device changes, while explicit choices stay fixed', () => {
  const f = fixture('system', false);
  assert.equal(f.dataset.appearance, 'light');
  assert.equal(f.meta.content, 'light');
  f.media.matches = true;
  f.media.listener();
  assert.equal(f.dataset.appearance, 'dark');
  f.apply('light');
  f.media.matches = false;
  f.media.listener();
  assert.equal(f.dataset.appearance, 'light');
  f.apply('dark');
  assert.equal(f.dataset.appearance, 'dark');
});

test('invalid stored choices fall back to System', () => {
  const f = fixture('unexpected', true);
  assert.equal(f.dataset.theme, 'system');
  assert.equal(f.dataset.appearance, 'dark');
});

test('selecting a mode previews it before saving', () => {
  const f = fixture('system', true);
  f.change({target:{value:'light',matches:selector=>selector==='input[type="radio"][name="theme_mode"]'}});
  assert.equal(f.dataset.appearance, 'light');
  assert.equal(f.dataset.theme, 'light');
});
