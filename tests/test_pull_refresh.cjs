const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
function fixture() {
  const listeners = {}, classes = new Set();
  let modal = false, reloads = 0;
  const indicator = {classList: {add: (...xs) => xs.forEach(x => classes.add(x)), remove: (...xs) => xs.forEach(x => classes.delete(x))}};
  const label = {};
  const document = {getElementById: id => id === 'pull-refresh' ? indicator : label,
    querySelector: () => modal ? {} : null, addEventListener: (name, fn) => listeners[name] = fn};
  const window = {scrollY: 0, location: {reload: () => reloads++}};
  vm.runInNewContext(fs.readFileSync('static/keep-pull-refresh.js', 'utf8'), {document, window});
  return {listeners, classes, window, modal: value => modal = value, reloads: () => reloads,
    touch: (name, y, count = 1) => listeners[name]({touches: Array.from({length: count}, () => ({clientY: y}))})};
}
test('scrolling down and back up inside an open welcome dialog never refreshes', () => {
  const f = fixture(); f.modal(true);
  for (const [start, end] of [[300, 100], [100, 350], [350, 100], [100, 400]]) {
    f.touch('touchstart', start); f.touch('touchmove', end); f.touch('touchend', end, 0);
    assert.equal(f.reloads(), 0); assert.equal(f.classes.size, 0);
  }
});
test('opening a dialog during a page gesture cancels the refresh', () => {
  for (const stage of ['touchmove', 'touchend']) {
    const f = fixture(); f.touch('touchstart', 100); f.touch('touchmove', 200);
    f.modal(true); f.touch(stage, 250); f.touch('touchend', 250, 0);
    assert.equal(f.reloads(), 0); assert.equal(f.classes.size, 0);
  }
});
test('page pull refresh remains deliberate and cancellation clears stale gestures', () => {
  const f = fixture(); f.touch('touchstart', 100); f.touch('touchmove', 200); f.touch('touchend', 200, 0);
  assert.equal(f.reloads(), 1);
  for (const cancel of ['touchcancel', 'multitouch', 'away']) {
    const g = fixture(); g.touch('touchstart', 100); g.touch('touchmove', 200);
    if (cancel === 'touchcancel') g.touch('touchcancel', 200, 0);
    if (cancel === 'multitouch') g.touch('touchmove', 200, 2);
    if (cancel === 'away') { g.window.scrollY = 100; g.touch('touchstart', 200); }
    g.touch('touchend', 200, 0); assert.equal(g.reloads(), 0);
  }
});
