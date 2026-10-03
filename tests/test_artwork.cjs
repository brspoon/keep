const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
test('only near-viewport posters are promoted; visible posters have priority', () => {
  const images = [100, 900, 5000].map(top => ({loading:'lazy', getBoundingClientRect:()=>({top,bottom:top+300})}));
  let callback, options;
  const observed = [], removed = [];
  class Observer {
    constructor(fn, opts){callback=fn; options=opts;}
    observe(image){observed.push(image);}
    unobserve(image){removed.push(image);}
  }
  vm.runInNewContext(fs.readFileSync('static/keep-artwork.js','utf8'), {
    document:{querySelectorAll:()=>images}, window:{innerHeight:844,IntersectionObserver:Observer}, IntersectionObserver:Observer
  });
  assert.equal(options.rootMargin,'844px 0px');
  callback(images.map((target,index)=>({target,isIntersecting:index<2})));
  assert.equal(images[0].fetchPriority,'high');
  assert.equal(images[1].fetchPriority,'low');
  assert.equal(images[2].loading,'lazy');
  assert.equal(removed.length,2);
});
