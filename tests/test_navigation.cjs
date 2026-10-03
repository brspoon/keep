const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(navigationType = 'navigate') {
  const handlers = {}, classes = new Set(), attributes = new Set();
  const search = {value:'Example', dispatchEvent:()=>{}};
  const storage = new Map();
  let restored;
  const link = {href:'https://keep.example/kept', target:'', hasAttribute:()=>false,
    getAttribute:()=>null, setAttribute:name=>attributes.add(name), removeAttribute:name=>attributes.delete(name)};
  const document = {documentElement:{classList:{add:x=>classes.add(x),remove:x=>classes.delete(x)}},
    querySelector:()=>null, querySelectorAll:()=>[link], getElementById:()=>search,
    addEventListener:(name,handler)=>handlers[name]=handler};
  const window = {performance:{getEntriesByType:()=>[{type:navigationType}]},scrollY:123, addEventListener:(name,handler)=>handlers[name]=handler,
    scrollTo:(x,y)=>{restored=y;}};
  const location = {origin:'https://keep.example',href:'https://keep.example/',pathname:'/',hash:''};
  vm.runInNewContext(fs.readFileSync('static/keep-navigation.js','utf8'), {document,window,location,URL,
    sessionStorage:{getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value)},
    requestAnimationFrame:fn=>fn(), Event:class {}});
  return {handlers,classes,attributes,search,restored:()=>restored,click:extra=>handlers.click({target:{closest:()=>link},button:0,...extra})};
}
test('normal navigation gives immediate feedback; modified clicks do not',()=>{
  const f=fixture(); f.click({ctrlKey:true}); assert.equal(f.classes.size,0);
  f.click({}); assert.ok(f.classes.has('navigation-pending')); assert.ok(f.attributes.has('data-pending'));
  f.handlers.pageshow({persisted:true}); assert.equal(f.classes.size,0); assert.equal(f.attributes.size,0);
});
test('search and scroll restore after history navigation',()=>{
  const f=fixture('back_forward'); f.handlers.pagehide(); f.search.value=''; f.handlers.pageshow({persisted:false});
  assert.equal(f.search.value,'Example'); assert.equal(f.restored(),123);
});
test('ordinary page navigation starts at the top despite a saved position',()=>{
  const f=fixture(); f.handlers.pagehide(); f.search.value=''; f.handlers.pageshow({persisted:false});
  assert.equal(f.search.value,'Example'); assert.equal(f.restored(),0);
});
