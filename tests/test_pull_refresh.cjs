const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('static/keep-pull-refresh.js', 'utf8');
function node(parent = null, interactive = false) {
  const classes = new Set();
  return {parentElement:parent, dataset:{}, children:[], attrs:{}, textContent:'',
    classList:{add:(...xs)=>xs.forEach(x=>classes.add(x)), remove:(...xs)=>xs.forEach(x=>classes.delete(x)),
      toggle:(name,on)=>on?classes.add(name):classes.delete(name), contains:name=>classes.has(name)},
    closest:()=>interactive?{}:null, setAttribute(name,value){this.attrs[name]=value;}, append(...items){this.children.push(...items);},
    scrollHeight:100,clientHeight:100,scrollWidth:100,clientWidth:100,style:{overflowX:'visible',overflowY:'visible'}};
}
function fixture({mobile=true, refreshUrl}={}) {
  const listeners = {}, windowListeners = {}, options = {}, timers = new Map();
  let modal = false, reloads = 0, replacements = [], nextTimer = 0;
  const root = node(), body = node(root), target = node(body);
  const media = {matches:mobile,addEventListener:(name,fn)=>media.change=fn};
  const document = {documentElement:root,body,forms:[],scrollingElement:{scrollTop:0},hidden:false,
    currentScript:{dataset:{refreshUrl}},createElement:()=>node(),querySelector:()=>modal?{}:null,
    addEventListener:(name,fn,opts)=>{listeners[name]=fn;options[name]=opts;}};
  const window = {scrollY:0,matchMedia:()=>media,getComputedStyle:element=>element.style,
    location:{reload:()=>reloads++,replace:url=>replacements.push(url)},
    setTimeout:fn=>{timers.set(++nextTimer,fn);return nextTimer;},clearTimeout:id=>timers.delete(id),
    addEventListener:(name,fn)=>windowListeners[name]=fn};
  const context = {document,window};
  vm.runInNewContext(source, context);
  const indicator = body.children[0], label = indicator.children[1];
  const touch = (name,y,count=name==='touchend'||name==='touchcancel'?0:1,{x=30,target:element=target,cancelable=true,id=1}={}) => {
    let prevented = false;
    listeners[name]({target:element,touches:Array.from({length:count},()=>({clientX:x,clientY:y,identifier:id})),
      cancelable,preventDefault(){prevented=true;}});
    return prevented;
  };
  const pull = (distance=100) => {touch('touchstart',100);touch('touchmove',100+distance);touch('touchend',100+distance);};
  return {document,window,listeners,windowListeners,media,options,root,body,target,indicator,label,touch,pull,
    modal:value=>modal=value,reloads:()=>reloads,replacements:()=>replacements,rerun:()=>vm.runInNewContext(source,context),
    runTimers:()=>{for(const fn of [...timers.values()])fn();}};
}
function form(fields,method='post',protectedForm=false) {
  return {elements:fields,method,matches:()=>protectedForm,closest:()=>null};
}
function field(extra={}) {
  return {name:'name',type:'text',value:'Alex',defaultValue:'Alex',disabled:false,readOnly:false,dataset:{},...extra};
}

test('mobile pages get one shared indicator and a deliberate pull refreshes once',()=>{
  const f=fixture();assert.equal(f.root.classList.contains('keep-pull-refresh-enabled'),true);
  assert.equal(f.indicator.attrs.role,'status');assert.equal(f.indicator.children[0].attrs['aria-hidden'],'true');
  f.rerun();assert.equal(f.body.children.length,1);
  f.touch('touchstart',100);assert.equal(f.touch('touchmove',200),true);
  assert.equal(f.options.touchmove.passive,false);assert.equal(f.label.textContent,'Release to refresh');
  f.touch('touchend',200);assert.equal(f.reloads(),1);
  f.pull();assert.equal(f.reloads(),1);
});
test('desktop touch and resizing out of mobile leave refresh inactive',()=>{
  const f=fixture({mobile:false});f.pull();assert.equal(f.reloads(),0);
  assert.equal(f.root.classList.contains('keep-pull-refresh-enabled'),false);
  f.media.matches=true;f.media.change();f.touch('touchstart',100);f.touch('touchmove',200);
  f.media.matches=false;f.media.change();f.touch('touchend',200);assert.equal(f.reloads(),0);
});
test('scrolling down and back up inside an open dialog never refreshes',()=>{
  const f=fixture();f.modal(true);
  for(const [start,end] of [[300,100],[100,350],[350,100],[100,400]]) {
    f.touch('touchstart',start);f.touch('touchmove',end);f.touch('touchend',end);
    assert.equal(f.reloads(),0);assert.equal(f.indicator.classList.contains('visible'),false);
  }
});
test('opening a dialog during a page gesture cancels refresh',()=>{
  for(const stage of ['touchmove','touchend']) {
    const f=fixture();f.touch('touchstart',100);f.touch('touchmove',200);f.modal(true);f.touch(stage,250);f.touch('touchend',250);
    assert.equal(f.reloads(),0);assert.equal(f.indicator.classList.contains('visible'),false);
  }
});
test('page must start and remain at its top',()=>{
  for(const stage of ['touchstart','touchmove','touchend']) {
    const f=fixture();if(stage==='touchstart')f.window.scrollY=100;f.touch('touchstart',100);
    if(stage==='touchmove')f.document.scrollingElement.scrollTop=100;f.touch('touchmove',200);
    if(stage==='touchend')f.window.scrollY=100;f.touch('touchend',200);assert.equal(f.reloads(),0);
  }
  const f=fixture();f.window.scrollY=-2;f.pull();assert.equal(f.reloads(),1);
});
test('short pulls, horizontal swipes, and reversing direction do not refresh',()=>{
  const short=fixture();short.pull(84);assert.equal(short.reloads(),0);
  const horizontal=fixture();horizontal.touch('touchstart',100);assert.equal(horizontal.touch('touchmove',150,1,{x:180}),false);
  horizontal.touch('touchmove',300);horizontal.touch('touchend',300);assert.equal(horizontal.reloads(),0);
  const reversed=fixture();reversed.touch('touchstart',100);reversed.touch('touchmove',200);reversed.touch('touchmove',90);
  reversed.touch('touchmove',300);reversed.touch('touchend',300);assert.equal(reversed.reloads(),0);
});
test('multitouch, transferred touches, cancellation, and browser-owned scrolling clear gestures',()=>{
  for(const cancel of ['touchcancel','multitouch','transferred','uncancelable']) {
    const f=fixture();f.touch('touchstart',100);f.touch('touchmove',200);
    if(cancel==='touchcancel')f.touch('touchcancel',200);
    if(cancel==='multitouch')f.touch('touchmove',200,2);
    if(cancel==='transferred')f.touch('touchmove',200,1,{id:2});
    if(cancel==='uncancelable')f.touch('touchmove',200,1,{cancelable:false});
    f.touch('touchend',200);assert.equal(f.reloads(),0);
    assert.equal(f.indicator.classList.contains('visible'),false);
  }
});
test('touches on controls and inside vertical or horizontal scrollers remain untouched',()=>{
  for(const kind of ['control','vertical','horizontal']) {
    const f=fixture(),parent=node(f.body,kind==='control'),target=node(parent);
    if(kind==='control')target.closest=()=>({});
    if(kind==='vertical'){parent.style.overflowY='auto';parent.scrollHeight=500;}
    if(kind==='horizontal'){parent.style.overflowX='scroll';parent.scrollWidth=500;}
    f.touch('touchstart',100,1,{target});assert.equal(f.touch('touchmove',200,1,{target}),false);
    f.touch('touchend',200,0,{target});assert.equal(f.reloads(),0);
  }
});
test('existing saved snapshots hold refresh and a brief message clears afterward',()=>{
  const f=fixture();f.window.keepHasUnsavedChanges=()=>true;f.pull();assert.equal(f.reloads(),0);
  assert.equal(f.label.textContent,'Save changes before refreshing');f.runTimers();
  assert.equal(f.indicator.classList.contains('visible'),false);assert.equal(f.label.textContent,'Pull to refresh');
  f.window.keepHasUnsavedChanges=()=>false;f.pull();assert.equal(f.reloads(),1);
});
test('new POST form edits are preserved until reverted; GET filters do not block refresh',()=>{
  const f=fixture(),input=field({value:'Changed'});f.document.forms=[form([input])];f.pull();assert.equal(f.reloads(),0);
  input.value='Alex';f.pull();assert.equal(f.reloads(),1);
  const filters=fixture();filters.document.forms=[form([field({value:'Search'})],'get')];filters.pull();assert.equal(filters.reloads(),1);
});
test('hidden, disabled, readonly, and revealed saved values do not count as edits',()=>{
  const f=fixture();f.document.forms=[form([
    field({type:'hidden',value:'CSRF'}),field({disabled:true,value:'Disabled'}),field({readOnly:true,value:'Copy'}),
    field({value:'secret',dataset:{revealedSaved:'true'}})
  ])];f.pull();assert.equal(f.reloads(),1);
});
test('checkbox and select edits block refresh while their defaults allow it',()=>{
  const option=(selected,defaultSelected=false)=>({selected,defaultSelected,disabled:false,closest:()=>null});
  const checkbox=field({type:'checkbox',checked:true,defaultChecked:false});
  const select=field({options:[option(false,true),option(true)],multiple:false});
  for(const edited of [checkbox,select]) {
    const f=fixture();f.document.forms=[form([edited])];f.pull();assert.equal(f.reloads(),0);
  }
  const f=fixture();f.document.forms=[form([field({options:[{...option(false),disabled:true},option(true)],multiple:false})])];
  f.pull();assert.equal(f.reloads(),1);
});
test('protected forms use their current saved baseline even when default values differ',()=>{
  const f=fixture();f.window.keepHasUnsavedChanges=()=>false;
  f.document.forms=[form([field({value:'Updated saved value'})],'post',true)];f.pull();assert.equal(f.reloads(),1);
});
test('canceled editors inside closed dialogs do not hold page refresh',()=>{
  const f=fixture(),editor=form([field({value:'Discarded edit'})]);
  editor.closest=()=>({open:false});f.document.forms=[editor];f.pull();assert.equal(f.reloads(),1);
});
test('POST-rendered pages refresh using GET navigation rather than repeating the action',()=>{
  const f=fixture({refreshUrl:'/setup?step=verify'});f.pull();assert.equal(f.reloads(),0);
  assert.deepEqual(f.replacements(),['/setup?step=verify']);
});
test('restored pages, hiding a page, and canceled navigation recover usable gesture state',()=>{
  const f=fixture();f.pull();f.runTimers();f.pull();assert.equal(f.reloads(),2);
  f.windowListeners.pageshow();assert.equal(f.indicator.classList.contains('visible'),false);
  f.touch('touchstart',100);f.touch('touchmove',200);f.document.hidden=true;f.listeners.visibilitychange();
  f.document.hidden=false;f.touch('touchend',200);assert.equal(f.reloads(),2);
});
