const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
function fixture(fetcher){
  const elements=[];
  const el=()=>({children:[],listeners:{},attrs:{},append(...e){this.children.push(...e)},prepend(e){this.children.unshift(e)},replaceChildren(){this.children=[];this.innerHTML=''},setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){this.listeners[k]=f},querySelector(){return null},focus(){this.focused=true},showModal(){this.open=true},close(){this.open=false;this.listeners.close()},getBoundingClientRect(){return {left:0,right:100,top:0,bottom:100}}});
  const opener={dataset:{detailsUrl:'/api/title-details/leaving/1?collection=1'},closest(){return null},focus(){this.focused=true}};
  const document={listeners:{},addEventListener(k,f){this.listeners[k]=f},createElement(){const e=el();elements.push(e);return e},body:el(),documentElement:{classList:{add(){},remove(){}}}};
  vm.runInNewContext(fs.readFileSync('static/keep-details.js','utf8'),{document,fetch:fetcher,AbortController});
  const click=()=>document.listeners.click({target:{closest:()=>opener},preventDefault(){}});
  return {click,opener,elements,document};
}
const tick=()=>new Promise(r=>setImmediate(r));
test('first and repeated opens use one dialog and closing restores opener focus',async()=>{
  const f=fixture(async()=>({ok:true,text:async()=>'<h2>Title</h2>'}));f.click();await tick();
  assert.equal(f.elements[0].open,true);assert.equal(f.elements[2].innerHTML,'<h2>Title</h2>');
  f.elements[0].close();assert.equal(f.opener.focused,true);f.click();await tick();
  assert.equal(f.document.body.children.length,1);
});
test('closed response cannot populate a later open',async()=>{
  const pending=[];const f=fixture(()=>new Promise(r=>pending.push(r)));
  f.click();f.elements[0].close();f.click();
  pending[1]({ok:true,text:async()=>'<h2>New</h2>'});await tick();
  pending[0]({ok:true,text:async()=>'<h2>Old</h2>'});await tick();
  assert.equal(f.elements[2].innerHTML,'<h2>New</h2>');
});
test('auth redirect is not inserted and error offers retry',async()=>{
  const f=fixture(async()=>({ok:true,redirected:true,text:async()=>'<form>login</form>'}));f.click();await tick();
  assert.equal(f.elements[2].innerHTML,'');assert.match(f.elements[3].textContent,/Could not load/);
  assert.equal(f.elements.at(-1).textContent,'Try again');
});
test('unrelated action clicks never open details',()=>{
  let fetched=false;const f=fixture(()=>{fetched=true});
  f.document.listeners.click({target:{closest:()=>null}});
  assert.equal(f.document.body.children.length,0);assert.equal(fetched,false);
});
test('Tab wraps within the modal instead of leaving the only control',async()=>{
  const f=fixture(async()=>({ok:true,text:async()=>'<h2>Title</h2>'}));f.click();await tick();
  const dialog=f.elements[0],close=f.elements[1];dialog.querySelectorAll=()=>[close];
  f.document.activeElement=close;let prevented=false;
  dialog.listeners.keydown({key:'Tab',shiftKey:false,preventDefault(){prevented=true}});
  assert.equal(prevented,true);assert.equal(close.focused,true);
});
test('season disclosure participates in the modal keyboard loop',async()=>{
  const f=fixture(async()=>({ok:true,text:async()=>'<h2>Title</h2><details><summary>Seasons</summary></details>'}));f.click();await tick();
  const dialog=f.elements[0],close=f.elements[1],summary={focus(){this.focused=true}};
  dialog.querySelectorAll=selector=>{assert.match(selector,/summary/);return [close,summary]};
  f.document.activeElement=close;
  dialog.listeners.keydown({key:'Tab',shiftKey:true,preventDefault(){}});
  assert.equal(summary.focused,true);
  f.document.activeElement=summary;
  dialog.listeners.keydown({key:'Tab',shiftKey:false,preventDefault(){}});
  assert.equal(close.focused,true);
});
