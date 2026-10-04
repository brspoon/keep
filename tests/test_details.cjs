const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
function fixture(fetcher,card=null){
  const elements=[];
  let document;
  const el=()=>({children:[],listeners:{},attrs:{},html:'',append(...e){this.children.push(...e)},prepend(e){this.children.unshift(e)},replaceChildren(...e){this.innerHTML='';this.children=e},setAttribute(k,v){this.attrs[k]=v},addEventListener(k,f){this.listeners[k]=f},querySelector(selector){return selector==='h2'?this.heading:selector==='[data-status-url]'?this.live:null},focus(){this.focused=true;document.activeElement=this},remove(){this.removed=true},showModal(){this.open=true},close(){this.open=false;this.listeners.close()},getBoundingClientRect(){return {left:0,right:100,top:0,bottom:100}},get innerHTML(){return this.html},set innerHTML(value){this.html=value;this.children=[];this.heading=value.includes('<h2')?el():null;const match=value.match(/data-status-url="([^"]+)"/);this.live=match?el():null;if(this.live)this.live.dataset={statusUrl:match[1]}}});
  const opener={dataset:{detailsUrl:'/api/title-details/leaving/1?collection=1'},closest(){return card},focus(){this.focused=true;document.activeElement=this}};
  document={listeners:{},addEventListener(k,f){this.listeners[k]=f},createElement(){const e=el();elements.push(e);return e},body:el(),documentElement:{classList:{add(){},remove(){}}}};
  vm.runInNewContext(fs.readFileSync('static/keep-details.js','utf8'),{document,fetch:fetcher,AbortController});
  const click=()=>document.listeners.click({target:{closest:()=>opener},preventDefault(){}});
  return {click,opener,elements,document,get dialog(){return elements[0]},get content(){return elements[2]}};
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
  assert.equal(f.elements[2].innerHTML,'');assert.match(f.elements.find(e=>e.attrs.role==='alert').textContent,/Could not load/);
  assert.equal(f.elements.at(-1).textContent,'Try again');
});
test('card title and existing artwork appear before the network responds',()=>{
  const card={querySelector(selector){return selector==='img.poster'?{currentSrc:'/artwork/poster.jpg',hidden:false}:{textContent:'Immediate title'}}};
  let requested;
  const f=fixture((url)=>{requested=url;return new Promise(()=>{})},card);f.click();
  assert.equal(f.dialog.open,true);
  assert.equal(f.content.children[0].src,'/artwork/poster.jpg');
  assert.equal(f.document.activeElement.textContent,'Immediate title');
  assert.equal(f.content.children[1].children[1].textContent,'Loading title details…');
  assert.equal(requested,'/api/title-details/leaving/1?collection=1&view=core');
});
test('library URL without a query requests core details correctly',async()=>{
  let requested;const f=fixture(async url=>{requested=url;return {ok:true,text:async()=>'<h2>Title</h2>'}});
  f.opener.dataset.detailsUrl='/api/title-details/sonarr/22';f.click();await tick();
  assert.equal(requested,'/api/title-details/sonarr/22?view=core');
});
test('artwork that fails during the instant shell is not reinserted after core details',async()=>{
  const card={querySelector(selector){return selector==='img.poster'?{src:'/broken-poster',hidden:false}:{textContent:'Title'}}};
  let resolve;const f=fixture(()=>new Promise(r=>resolve=r),card);f.click();
  const image=f.content.children[0];image.listeners.error();assert.equal(image.removed,true);
  resolve({ok:true,text:async()=>'<h2>Title</h2>'});await tick();
  assert.equal(f.content.children.includes(image),false);
});
test('slow optional status leaves basic details and request history visible',async()=>{
  const pending=[];
  const f=fixture((url,options)=>new Promise(resolve=>pending.push({url,options,resolve})));
  f.click();pending[0].resolve({ok:true,text:async()=>'<h2>Title</h2><p>Description</p><section>Request history</section><div data-status-url="/fresh-status"></div>'});await tick();
  assert.match(f.content.innerHTML,/Description/);assert.match(f.content.innerHTML,/Request history/);
  assert.equal(pending[1].url,'/fresh-status');assert.equal(pending[1].options.credentials,'same-origin');
  assert.equal(pending[1].options.signal,pending[0].options.signal);
  const live=f.content.live;assert.equal(live.attrs['aria-busy'],'true');
  pending[1].resolve({ok:true,text:async()=>'<p>Kept indefinitely</p>'});await tick();
  assert.equal(live.innerHTML,'<p>Kept indefinitely</p>');assert.equal(live.attrs['aria-busy'],'false');
  assert.match(f.content.innerHTML,/Description/);
});
test('a late status response cannot update a reopened title',async()=>{
  const pending=[];const f=fixture((url,options)=>new Promise(resolve=>pending.push({url,options,resolve})));
  f.click();pending[0].resolve({ok:true,text:async()=>'<h2>Old title</h2><div data-status-url="/old-status"></div>'});await tick();
  const old=f.content.live;f.dialog.close();assert.equal(pending[1].options.signal.aborted,true);
  f.click();pending[2].resolve({ok:true,text:async()=>'<h2>New title</h2><div data-status-url="/new-status"></div>'});await tick();
  const current=f.content.live;
  pending[3].resolve({ok:true,text:async()=>'<p>Current status</p>'});await tick();
  pending[1].resolve({ok:true,text:async()=>'<p>Old status</p>'});await tick();
  assert.equal(current.innerHTML,'<p>Current status</p>');assert.equal(old.innerHTML,'');
  assert.match(f.content.innerHTML,/New title/);
});
test('status errors preserve core details and retry only the fresh status request',async()=>{
  const urls=[];
  const f=fixture(async url=>{urls.push(url);return urls.length===1?{ok:true,text:async()=>'<h2>Title</h2><p>Description</p><div data-status-url="/status"></div>'}:urls.length===2?{ok:true,redirected:true,text:async()=>'<form>login</form>'}:{ok:true,text:async()=>'<p>New status</p>'}});
  f.click();await tick();const live=f.content.live;
  assert.match(f.content.innerHTML,/Description/);assert.equal(live.innerHTML,'');
  assert.equal(live.children[0].attrs.role,'alert');assert.match(live.children[0].textContent,/currently unavailable/);
  live.children[1].focus();live.children[1].listeners.click();await tick();
  assert.deepEqual(urls,['/api/title-details/leaving/1?collection=1&view=core','/status','/status']);
  assert.equal(live.innerHTML,'<p>New status</p>');
  assert.equal(f.document.activeElement,live);
});
test('finishing core details does not steal focus back from the close button',async()=>{
  let resolve;const f=fixture(()=>new Promise(r=>resolve=r));f.click();
  const close=f.elements[1];close.focus();
  resolve({ok:true,text:async()=>'<h2>Title</h2>'});await tick();
  assert.equal(f.document.activeElement,close);
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
