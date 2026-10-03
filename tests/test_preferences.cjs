const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher) {
  const el=()=>({listeners:{},addEventListener(n,f){this.listeners[n]=f;},focus(){},hidden:false});
  const trigger=el(), close=el(), cancel=el(), receive=el(), topics={}, title=el();
  const content=el(); let html='';
  Object.defineProperty(content,'innerHTML',{get:()=>html,set:v=>html=v});
  content.prepend=e=>content.error=e;
  content.querySelector=s=>s==='[name="receive_email"]'?receive:s==='fieldset.topics'?topics:s==='.request-error'?content.error:null;
  const dialog=Object.assign(el(),{open:false,showModal(){this.open=true;},close(){this.open=false;this.listeners.close();},querySelector:s=>s==='.welcome-close'?close:cancel,querySelectorAll:()=>[close,cancel]});
  const account={querySelector:s=>s==='.user-links'?{hidden:true}:trigger};
  const document={activeElement:{},getElementById:id=>({'preferences-open':trigger,'preferences-dialog':dialog,'preferences-content':content,'preferences-title':title,'account-menu':account}[id]),documentElement:{dataset:{theme:'system'},classList:{add(){},remove(){}}},createElement:()=>({...el(),setAttribute(){},append(child){this.child=child;}})};
  let calls=[];
  const themeCalls=[];
  const window={keepApplyTheme(choice){themeCalls.push(choice);document.documentElement.dataset.theme=choice;}};
  vm.runInNewContext(fs.readFileSync('static/keep-preferences.js','utf8'),{document,window,URL,fetch:(...args)=>{calls.push(args);return fetcher(...args);},FormData:class{},showToast(){}});
  const click=()=>trigger.listeners.click({preventDefault(){}});
  return {dialog,content,calls,click,close,cancel,receive,topics,themeCalls,document};
}
const success=()=>Promise.resolve({ok:true,url:'http://localhost/preferences?fragment=1',text:async()=>'<form>preferences</form>'});
test('first and repeated Preferences clicks open the dialog and request only the fragment',async()=>{
  const f=fixture(success); await f.click();assert.equal(f.dialog.open,true);assert.equal(f.content.innerHTML,'<form>preferences</form>');
  assert.equal(f.calls[0][0],'/preferences?fragment=1');
  f.cancel.listeners.click();assert.equal(f.dialog.open,false);await f.click();assert.equal(f.dialog.open,true);assert.equal(f.calls.length,2);
});
test('closing while loading discards the stale response',async()=>{
  let finish;const f=fixture(()=>new Promise(r=>finish=r));const loading=f.click();f.close.listeners.click();finish(await success());await loading;assert.equal(f.dialog.open,false);assert.equal(f.content.innerHTML,'');
});
test('an authentication redirect stays in the dialog with a safe error',async()=>{
  const f=fixture(async()=>({ok:true,url:'http://localhost/login',text:async()=>'<html>login</html>'}));await f.click();assert.equal(f.dialog.open,true);assert.equal(f.content.innerHTML,'');assert.match(f.content.error.textContent,/Could not load/);
});
test('closing Preferences restores the saved mode after an unsaved preview',async()=>{
  const f=fixture(success);await f.click();f.document.documentElement.dataset.theme='dark';
  f.cancel.listeners.click();assert.equal(f.document.documentElement.dataset.theme,'system');
  assert.equal(f.themeCalls.at(-1),'system');
});
