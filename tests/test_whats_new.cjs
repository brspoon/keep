const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher = async () => ({ok:true,json:async()=>({status:'seen'})}), auto = true) {
  const element = () => ({listeners:{},addEventListener(name, fn){this.listeners[name]=fn;}});
  const close=element(), done=element(), help=Object.assign(element(),{href:'/help'}), error={hidden:true};
  let focused=false, destination=null, calls=[];
  const dialog=Object.assign(element(),{open:false,dataset:{autoOpen:String(auto),version:'title-status-2.16.0',csrf:'csrf'},
    querySelector:s=>({'.welcome-close':close,'.whats-new-done':done,'.whats-new-help':help,'.whats-new-error':error}[s]),
    showModal(){this.open=true;},close(){this.open=false;this.listeners.close?.();}});
  const classes=new Set();
  const document={documentElement:{classList:{add:name=>classes.add(name),remove:name=>classes.delete(name)}},
    getElementById:id=>id==='whats-new-dialog'?dialog:id==='account-menu'?{querySelector:()=>({focus(){focused=true;}})}:null};
  const window={location:{assign:url=>destination=url}};
  vm.runInNewContext(fs.readFileSync('static/keep-whats-new.js','utf8'),
    {document,window,fetch:async(url,options)=>{calls.push({url,options});return fetcher(url,options);}});
  return {close,done,help,error,dialog,calls,focused:()=>focused,destination:()=>destination,classes};
}

test('close saves seen and does not require Got it',async()=>{
  const f=fixture(); assert.equal(f.dialog.open,true);
  assert.equal(f.classes.has('whats-new-open'),true);
  await f.close.listeners.click();
  assert.equal(f.dialog.open,false); assert.equal(f.focused(),true);
  assert.equal(f.classes.has('whats-new-open'),false);
  assert.equal(f.calls.length,1); assert.equal(f.calls[0].url,'/api/announcements/seen');
  assert.equal(f.calls[0].options.keepalive,true);
  assert.equal(f.calls[0].options.headers['X-CSRF-Token'],'csrf');
  assert.equal(JSON.parse(f.calls[0].options.body).version,'title-status-2.16.0');
});

test('Got it, Escape, and FAQ link all mark the same release seen',async()=>{
  const done=fixture(); await done.done.listeners.click(); assert.equal(done.dialog.open,false);
  const escape=fixture(); let prevented=false;
  escape.dialog.listeners.cancel({preventDefault(){prevented=true;}});
  await Promise.resolve(); await Promise.resolve();
  assert.equal(prevented,true); assert.equal(escape.calls.length,1);
  const help=fixture(); let navigationPrevented=false;
  await help.help.listeners.click({button:0,preventDefault(){navigationPrevented=true;}});
  assert.equal(navigationPrevented,true); assert.equal(help.destination(),'/help');
});

test('failed save keeps the notice available for retry',async()=>{
  const f=fixture(async()=>({ok:false}));
  await f.close.listeners.click();
  assert.equal(f.dialog.open,true); assert.equal(f.error.hidden,false);
  assert.equal(f.close.disabled,false); assert.equal(f.done.disabled,false);
  await f.done.listeners.click(); assert.equal(f.calls.length,2);
});

test('pending dismissals do not submit twice and seen releases do not auto-open',async()=>{
  let resolve;
  const f=fixture(()=>new Promise(r=>resolve=r));
  const first=f.close.listeners.click();
  await f.done.listeners.click(); assert.equal(f.calls.length,1);
  resolve({ok:true,json:async()=>({status:'seen'})}); await first;
  assert.equal(f.dialog.open,false);
  const alreadySeen=fixture(undefined,false);
  assert.equal(alreadySeen.dialog.open,false); assert.equal(alreadySeen.calls.length,0);
});
