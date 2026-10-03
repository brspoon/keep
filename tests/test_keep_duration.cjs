const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher = async () => ({ok:true})) {
  const element = () => {
    const classes=new Set(), attrs=new Map();
    return ({
    listeners:{}, disabled:false, isConnected:true, classList:{add:v=>classes.add(v),remove:v=>classes.delete(v),toggle:(v,on)=>on?classes.add(v):classes.delete(v),contains:v=>classes.has(v)},
    addEventListener(name, fn){this.listeners[name]=fn;},
    setAttribute(name,value){attrs.set(name,value);},removeAttribute(name){attrs.delete(name);},
    focus(){document.activeElement=this;}
  });};
  const heading=element(), close=element(), cancel=element(), error={hidden:true};
  const temporary=Object.assign(element(),{dataset:{duration:'temporary'}});
  const indefinite=Object.assign(element(),{dataset:{duration:'indefinite'}});
  const count={textContent:'1'};
  const grid={};
  const title={textContent:'A Very Good Movie'};
  const card={removed:false,querySelector:s=>s==='.title'?title:null,remove(){this.removed=true;}};
  const section={querySelector:s=>s==='.count'?count:grid,querySelectorAll:()=>card.removed?[]:[card]};
  const opener=Object.assign(element(),{
    dataset:{mediaId:'42',collectionId:'1'},textContent:'KEEP',
    closest:s=>s==='.card'?card:section
  });
  const dialog=Object.assign(element(),{
    open:false,dataset:{csrf:'csrf'},
    querySelector:s=>({h2:heading,'.welcome-close':close,'.keep-duration-cancel':cancel,'.welcome-error':error}[s]),
    querySelectorAll:s=>s==='[data-duration]'?[temporary,indefinite]:[],
    showModal(){this.open=true;},close(){this.open=false;this.listeners.close();}
  });
  const classes=new Set();
  const document={activeElement:null,documentElement:{classList:{add:v=>classes.add(v),remove:v=>classes.delete(v)}},
    getElementById:id=>id==='keep-duration-dialog'?dialog:null,
    querySelectorAll:s=>s==='.new-keep-button'?[opener]:[]};
  let request, toast, counts=0, searches=0;
  const context={document,fetch:async(...args)=>{request=args;return fetcher(...args);},
    refreshCounts(){counts++;},showToast(...args){toast=args;},applyMediaSearch(){searches++;},
    setTimeout,window:{KeepUI:null,location:{reload(){}}}};
  vm.runInNewContext(fs.readFileSync('static/keep-duration.js','utf8'),context);
  return {dialog,opener,temporary,indefinite,close,cancel,error,heading,card,
    request:()=>request,toast:()=>toast,counts:()=>counts,searches:()=>searches,document,classes};
}

test('dialog offers a recommended 30-day keep and sends the selected duration', async()=>{
  const f=fixture();
  f.opener.listeners.click();
  assert.equal(f.dialog.open,true);
  assert.equal(f.heading.textContent,'Keep A Very Good Movie?');
  assert.equal(f.document.activeElement,f.temporary);
  assert.equal(f.classes.has('keep-duration-open'),true);
  await f.temporary.listeners.click();
  const [url,options]=f.request();
  assert.equal(url,'/api/keep');
  assert.deepEqual(JSON.parse(options.body),{mediaId:'42',collectionId:1,duration:'temporary'});
  assert.equal(options.headers['X-CSRF-Token'],'csrf');
  assert.equal(f.dialog.open,false);
  assert.equal(f.card.removed,true);
  assert.equal(f.counts(),1);
  assert.equal(f.searches(),1);
  assert.ok(f.toast()[0].includes('30 days'));
});

test('cancel restores focus and a failed request remains open for retry', async()=>{
  const f=fixture(async()=>({ok:false}));
  f.opener.listeners.click();f.cancel.listeners.click();
  assert.equal(f.dialog.open,false);assert.equal(f.document.activeElement,f.opener);
  assert.equal(f.classes.has('keep-duration-open'),false);
  f.opener.listeners.click();await f.indefinite.listeners.click();
  assert.equal(f.dialog.open,true);assert.equal(f.error.hidden,false);
  assert.equal(f.temporary.disabled,false);assert.equal(f.indefinite.disabled,false);
  assert.equal(f.document.activeElement,f.temporary);
});

test('keyboard focus wraps through every dialog action',()=>{
  const f=fixture();f.opener.listeners.click();let prevented=0;
  f.document.activeElement=f.cancel;
  f.dialog.listeners.keydown({key:'Tab',shiftKey:false,preventDefault(){prevented++;}});
  assert.equal(f.document.activeElement,f.close);
  f.dialog.listeners.keydown({key:'Tab',shiftKey:true,preventDefault(){prevented++;}});
  assert.equal(f.document.activeElement,f.cancel);
  assert.equal(prevented,2);
});

test('30-day-only users confirm inline without opening a dialog', async()=>{
  const classes=new Set();
  const count={textContent:'1'};
  const title={textContent:'A Very Good Movie'};
  const card={removed:false,querySelector:s=>s==='.title'?title:null,remove(){this.removed=true;}};
  const section={querySelector:s=>s==='.count'?count:{},querySelectorAll:()=>card.removed?[]:[card]};
  const opener={listeners:{},disabled:false,textContent:'KEEP',dataset:{
      mediaId:'42',collectionId:'1',directTemporary:'true'
    },addEventListener(name,fn){this.listeners[name]=fn;},
    closest:s=>s==='.card'?card:section};
  const document={body:{dataset:{csrf:'csrf'}},documentElement:{classList:{add(){},remove(){}}},
    getElementById:()=>null,
    querySelectorAll:s=>s==='.new-keep-button[data-direct-temporary="true"]'||s==='.new-keep-button'?[opener]:[]};
  let request,toast;
  const context={document,fetch:async(...args)=>{request=args;return {ok:true};},
    refreshCounts(){},showToast(message){toast=message;},applyMediaSearch(){},setTimeout,clearTimeout,
    window:{KeepUI:null,showToast(message){toast=message;},location:{reload(){}}}};
  vm.runInNewContext(fs.readFileSync('static/keep-duration.js','utf8'),context);
  await opener.listeners.click();
  assert.equal(request,undefined);
  assert.equal(opener.textContent,'KEEP FOR 30 DAYS?');
  assert.equal(opener.dataset.confirming,'true');
  await opener.listeners.click();
  assert.equal(request[0],'/api/keep');
  assert.deepEqual(JSON.parse(request[1].body),{mediaId:'42',collectionId:1,duration:'temporary'});
  assert.equal(request[1].headers['X-CSRF-Token'],'csrf');
  assert.equal(card.removed,true);
  assert.ok(toast.includes('30 days'));
});

function manageFixture({temporary=true, canExtend=true, fetcher=async()=>({ok:true})}={}) {
  const element = () => {
    const classes=new Set(), attrs=new Map();
    return {listeners:{},disabled:false,isConnected:true,textContent:'',
      classList:{add:v=>classes.add(v),remove:v=>classes.delete(v),toggle:(v,on)=>on?classes.add(v):classes.delete(v),contains:v=>classes.has(v)},
      addEventListener(name,fn){this.listeners[name]=fn;},
      setAttribute(name,value){attrs.set(name,value);},removeAttribute(name){attrs.delete(name);},
      getAttribute(name){return attrs.get(name);},focus(){document.activeElement=this;}};
  };
  const heading=element(),description=element(),close=element(),cancel=element(),error={hidden:true};
  const temporaryTitle=element(),temporaryDetail=element(),indefiniteDetail=element();
  const temporaryChoice=Object.assign(element(),{dataset:{duration:'temporary'},querySelector:s=>s==='[data-option-title]'?temporaryTitle:temporaryDetail});
  const indefiniteChoice=Object.assign(element(),{dataset:{duration:'indefinite'},querySelector:()=>indefiniteDetail});
  const title={textContent:'A Very Good Movie'};
  const card={querySelector:s=>s==='.title'?title:null};
  const opener=Object.assign(element(),{textContent:'MANAGE KEEP',dataset:{
    mediaId:'42',collectionId:'1',isTemporary:String(temporary),daysLeft:temporary?'18':'',
    expiryLabel:temporary?'September 28, 2026':'',nextTemporaryLabel:temporary?'October 28, 2026':'October 10, 2026',
    canExtend:String(canExtend),extensionAvailableLabel:canExtend?'':'September 28, 2026'
  },closest:()=>card});
  const dialog=Object.assign(element(),{open:false,dataset:{csrf:'csrf'},
    querySelector:s=>({h2:heading,'.welcome-intro':description,'.welcome-close':close,'.keep-duration-cancel':cancel,'.welcome-error':error}[s]),
    querySelectorAll:s=>s==='[data-duration]'?[temporaryChoice,indefiniteChoice]:[],
    showModal(){this.open=true;},close(){this.open=false;this.listeners.close();}});
  const classes=new Set();
  const document={activeElement:null,documentElement:{classList:{add:v=>classes.add(v),remove:v=>classes.delete(v)}},
    getElementById:id=>id==='manage-keep-dialog'?dialog:null,
    querySelectorAll:s=>s==='.keep-manage-button'?[opener]:[]};
  let request,toast,replay,reloads=0;
  const context={document,fetch:async(...args)=>{request=args;return fetcher(...args);},
    refreshCounts(){},showToast(...args){toast=args;},applyMediaSearch(){},
    setTimeout(fn){fn();},window:{KeepUI:null,KeepToastAfterReload(message){replay=message;},location:{reload(){reloads++;}}}};
  vm.runInNewContext(fs.readFileSync('static/keep-duration.js','utf8'),context);
  return {dialog,opener,temporaryChoice,indefiniteChoice,temporaryTitle,temporaryDetail,
    indefiniteDetail,description,heading,close,cancel,error,document,classes,
    request:()=>request,toast:()=>toast,replay:()=>replay,reloads:()=>reloads};
}

test('temporary keep management previews and applies a 30-day extension',async()=>{
  const f=manageFixture();
  f.opener.listeners.click();
  assert.equal(f.dialog.open,true);
  assert.equal(f.heading.textContent,'Manage A Very Good Movie');
  assert.ok(f.description.textContent.includes('18 days'));
  assert.equal(f.temporaryTitle.textContent,'Extend by 30 days');
  assert.equal(f.temporaryDetail.textContent,'New expiration: October 28, 2026');
  assert.equal(f.request(),undefined);
  await f.temporaryChoice.listeners.click();
  const [url,options]=f.request();
  assert.equal(url,'/api/update-keep');
  assert.deepEqual(JSON.parse(options.body),{mediaId:'42',collectionId:1,duration:'temporary'});
  assert.equal(f.dialog.open,false);
  assert.equal(f.reloads(),1);
  assert.equal(f.toast()[0],'Keep extended by 30 days');
  assert.equal(f.replay(),'Keep extended by 30 days');
});

test('indefinite keep management marks the current choice and can switch to 30 days',async()=>{
  const f=manageFixture({temporary:false});
  f.opener.listeners.click();
  assert.equal(f.temporaryTitle.textContent,'Switch to a 30-day keep');
  assert.equal(f.temporaryDetail.textContent,'Expires: October 10, 2026');
  assert.equal(f.indefiniteChoice.disabled,true);
  assert.equal(f.indefiniteChoice.classList.contains('is-current'),true);
  await f.indefiniteChoice.listeners.click();
  assert.equal(f.request(),undefined);
  await f.temporaryChoice.listeners.click();
  assert.equal(JSON.parse(f.request()[1].body).duration,'temporary');
  assert.equal(f.toast()[0],'Title protected for 30 days');
});

test('cooldown keeps extension visible with its next availability and sends no request',async()=>{
  const f=manageFixture({canExtend:false});
  f.opener.listeners.click();
  assert.equal(f.temporaryChoice.disabled,true);
  assert.equal(f.temporaryDetail.textContent,'Available September 28, 2026');
  await f.temporaryChoice.listeners.click();
  assert.equal(f.request(),undefined);
});

test('failed management stays open and cancel restores focus',async()=>{
  const f=manageFixture({fetcher:async()=>({ok:false})});
  f.opener.listeners.click();
  await f.indefiniteChoice.listeners.click();
  assert.equal(f.dialog.open,true);
  assert.equal(f.error.hidden,false);
  assert.equal(f.temporaryChoice.disabled,false);
  assert.equal(f.document.activeElement,f.temporaryChoice);
  f.cancel.listeners.click();
  assert.equal(f.dialog.open,false);
  assert.equal(f.document.activeElement,f.opener);
});
