const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');

function fixture(fetcher) {
  const element=()=>({listeners:{},dataset:{},hidden:false,disabled:false,checked:false,textContent:'',children:[],
    addEventListener(n,fn){this.listeners[n]=fn;},setAttribute(n,v){this[n]=v;},
    append(...nodes){this.children.push(...nodes);},replaceChildren(){this.children=[];},
    focus(){document.activeElement=this;},getClientRects(){return this.hidden?[]:[{}];}});
  const document={activeElement:null,createElement:()=>element()};
  const selectors=['h2','.season-loading','.season-selection','.season-options','.season-summary','.season-review',
    '.season-confirmation','.season-confirm-summary','.season-delete','.season-back','.season-close','.season-error','.season-reload'];
  const els=Object.fromEntries(selectors.map(s=>[s,element()]));
  const dialog=Object.assign(element(),{open:false,dataset:{csrf:'csrf'},showModal(){this.open=true;},close(){this.open=false;this.listeners.close();},
    querySelector:s=>els[s],querySelectorAll:()=>Object.values(els)});
  els['.season-options'].querySelectorAll=()=>els['.season-options'].children.map(row=>row.children[0]).filter(input=>input.checked);
  const opener=element();opener.dataset={itemId:'22',libraryKey:'sonarr:5',title:'Show'};
  document.getElementById=()=>dialog;document.querySelectorAll=()=>[opener];
  let calls=[],reloads=0;
  const window={location:{reload(){reloads++;}}};
  const data={token:'signed-preview',seasons:[{number:0,episodes:2,size:'1 GB'},{number:1,episodes:8,size:'8 GB'}]};
  vm.runInNewContext(fs.readFileSync('static/keep-seasons.js','utf8'),{document,window,fetch:async(url,options)=>{
    calls.push({url,options});return fetcher?fetcher(url,options):{ok:true,json:async()=>options.method?{status:'seasons-deleted'}:data};}});
  const select=n=>{const input=els['.season-options'].children[n].children[0];input.checked=!input.checked;input.listeners.change();};
  return {els,dialog,opener,document,calls,data,select,reloads:()=>reloads};
}

test('switches select only; separate review and confirmation precede deletion',async()=>{
  const f=fixture();await f.opener.listeners.click();
  assert.equal(f.els['.season-review'].disabled,true);
  assert.equal(f.els['.season-options'].children[0].children[0].role,'switch');
  f.select(1);assert.equal(f.calls.length,1);assert.equal(f.els['.season-review'].disabled,false);
  f.els['.season-review'].listeners.click();assert.equal(f.calls.length,1);
  assert.equal(f.els['.season-confirmation'].hidden,false);
  assert.equal(f.document.activeElement,f.els['.season-back']);
  await f.els['.season-delete'].listeners.click();
  assert.equal(f.calls.length,2);
  assert.deepEqual(JSON.parse(f.calls[1].options.body),{service:'sonarr',itemId:22,libraryKey:'sonarr:5',seasons:[1],previewToken:'signed-preview'});
  assert.equal(f.reloads(),1);
});

test('Back preserves selection; Close restores focus without any write',async()=>{
  const f=fixture();await f.opener.listeners.click();f.select(0);f.els['.season-review'].listeners.click();
  f.els['.season-back'].listeners.click();assert.equal(f.els['.season-selection'].hidden,false);
  assert.equal(f.els['.season-options'].children[0].children[0].checked,true);
  f.els['.season-close'].listeners.click();assert.equal(f.dialog.open,false);
  assert.equal(f.document.activeElement,f.opener);assert.equal(f.calls.length,1);
});

test('late load response cannot reopen a closed dialog',async()=>{
  let resolve;const f=fixture(()=>new Promise(r=>resolve=r));const loading=f.opener.listeners.click();
  f.els['.season-close'].listeners.click();resolve({ok:true,json:async()=>f.data});await loading;
  assert.equal(f.dialog.open,false);assert.equal(f.els['.season-options'].children.length,0);
});

test('uncertain failure requires reload, never success or automatic retry',async()=>{
  for(const mode of ['html','partial','network','null']) {
    const f=fixture(async(url,options)=>{
      if(!options.method) return {ok:true,json:async()=>({token:'token',seasons:[{number:1,episodes:8,size:'8 GB'}]})};
      if(mode==='network') throw Error('network');
      return {ok:false,json:async()=>{if(mode==='html') throw Error('<html>');return mode==='null'?null:{error:'Partially deleted',refreshRequired:true};}};
    });
    await f.opener.listeners.click();f.select(0);f.els['.season-review'].listeners.click();
    await f.els['.season-delete'].listeners.click();
    assert.equal(f.els['.season-error'].hidden,false);
    assert.equal(f.els['.season-reload'].hidden,false);
    assert.equal(f.els['.season-delete'].disabled,true);
    await f.els['.season-delete'].listeners.click();
    assert.equal(f.calls.length,2);assert.equal(f.reloads(),0);
  }
});

test('pending deletion blocks duplicate confirmation and Escape',async()=>{
  let finish;const f=fixture(async(url,options)=>options.method?new Promise(resolve=>finish=resolve):
    {ok:true,json:async()=>({token:'token',seasons:[{number:1,episodes:8,size:'8 GB'}]})});
  await f.opener.listeners.click();f.select(0);f.els['.season-review'].listeners.click();
  const deleting=f.els['.season-delete'].listeners.click();
  await f.els['.season-delete'].listeners.click();assert.equal(f.calls.length,2);
  let blocked=false;f.dialog.listeners.cancel({preventDefault(){blocked=true;}});assert.equal(blocked,true);
  finish({ok:true,json:async()=>({status:'seasons-deleted'})});await deleting;
});
