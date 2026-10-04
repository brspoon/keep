const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');

function fixture(fetcher=async()=>({ok:true,json:async()=>({status:'deleted',title:'Movie'})})) {
  const element=()=>({listeners:{},dataset:{},hidden:false,disabled:false,textContent:'',classList:{toggle(){},add(){},remove(){}},
    addEventListener(name,fn){this.listeners[name]=fn;},focus(){},setAttribute(){},querySelector(){return null;}});
  const search=element(),clear=element(),status=element(),empty=element(),browseEmpty=element(),nav=element(),link=element(),confirm=element(),cancel=element(),close=element(),error=element();search.value='';error.hidden=true;
  link.getAttribute=()=> '#library-1';
  const heading=element(),library=element();
  const grid=element();grid.replaceWith=replacement=>grid.replacement=replacement;
  const card=element(); card.dataset={title:'Movie',year:'2026'};card.removed=false;card.remove=()=>card.removed=true;
  const count=element();count.textContent='1';
  const section=element();section.id='library-1';section.querySelector=s=>s==='.count'?count:null;section.querySelectorAll=s=>s==='.card'?(card.removed?[]:[card]):[];
  const opener=element();opener.dataset={service:'radarr',itemId:'22',libraryKey:'radarr:4',libraryName:'Movies',title:'Movie'};
  opener.closest=s=>s==='.card'?card:s==='section'?section:null;
  card.closest=s=>s==='.grid'?grid:null;
  card.querySelector=()=>null;
  const dialog=Object.assign(element(),{open:false,dataset:{csrf:'csrf'},showModal(){this.open=true;},close(){this.open=false;this.listeners.close?.();}});
  dialog.querySelector=s=>({'.confirm-delete':confirm,'.delete-cancel':cancel,'.welcome-close':close,'.welcome-error':error,
    'h2':heading,'[data-delete-library]':library}[s]);
  const document={
    getElementById:id=>({'media-search':search,'search-clear':clear,'search-status':status,'search-empty':empty,'browse-empty':browseEmpty,'delete-media-dialog':dialog}[id]),
    querySelector:s=>s==='.section-nav'?nav:null,
    querySelectorAll:s=>s==='.delete-media-button'?[opener]:s==='.media-view section'?[section]:s==='.section-nav a'?[link]:[],
    createElement:()=>element()
  };
  let calls=0,payload=null,toast='';
  const window={showToast:message=>toast=message};
  vm.runInNewContext(fs.readFileSync('static/keep-library.js','utf8'),{document,window,
    fetch:async(url,options)=>{calls++;payload=JSON.parse(options.body);return fetcher(url,options);},
    setTimeout:()=>1,clearTimeout(){}});
  return {search,clear,status,empty,browseEmpty,nav,link,section,confirm,cancel,close,error,opener,card,count,grid,dialog,heading,library,
    calls:()=>calls,payload:()=>payload,toast:()=>toast};
}

test('delete requires the explicit second confirmation and sends service IDs only',async()=>{
  const f=fixture();f.opener.listeners.click();
  assert.equal(f.dialog.open,true);assert.equal(f.heading.textContent,'Delete Movie?');
  assert.equal(f.library.textContent,'Movies');
  await f.confirm.listeners.click();assert.equal(f.calls(),0);assert.equal(f.confirm.textContent,'Delete forever?');
  await f.confirm.listeners.click();assert.equal(f.calls(),1);
  assert.deepEqual(f.payload(),{service:'radarr',itemId:22,libraryKey:'radarr:4'});
  assert.equal(Object.hasOwn(f.payload(),'path'),false);assert.equal(f.card.removed,true);assert.equal(f.count.textContent,0);
  assert.equal(f.toast(),'Movie deleted');assert.equal(f.dialog.open,false);
  assert.equal(f.section.hidden,true);assert.equal(f.link.hidden,true);assert.equal(f.nav.hidden,true);
  assert.equal(f.browseEmpty.hidden,false);assert.equal(f.empty.hidden,true);
});

test('search hides collection buttons and restores them when cleared',()=>{
  const f=fixture();f.search.value='no match';f.search.listeners.input();
  assert.equal(f.section.hidden,true);assert.equal(f.link.hidden,true);assert.equal(f.nav.hidden,true);
  assert.equal(f.empty.hidden,false);assert.equal(f.browseEmpty.hidden,true);
  f.clear.listeners.click();
  assert.equal(f.section.hidden,false);assert.equal(f.link.hidden,false);assert.equal(f.nav.hidden,false);
  assert.equal(f.empty.hidden,true);assert.equal(f.browseEmpty.hidden,true);
});

test('server refusal stays in the dialog and never removes the card',async()=>{
  const f=fixture(async()=>({ok:false,json:async()=>({error:'Remove this title from Kept before deleting it'})}));
  f.opener.listeners.click();await f.confirm.listeners.click();await f.confirm.listeners.click();
  assert.equal(f.dialog.open,true);assert.equal(f.card.removed,false);assert.equal(f.error.hidden,false);
  assert.equal(f.error.textContent,'Remove this title from Kept before deleting it');
  assert.equal(f.confirm.disabled,false);assert.equal(f.cancel.disabled,false);
});

test('unexpected HTML failure stays readable and never removes a card',async()=>{
  const f=fixture(async()=>({ok:false,json:async()=>{throw new SyntaxError('Unexpected token <');}}));
  f.opener.listeners.click();await f.confirm.listeners.click();await f.confirm.listeners.click();
  assert.equal(f.dialog.open,true);assert.equal(f.card.removed,false);
  assert.equal(f.error.textContent,'Could not confirm deletion. Reload the library to check its current state.');
  assert.equal(f.confirm.disabled,false);
});
