const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
function fixture(fetcher, times=[], addresses=[], panels=[]) {
  const element = props => Object.assign({listeners:{}, attrs:{}, addEventListener(k,v){this.listeners[k]=v;},setAttribute(k,v){this.attrs[k]=v;}},props);
  const input=element({value:'',type:'password',dataset:{}}), button=element({}), clear=element({checked:false}), error={hidden:true};
  const form=element({children:[], querySelector(selector){
    return selector === '[name=csrf_token]' ? {value:'csrf'} :
      selector === 'input[name="open_services"]' ? this.children.find(child=>child.name==='open_services') : null;
  },appendChild(child){this.children.push(child);}});
  const field={dataset:{credential:'PLEX_ADMIN_TOKEN',configured:'true'},closest:()=>form,querySelector:s=>({'input':input,'.reveal':button,'.credential-clear':clear,'.credential-error':error,'label':{textContent:'Token'}}[s])};
  const document=element({hidden:false,createElement:()=>element({}),querySelectorAll:s=>({
    '[data-credential]':[field], 'time.service-test-time[datetime]':times,
    '[data-service-address]':addresses, 'form':[form],
    'details.service-panel[open]':panels.filter(panel=>panel.open)
  }[s] || [])});
  const window=element({});
  const localIntl={DateTimeFormat:function(locale,options){return new Intl.DateTimeFormat('en-US',{...options,timeZone:'America/Chicago'});}};
  vm.runInNewContext(fs.readFileSync('static/keep-connections.js','utf8'),{document,window,fetch:fetcher|| (async()=>({ok:true,json:async()=>({value:'synthetic'})})),URL,URLSearchParams,Intl:localIntl,setTimeout:()=>1,clearTimeout:()=>{}});
  return {input,button,clear,error,form,document};
}
test('automatic check time uses the viewer time zone and keeps a UTC fallback for invalid dates',()=>{
 const valid={dateTime:'2026-09-21T01:58:00+00:00',textContent:'Checked 2026-09-21 01:58 UTC'};
 const invalid={dateTime:'invalid',textContent:'Checked unknown UTC'};
 fixture(undefined,[valid,invalid]);
 assert.equal(valid.textContent,'Checked Sep 20, 2026, 8:58 PM CDT');
 assert.equal(invalid.textContent,'Checked unknown UTC');
});
test('reveal is deliberate and submit does not resave fetched credentials',async()=>{
 const f=fixture(); assert.equal(f.input.value,''); await f.button.listeners.click(); assert.equal(f.input.value,'synthetic'); assert.equal(f.input.type,'text'); f.form.listeners.submit(); assert.equal(f.input.value,''); assert.equal(f.input.type,'password');
});
test('editing a revealed credential retains the edit on submit',async()=>{
 const f=fixture(); await f.button.listeners.click(); f.input.value='replacement'; f.input.listeners.input(); f.form.listeners.submit(); assert.equal(f.input.value,'replacement');
});
test('hide never erases a typed replacement',async()=>{
 const f=fixture(); f.input.value='replacement'; f.input.listeners.input(); await f.button.listeners.click(); await f.button.listeners.click(); assert.equal(f.input.value,'replacement');
});
test('late reveal cannot overwrite a new edit or leave the toggle disabled',async()=>{
 let finish; const f=fixture(()=>new Promise(resolve=>{finish=resolve;})); const pending=f.button.listeners.click(); f.input.value='edited'; f.input.listeners.input(); finish({ok:true,json:async()=>({value:'old'})}); await pending; assert.equal(f.input.value,'edited'); assert.equal(f.button.disabled,false);
});
test('failed reveal shows a safe error and hidden pages discard late responses',async()=>{
 const f=fixture(async()=>({ok:false})); await f.button.listeners.click(); assert.equal(f.error.hidden,false); assert.equal(f.input.value,'');
 let finish; const g=fixture(()=>new Promise(resolve=>{finish=resolve;})); const pending=g.button.listeners.click(); g.document.hidden=true; g.document.listeners.visibilitychange(); finish({ok:true,json:async()=>({value:'old'})}); await pending; assert.equal(g.input.value,'');
});

function addressFixture(readOnly=false) {
 const controls={};
 for(const part of ['host','scheme','port','path']) controls[part]={listeners:{},value:'',readOnly,
   addEventListener(name,fn){this.listeners[name]=fn;}};
 controls.scheme.value='http'; controls.port.value='7878';
 const address={dataset:{serviceAddress:'RADARR_URL'},querySelector:selector=>controls[selector.split('_').at(-1)]};
 fixture(undefined,[],[address]);
 return controls;
}

test('pasting a full URL keeps its protocol, effective port, IPv6 address and base path',()=>{
 const c=addressFixture();
 c.host.value='https://[2001:db8::1]/radarr'; c.host.listeners.input();
 assert.equal(c.host.value,'2001:db8::1'); assert.equal(c.scheme.value,'https');
 assert.equal(c.port.value,'443'); assert.equal(c.path.value,'/radarr');
 c.host.value='http://radarr:7879/custom'; c.host.listeners.input();
 assert.equal(c.host.value,'radarr'); assert.equal(c.port.value,'7879'); assert.equal(c.path.value,'/custom');
});

test('unsafe pasted URLs remain untouched for server rejection, managed fields have no editing listeners',()=>{
 for(const value of ['https://user:secret@host', 'https://host?token=secret', 'https://host/#fragment', 'https://host\\path']) {
  const c=addressFixture(); c.host.value=value; c.host.listeners.input();
  assert.equal(c.host.value,value); assert.equal(c.port.value,'7878'); assert.equal(c.path.value,'');
 }
 const managed=addressFixture(true); assert.equal(managed.host.listeners.input,undefined);
});

test('protocol controls switch standard web ports while preserving service and custom ports',()=>{
 const c=addressFixture(); c.scheme.value='https'; c.scheme.listeners.change();
 assert.equal(c.port.value,'7878');
 c.port.value='80'; c.scheme.listeners.change(); assert.equal(c.port.value,'443');
 c.scheme.value='http'; c.scheme.listeners.change(); assert.equal(c.port.value,'80');
});

test('submission sends only the current open service IDs, including an explicitly collapsed page',()=>{
 const panels=[{id:'plex',open:true},{id:'email',open:false},{id:'sonarr',open:true}];
 const f=fixture(undefined,[],[],panels); f.form.listeners.submit();
 assert.equal(f.form.children.length,1); assert.equal(f.form.children[0].type,'hidden');
 assert.equal(f.form.children[0].value,'plex,sonarr');
 panels.forEach(panel=>{panel.open=false;}); f.form.listeners.submit();
 assert.equal(f.form.children.length,1); assert.equal(f.form.children[0].value,'');
});
