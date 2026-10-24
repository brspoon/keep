const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
function fixture(withSaveButton=true,initiallyDisabled=false) {
  const handlers={},events={},button=withSaveButton?{disabled:initiallyDisabled,attrs:{},getAttribute:()=>null,setAttribute(name,value){this.attrs[name]=value;}}:null;
  const field={name:'name',type:'text',value:'Alex'};
  const form={elements:[field],isConnected:true,dataset:{},querySelector:()=>button,addEventListener:(n,f)=>events[n]=f,checkValidity:()=>true,matches:s=>s==='[data-saved-test]'&&form.dataset.savedTest==='true',closest:()=>null,reset(){field.value='Alex';},dispatchEvent(e){events[e.type]?.();}};
  const document={body:{},querySelector:()=>null,querySelectorAll:s=>s==='form[data-save-key], form[data-protect-unsaved]'?[form]:[],getElementById:()=>null,addEventListener:(n,f)=>handlers[n]=f};
  const window={addEventListener:(n,f)=>handlers[n]=f,confirm:()=>false};
  vm.runInNewContext(fs.readFileSync('static/keep-refinements.js','utf8'),{document,window,MutationObserver:class{observe(){}},Event:class{constructor(type){this.type=type;}}});
  return {field,button,form,events,handlers,window};
}
test('Save requires a change and becomes disabled when reverted',()=>{
  const f=fixture();assert.equal(f.button.disabled,true);f.field.value='New';f.events.input();assert.equal(f.button.disabled,false);f.field.value='Alex';f.events.input();assert.equal(f.button.disabled,true);
});
test('dirty forms protect leaving, valid native submission releases protection',()=>{
  const f=fixture();f.field.value='New';let blocked=false;f.handlers.beforeunload({preventDefault(){blocked=true;}});assert.equal(blocked,true);
  f.handlers.submit({target:f.form});blocked=false;f.handlers.beforeunload({preventDefault(){blocked=true;}});assert.equal(blocked,false);
});
test('shared refresh guard follows saved form snapshots and clears on reversion or submission',()=>{
  const f=fixture();assert.equal(f.window.keepHasUnsavedChanges(),false);
  f.field.value='New';assert.equal(f.window.keepHasUnsavedChanges(),true);
  f.field.value='Alex';assert.equal(f.window.keepHasUnsavedChanges(),false);
  f.field.value='New';f.handlers.submit({target:f.form});
  assert.equal(f.window.keepHasUnsavedChanges(),false);
});
test('connection tests require confirmation when edits differ from saved settings',()=>{
  const f=fixture();f.form.dataset.savedTest='true';f.field.value='New';let prevented=false;
  f.window.confirm=()=>false;
  f.handlers.submit({target:f.form,submitter:{value:'radarr'},preventDefault(){prevented=true;}});
  assert.equal(prevented,true);
  let blocked=false;f.handlers.beforeunload({preventDefault(){blocked=true;}});assert.equal(blocked,true);
  prevented=false;f.window.confirm=()=>true;
  f.handlers.submit({target:f.form,submitter:{value:'radarr'},preventDefault(){prevented=true;}});
  assert.equal(prevented,false);
  blocked=false;f.handlers.beforeunload({preventDefault(){blocked=true;}});assert.equal(blocked,false);
});
test('saved-only test confirmation still runs when the test button bypasses validation',()=>{
  const f=fixture();f.form.dataset.savedTest='true';f.field.value='New';f.form.checkValidity=()=>false;
  let confirmed=false,prevented=false;f.window.confirm=()=>{confirmed=true;return false;};
  f.handlers.submit({target:f.form,submitter:{value:'radarr',formNoValidate:true},preventDefault(){prevented=true;}});
  assert.equal(confirmed,true);assert.equal(prevented,true);
});
test('collection forms are protected even without a save-button dirty-state control',()=>{
  const f=fixture(false);f.field.value='New';f.events.input();
  let blocked=false;f.handlers.beforeunload({preventDefault(){blocked=true;}});assert.equal(blocked,true);
});
test('cancel discard keeps editor open; accepting resets fields',()=>{
  const f=fixture();f.field.value='New';const control={matches:()=>true,getAttribute:()=> 'true',closest:()=>({querySelectorAll:()=>[f.form]})};let stopped=false;
  const event={target:{closest:()=>control},preventDefault(){},stopImmediatePropagation(){stopped=true;}};
  f.handlers.click(event);assert.equal(stopped,true);assert.equal(f.field.value,'New');
  f.window.confirm=()=>true;f.handlers.click(event);assert.equal(f.field.value,'Alex');assert.equal(f.button.disabled,true);
});
test('admin search shows a clear button and restores all rows and focus',()=>{
  const listeners={};
  const input={value:'',addEventListener:(type,fn)=>listeners['input-'+type]=fn,focus(){this.focused=true;}};
  const clear={hidden:true,addEventListener:(type,fn)=>listeners['clear-'+type]=fn};
  const status={textContent:''};
  const rows=[{textContent:'Alex',hidden:false},{textContent:'Bailey',hidden:false}];
  const wrapper={dataset:{searchRows:'.user-card',searchLabel:'users'},
    querySelector:selector=>selector==='input'?input:selector==='.admin-search-clear'?clear:status};
  const document={body:{},querySelector:selector=>selector==='.admin-list-search'?wrapper:null,
    querySelectorAll:selector=>selector==='.user-card'?rows:[],getElementById:()=>null,
    addEventListener:(type,fn)=>listeners['document-'+type]=fn};
  const window={addEventListener:(type,fn)=>listeners['window-'+type]=fn};
  vm.runInNewContext(fs.readFileSync('static/keep-refinements.js','utf8'),{
    document,window,MutationObserver:class{observe(){}},Event:class{constructor(type){this.type=type;}}});
  input.value='alex';
  listeners['input-input']();
  assert.equal(clear.hidden,false);
  assert.equal(rows[0].hidden,false);
  assert.equal(rows[1].hidden,true);
  assert.equal(status.textContent,'1 user');
  listeners['clear-click']();
  assert.equal(input.value,'');
  assert.equal(clear.hidden,true);
  assert.equal(rows[0].hidden,false);
  assert.equal(rows[1].hidden,false);
  assert.equal(input.focused,true);
  input.value='   ';
  listeners['input-input']();
  assert.equal(clear.hidden,false, 'Whitespace remains clearable');
  assert.equal(rows.every(row=>!row.hidden),true);
  input.value='bailey';
  listeners['window-pageshow']();
  assert.equal(clear.hidden,false);
  assert.equal(rows[0].hidden,true);
  assert.equal(rows[1].hidden,false);
  assert.equal(status.textContent,'1 user');
  rows.push({textContent:'Bailey New Plex user',hidden:false});
  listeners['document-keep-users-updated']();
  assert.equal(input.value,'bailey');
  assert.equal(status.textContent,'2 users');
  assert.equal(rows[0].hidden,true);
  assert.equal(rows[2].hidden,false);
});

test('email search matches profile names and aliases regardless of case and retains email matches',()=>{
  const listeners={};
  const input={value:'',addEventListener:(type,fn)=>listeners['input-'+type]=fn,focus(){}};
  const clear={hidden:true,addEventListener:(type,fn)=>listeners['clear-'+type]=fn};
  const status={textContent:''};
  const rows=[
    {textContent:'Alex Johnson alex@example.com Enabled',dataset:{searchText:'alex@example.com Alex Johnson AJ alex_plex'},hidden:false},
    {textContent:'family@example.com Enabled',dataset:{searchText:'family@example.com Bailey Johnson BJ'},hidden:false},
    {textContent:'standalone@example.com Enabled',hidden:false},
  ];
  const wrapper={dataset:{searchRows:'.recipient-row',searchLabel:'email recipients'},
    querySelector:selector=>selector==='input'?input:selector==='.admin-search-clear'?clear:status};
  const document={body:{},querySelector:selector=>selector==='.admin-list-search'?wrapper:null,
    querySelectorAll:selector=>selector==='.recipient-row'?rows:[],getElementById:()=>null,addEventListener(){}};
  vm.runInNewContext(fs.readFileSync('static/keep-refinements.js','utf8'),{
    document,window:{addEventListener(){}},MutationObserver:class{observe(){}},Event:class{}});
  for (const [query,index] of [['JOHNSON',null],[' aj ',0],['ALEX_PLEX',0],['BJ',1],['STANDALONE@EXAMPLE.COM',2]]) {
    input.value=query;
    listeners['input-input']();
    const visible=rows.map((row,i)=>row.hidden?null:i).filter(i=>i!==null);
    assert.deepEqual(visible,index===null?[0,1]:[index]);
    assert.equal(status.textContent,index===null?'2 email recipients':'1 email recipient');
  }
  input.value='missing name';listeners['input-input']();
  assert.equal(rows.every(row=>row.hidden),true);
  assert.match(status.textContent,/No matching email recipients/);
  listeners['clear-click']();
  assert.equal(rows.every(row=>!row.hidden),true);
});

test('save presentation stays neutral until a change and environment-managed buttons stay disabled',()=>{
  const f=fixture();assert.equal(f.button.attrs['data-save-state'],'pristine');
  f.field.value='Changed';f.events.input();assert.equal(f.button.attrs['data-save-state'],'dirty');assert.equal(f.button.disabled,false);
  f.field.value='Alex';f.events.change();assert.equal(f.button.attrs['data-save-state'],'pristine');assert.equal(f.button.disabled,true);
  const managed=fixture(true,true);assert.equal(managed.button.disabled,true);assert.equal(managed.events.input,undefined);assert.equal(managed.window.keepHasUnsavedChanges(),false);
});

function submissionFixture() {
  let document;
  const node=(properties={})=>{
    const attributes=new Map(),classes=new Set();
    return {listeners:{},dataset:{},isConnected:true,disabled:false,...properties,
      classList:{add:name=>classes.add(name),remove:name=>classes.delete(name),contains:name=>classes.has(name)},
      getAttribute:name=>attributes.get(name),setAttribute:(name,value)=>attributes.set(name,value),removeAttribute:name=>attributes.delete(name),
      addEventListener(name,callback,capture=false){(this.listeners[name]||=[]).push({callback,capture});},
      emit(name,event={}){for(const listener of this.listeners[name]||[])listener.callback(event);},
      focus(){document.activeElement=this;}};
  };
  const writes=[],requests=[],submitted=[];
  let stored=null;
  const forms=['notification-email','notification-owner-pushover'].map((key,index)=>{
    const field={name:'setting',type:'text',value:'saved-'+index},button=node({textContent:'Save'});
    const form=node({dataset:{saveKey:key},elements:[field],field,button,valid:true,resets:0,
      querySelector:selector=>selector==='.save-button'||selector==='.save-button[aria-busy="true"]'&&button.getAttribute('aria-busy')==='true'?button:null,
      closest:()=>null,matches:selector=>selector==='[data-saved-test]'&&form.dataset.savedTest==='true',
      checkValidity:()=>form.valid,
      reset(){this.resets++;field.value='saved-'+index;},
      dispatchEvent(event){this.emit(event.type,event);return true;},
      requestSubmit(submitter){requests.push({form:this,submitter});submit(this,submitter);}});
    return form;
  });
  const stay=node(),discard=node();
  const prompt=node({open:false,querySelector:selector=>selector==='[data-stay]'?stay:discard,
    showModal(){this.open=true;},close(){this.open=false;this.emit('close');}});
  document=node({body:{},activeElement:null,documentElement:node(),
    querySelector:()=>null,
    querySelectorAll:selector=>selector==='form[data-save-key]'||selector==='form[data-save-key], form[data-protect-unsaved]'?forms:[],
    getElementById:id=>id==='unsaved-dialog'?prompt:null});
  const window=node({matchMedia:()=>({matches:true}),confirm:()=>false,scrollTo(){}});
  const context={document,window,location:{pathname:'/settings/notifications'},scrollY:120,
    sessionStorage:{getItem:()=>stored,setItem:(key,value)=>{stored=value;writes.push({key,value});},removeItem:()=>{stored=null;}},
    requestAnimationFrame:callback=>callback(),setTimeout:()=>1,
    MutationObserver:class{observe(){}},Event:class{constructor(type,options){this.type=type;Object.assign(this,options);}}};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync('static/keep-interactions.js','utf8'),context);
  vm.runInContext(fs.readFileSync('static/keep-refinements.js','utf8'),context);
  function submit(form,submitter=form.button) {
    document.activeElement=submitter;
    if(!form.noValidate&&!submitter?.formNoValidate&&!form.checkValidity())return null;
    const event={target:form,submitter,defaultPrevented:false,stopped:false,
      preventDefault(){this.defaultPrevented=true;},stopImmediatePropagation(){this.stopped=true;}};
    // Browser order includes window bubbling after all document guards.
    for(const [target,capture] of [[window,true],[document,true],[form,true],[form,false],[document,false],[window,false]]) {
      for(const listener of target.listeners.submit||[]) {
        if(event.stopped)break;
        if(listener.capture===capture)listener.callback(event);
      }
    }
    if(!event.defaultPrevented)submitted.push({form,submitter});
    return event;
  }
  const edit=(form,value)=>{form.field.value=value;form.emit('input',{target:form.field});};
  const escape=()=>{let prevented=false;prompt.emit('cancel',{preventDefault(){prevented=true;}});if(!prevented)prompt.close();};
  return {forms,document,window,prompt,stay,discard,writes,requests,submitted,submit,edit,escape,stored:()=>stored};
}

test('Stay and Escape preserve both drafts and allow retry after a canceled save',()=>{
  for(const cancel of ['stay','escape']) {
    const f=submissionFixture(),[current,other]=f.forms;
    f.edit(current,'email draft');f.edit(other,'pushover draft');
    assert.equal(f.submit(current).defaultPrevented,true);
    assert.equal(f.prompt.open,true);
    assert.equal(current.button.disabled,false);
    assert.equal(current.button.textContent,'Save');
    assert.equal(current.button.getAttribute('aria-busy'),undefined);
    assert.equal(f.stored(),null);assert.equal(f.writes.length,0);
    if(cancel==='stay')f.stay.emit('click');else f.escape();
    assert.equal(f.prompt.open,false);
    assert.equal(current.field.value,'email draft');assert.equal(other.field.value,'pushover draft');
    assert.equal(f.window.keepHasUnsavedChanges(),true);
    f.submit(current);
    assert.equal(f.prompt.open,true,'Retry must reach the unsaved-change guard');
    assert.equal(current.button.disabled,false);
    assert.equal(f.writes.length,0);
  }
});

test('Discard resets only the other dirty form and submits once with the original submitter',()=>{
  const f=submissionFixture(),[current,other]=f.forms;
  f.edit(current,'email draft');f.edit(other,'pushover draft');
  const submitter=current.button;
  f.submit(current,submitter);
  f.discard.emit('click');
  assert.equal(current.field.value,'email draft');assert.equal(current.resets,0);
  assert.equal(other.field.value,'saved-1');assert.equal(other.resets,1);
  assert.equal(other.button.disabled,true);
  assert.equal(f.requests.length,1);assert.equal(f.requests[0].submitter,submitter);
  assert.equal(f.submitted.length,1);assert.equal(f.submitted[0].submitter,submitter);
  assert.equal(current.button.disabled,true);assert.equal(current.button.textContent,'Saving…');
  assert.equal(f.writes.length,1);
  const feedback=JSON.parse(f.writes[0].value);
  assert.equal(feedback.key,'notification-email');
  assert.deepEqual(Object.keys(feedback).sort(),['at','key','path','scroll']);
  assert.equal(f.window.keepHasUnsavedChanges(),false);
});

test('saved-setting confirmation cancellation retains dirty protection and never marks Saving',()=>{
  const f=submissionFixture(),current=f.forms[0];
  current.dataset.savedTest='true';current.button.value='smtp';
  f.edit(current,'email draft');
  assert.equal(f.submit(current).defaultPrevented,true);
  assert.equal(current.button.disabled,false);assert.equal(current.button.textContent,'Save');
  assert.equal(f.window.keepHasUnsavedChanges(),true);assert.equal(f.writes.length,0);
});

test('native validation and target-capture cancellation preserve an enabled dirty Save',()=>{
  const f=submissionFixture(),current=f.forms[0];f.edit(current,'email draft');
  current.valid=false;
  assert.equal(f.submit(current),null);
  assert.equal(current.button.disabled,false);assert.equal(f.writes.length,0);
  current.valid=true;
  current.addEventListener('submit',event=>event.preventDefault(),true);
  assert.equal(f.submit(current).defaultPrevented,true);
  assert.equal(current.button.textContent,'Save');assert.equal(current.button.disabled,false);
  assert.equal(f.window.keepHasUnsavedChanges(),true);assert.equal(f.writes.length,0);
});

test('normal submission stores once despite same-turn duplication and BFcache clears busy state',()=>{
  const f=submissionFixture(),current=f.forms[0];f.edit(current,'email draft');
  assert.equal(f.submit(current).defaultPrevented,false);
  assert.equal(f.submit(current).defaultPrevented,true);
  assert.equal(f.writes.length,1);assert.equal(f.submitted.length,1);
  assert.equal(current.button.disabled,true);assert.equal(current.button.textContent,'Saving…');
  f.window.emit('pageshow',{persisted:true});
  assert.equal(current.button.disabled,false);assert.equal(current.button.textContent,'Save');
  assert.equal(current.button.getAttribute('aria-busy'),undefined);assert.equal(f.stored(),null);
  assert.equal(f.submit(current).defaultPrevented,false);
  assert.equal(f.writes.length,2);assert.equal(f.submitted.length,2);
});
