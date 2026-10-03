const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
function fixture(withSaveButton=true) {
  const handlers={},events={},button=withSaveButton?{disabled:false,getAttribute:()=>null}:null;
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
    querySelectorAll:selector=>selector==='.user-card'?rows:[],getElementById:()=>null,addEventListener(){}};
  const window={addEventListener(){}};
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
});
