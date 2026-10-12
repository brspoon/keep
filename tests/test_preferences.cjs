const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher, options={}) {
  let document;
  const el = (props={}) => ({listeners:{},hidden:false,disabled:false,...props,
    addEventListener(name, callback){(this.listeners[name] ||= []).push(callback);},
    emit(name,event={}){for(const callback of this.listeners[name]||[]) callback(event);},
    async fire(name,event={}){for(const callback of this.listeners[name]||[]) await callback(event);},
    focus(settings){document.activeElement=this;this.focusSettings=settings;},
    closest(){return null;},setAttribute(){},append(child){this.child=child;}});
  const makeForm = (channel, enabled) => {
    const toggle=el({name:`receive_${channel}`,value:'1',type:'checkbox',checked:enabled});
    const collection=el({name:channel==='email'?'collection_id':'pushover_collection_id',value:'1',type:'checkbox',checked:true});
    const topic=el({name:channel==='email'?'email_event':'pushover_event',value:'MEDIA_ADDED_TO_COLLECTION',type:'checkbox',checked:true});
    const groups=[collection,topic].map(input=>el({disabled:!enabled,inputs:[input],querySelectorAll(){return this.inputs.filter(i=>i.checked);}}));
    const button=el({textContent:channel==='email'?'Save preferences':'Save Pushover'});
    const fields=[{name:'csrf_token',value:'synthetic-csrf'},{name:'action',value:channel},toggle];
    if(channel==='email') fields.push({name:'theme_mode',value:'system'});
    const form=el({action:'http://localhost/preferences',channel,groups,toggle,button,fields,
      querySelector(selector){return selector==='[data-channel-toggle]'?toggle:selector==='.save-button'?button:null;},
      querySelectorAll(selector){return selector==='[data-channel-options]'?groups:[];}});
    return form;
  };
  const secret=()=>{
    const mode=el({name:'key_mode',value:options.configured===false?'replace':'keep'}),input=el({name:'user_key',value:''});
    const replacement=el({querySelector:()=>input});
    const control=el({querySelector:s=>s==='[data-secret-mode]'?mode:replacement});
    return {mode,input,replacement,control};
  };
  const build=()=>{
    const email=makeForm('email',options.emailEnabled??true),push=makeForm('pushover',options.pushEnabled??false),key=secret();
    push.fields.push(key.mode,key.input,{name:'device',value:'phone'});
    const testAction=options.testAction||'test-pushover';
    const button=el({textContent:testAction==='discard-pushover-test'?'Discard test':'Test notification'});
    const testForm=el({action:'http://localhost/preferences',button,fields:[{name:'csrf_token',value:'synthetic-csrf'},{name:'action',value:testAction},...(testAction==='discard-pushover-test'?[{name:'test_id',value:'a'.repeat(32)}]:[])],
      querySelector:s=>s==='.save-button'?button:s===`[name="action"][value="${testAction}"]`?{value:testAction}:null});
    return {email,push,key,testForm};
  };
  let forms=build(),html='',error;
  const trigger=el(),close=el(),cancel=el(),title=el({id:'preferences-title'});
  const content=el({prepend(e){error=e;},
    querySelector(s){return s==='.request-error'?error:s==='form[data-notification-channel]'||s==='form'?forms.email:s==='.notice'&&html==='saved'?{}:null;},
    querySelectorAll(s){return s==='[data-notification-channel]'?[forms.email,forms.push]:s==='[data-secret-control]'?[forms.key.control]:[];}});
  Object.defineProperty(content,'innerHTML',{get:()=>html,set:value=>{html=value;forms=build();}});
  const dialog=el({open:false,showModal(){this.open=true;},close(){this.open=false;this.emit('close');},
    querySelector:s=>s==='.welcome-close'?close:cancel,
    querySelectorAll:()=>[close,forms.email.toggle,forms.key.mode,cancel]});
  const window=el({location:{href:'http://localhost/',origin:'http://localhost'},keepApplyTheme(choice){themeCalls.push(choice);document.documentElement.dataset.theme=choice;}});
  const account={querySelector:s=>s==='.user-links'?{hidden:true}:trigger};
  document={activeElement:{},documentElement:{dataset:{theme:'system'},classList:{add(){},remove(){}}},
    getElementById:id=>({'preferences-open':options.fullPage?null:trigger,'preferences-dialog':dialog,'preferences-content':content,'preferences-title':title,'account-menu':account}[id]),
    querySelectorAll:s=>options.fullPage||dialog.open?content.querySelectorAll(s):[],createElement:()=>el()};
  const calls=[],themeCalls=[],toasts=[];
  class TestFormData {
    constructor(form){this.entries=[];for(const field of form.fields){if(!field.disabled&&(field.type!=='checkbox'||field.checked))this.append(field.name,field.value);}
      for(const group of form.groups||[]){if(!group.disabled)for(const input of group.inputs)if(input.checked&&!input.disabled)this.append(input.name,input.value);}
      form.emit('formdata',{formData:this});}
    append(name,value){this.entries.push([name,value]);}
    getAll(name){return this.entries.filter(([key])=>key===name).map(([,value])=>value);}
  }
  vm.runInNewContext(fs.readFileSync('static/keep-preferences.js','utf8'),{document,window,URL,fetch:(...args)=>{calls.push(args);return fetcher(...args);},FormData:TestFormData,showToast:m=>toasts.push(m)});
  const click=()=>trigger.fire('click',{preventDefault(){}});
  const submit=form=>content.fire('submit',{target:form,preventDefault(){}});
  return {document,window,dialog,content,calls,click,submit,close,cancel,title,themeCalls,toasts,
    get forms(){return forms;},get error(){return error;},data:form=>new TestFormData(form)};
}
const response=(html='form')=>({ok:true,url:'http://localhost/preferences?fragment=1',text:async()=>html});
const success=()=>Promise.resolve(response());
test('first and repeated Preferences clicks open only the authenticated fragment',async()=>{
  const f=fixture(success);await f.click();assert.equal(f.dialog.open,true);assert.equal(f.content.innerHTML,'form');assert.equal(f.calls[0][0],'/preferences?fragment=1');
  f.cancel.emit('click');await f.click();assert.equal(f.calls.length,2);assert.equal(f.dialog.open,true);
});
test('closing while loading discards the stale response',async()=>{
  let finish;const f=fixture(()=>new Promise(resolve=>finish=resolve));const loading=f.click();f.close.emit('click');finish(response());await loading;assert.equal(f.content.innerHTML,'');assert.equal(f.dialog.open,false);
});
test('an authentication redirect remains in the dialog with a safe error',async()=>{
  const f=fixture(async()=>({...response(),url:'http://localhost/login'}));await f.click();assert.equal(f.content.innerHTML,'');assert.match(f.error.textContent,/Could not load/);assert.equal(f.dialog.open,true);
});
test('closing restores the saved appearance after an unsaved preview',async()=>{
  const f=fixture(success);await f.click();f.document.documentElement.dataset.theme='dark';f.cancel.emit('click');assert.equal(f.themeCalls.at(-1),'system');
});
test('Email and Pushover choices toggle independently on the standalone page',()=>{
  const f=fixture(success,{fullPage:true}),{email,push}=f.forms;assert.equal(email.groups[0].disabled,false);assert.equal(push.groups[0].disabled,true);
  push.toggle.checked=true;push.toggle.emit('change');email.toggle.checked=false;email.toggle.emit('change');assert.equal(push.groups[0].disabled,false);assert.equal(email.groups[1].disabled,true);
  assert.equal(email.groups[0].inputs[0].checked,true);assert.equal(push.groups[0].inputs[0].checked,true);
});
test('disabled channel collections and event choices remain in submitted FormData',()=>{
  const f=fixture(success,{fullPage:true,emailEnabled:false,pushEnabled:false});
  const email=f.data(f.forms.email),push=f.data(f.forms.push);assert.deepEqual(email.getAll('collection_id'),['1']);assert.deepEqual(push.getAll('pushover_event'),['MEDIA_ADDED_TO_COLLECTION']);assert.deepEqual(push.getAll('receive_pushover'),[]);
});
test('rebinding does not duplicate listeners or retained choices',()=>{
  const f=fixture(success,{fullPage:true,emailEnabled:false});f.window.keepBindNotificationPreferences(f.document);f.window.keepBindNotificationPreferences(f.document);
  assert.equal(f.forms.email.toggle.listeners.change.length,1);assert.deepEqual(f.data(f.forms.email).getAll('collection_id'),['1']);
});
test('page restoration reapplies both channel and secret mode state',()=>{
  const f=fixture(success,{fullPage:true});f.forms.push.toggle.checked=true;f.forms.push.groups[0].disabled=true;f.forms.key.mode.value='replace';f.window.emit('pageshow');assert.equal(f.forms.push.groups[0].disabled,false);assert.equal(f.forms.key.input.disabled,false);assert.equal(f.forms.key.replacement.hidden,false);
});
test('saved keys stay hidden until replace is selected and switching away clears a typed key',()=>{
  const f=fixture(success,{fullPage:true}),key=f.forms.key;assert.equal(key.replacement.hidden,true);assert.equal(key.input.disabled,true);
  key.mode.value='replace';key.mode.emit('change');key.input.value='synthetic-new-key';assert.equal(key.input.disabled,false);
  key.mode.value='clear';key.mode.emit('change');assert.equal(key.input.value,'');assert.equal(key.input.disabled,true);assert.deepEqual(f.data(f.forms.push).getAll('user_key'),[]);
});
test('Pushover save posts its own fields without Email or appearance values',async()=>{
  const f=fixture(async()=>response(f.calls.length>1?'saved':'form'));await f.click();await f.submit(f.forms.push);const data=f.calls[1][1].body;
  assert.deepEqual(data.getAll('action'),['pushover']);assert.deepEqual(data.getAll('collection_id'),[]);assert.deepEqual(data.getAll('theme_mode'),[]);assert.equal(f.dialog.open,false);assert.deepEqual(f.toasts,['Preferences saved']);
});
test('personal test posts saved-credential action only and does not close as a save',async()=>{
  const f=fixture(async()=>response('test-result'));await f.click();await f.submit(f.forms.testForm);const data=f.calls[1][1].body;
  assert.deepEqual(data.entries,[['csrf_token','synthetic-csrf'],['action','test-pushover']]);assert.equal(f.dialog.open,true);assert.equal(f.toasts.length,0);
  f.forms.push.toggle.checked=true;f.forms.push.toggle.emit('change');assert.equal(f.forms.push.groups[0].disabled,false);
});
test('test feedback never becomes a Preferences saved toast even if an old notice is present',async()=>{
  const f=fixture(async()=>response('saved'));await f.click();await f.submit(f.forms.testForm);assert.equal(f.dialog.open,true);assert.equal(f.toasts.length,0);
});
test('discarding an uncertain test posts only the owned record and stays open without a save toast',async()=>{
  const f=fixture(async()=>response('saved'),{testAction:'discard-pushover-test'});await f.click();await f.submit(f.forms.testForm);
  assert.deepEqual(f.calls[1][1].body.entries,[['csrf_token','synthetic-csrf'],['action','discard-pushover-test'],['test_id','a'.repeat(32)]]);
  assert.equal(f.dialog.open,true);assert.equal(f.toasts.length,0);
});
test('closing during a save discards late success and permits another open',async()=>{
  let finish;let count=0;const f=fixture(()=>++count===2?new Promise(resolve=>finish=resolve):success());await f.click();const pending=f.submit(f.forms.push);f.close.emit('click');finish(response('saved'));await pending;assert.equal(f.toasts.length,0);assert.equal(f.dialog.open,false);await f.click();assert.equal(f.dialog.open,true);
});
test('an in-flight submit blocks another channel or test submission',async()=>{
  let finish;let count=0;const f=fixture(()=>++count===2?new Promise(resolve=>finish=resolve):success());await f.click();const pending=f.submit(f.forms.push);await f.submit(f.forms.testForm);assert.equal(f.calls.length,2);finish(response());await pending;
});
test('failed personal test restores its original button label',async()=>{
  let count=0;const f=fixture(()=>++count===1?success():Promise.reject(Error('offline')));await f.click();const button=f.forms.testForm.button;await f.submit(f.forms.testForm);assert.equal(button.textContent,'Test notification');assert.equal(button.disabled,false);assert.match(f.error.textContent,/Could not confirm/);
});
test('foreign form actions are refused before fetch or credential serialization',async()=>{
  const f=fixture(success);await f.click();f.forms.push.action='https://other.example/preferences';await f.submit(f.forms.push);assert.equal(f.calls.length,1);assert.match(f.error.textContent,/Could not confirm/);
});
test('keyboard focus includes the secret mode select and wraps within the dialog',async()=>{
  const f=fixture(success);await f.click();f.document.activeElement=f.cancel;let prevented=false;f.dialog.emit('keydown',{key:'Tab',preventDefault(){prevented=true;}});assert.equal(prevented,true);assert.equal(f.document.activeElement,f.close);
  f.document.activeElement=f.forms.key.mode;prevented=false;f.dialog.emit('keydown',{key:'Tab',preventDefault(){prevented=true;}});assert.equal(prevented,false);
});
