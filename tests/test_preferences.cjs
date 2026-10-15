const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher, options={}) {
  let document;
  const el = (props={}) => ({listeners:{},hidden:false,disabled:false,...props,
    addEventListener(name, callback){(this.listeners[name] ||= []).push(callback);},
    emit(name,event={}){for(const callback of this.listeners[name]||[]) callback(event);if(this.parent)this.parent.emit(name,event);},
    async fire(name,event={}){for(const callback of this.listeners[name]||[]) await callback(event);},
    focus(settings){document.activeElement=this;this.focusSettings=settings;},
    closest(selector){this.closestQueries ||= [];this.closestQueries.push(selector);return selector==='[hidden]'&&this.hidden?this:null;},
    matches(selector){return selector===this.tagName?.toLowerCase();},setAttribute(){},append(child){this.child=child;}});
  const makeForm = (channel, enabled) => {
    const toggle=el({name:`receive_${channel}`,value:'1',type:'checkbox',checked:enabled});
    const collectionInputs=(options.collectionChoices??[true]).map((checked,index)=>el({name:channel==='email'?'collection_id':'pushover_collection_id',value:String(index+1),type:'checkbox',checked}));
    const topicInputs=(options.topicChoices??[true]).map((checked,index)=>el({name:channel==='email'?'email_event':'pushover_event',value:index===0?'MEDIA_ADDED_TO_COLLECTION':'MEDIA_ABOUT_TO_BE_HANDLED',type:'checkbox',checked}));
    const groups=[collectionInputs,topicInputs].map(inputs=>el({disabled:!enabled,inputs,querySelectorAll(){return this.inputs.filter(i=>i.checked);}}));
    const sections=groups.map(group=>{
      const selection=el({textContent:''}),summary=el({tagName:'SUMMARY'});
      const section=el({tagName:'DETAILS',open:false,group,selection,summary,
        querySelector:s=>s==='[data-selection-summary]'?selection:s==='summary'?summary:null,
        querySelectorAll:s=>s==='input[type="checkbox"]'?group.inputs:s==='input[type="checkbox"]:checked'?group.inputs.filter(input=>input.checked):[]});
      summary.closest=selector=>selector==='details:not([open])'&&!section.open?section:null;
      section.contains=item=>item===summary||group.inputs.includes(item);
      for(const input of group.inputs){input.parent=section;input.closest=selector=>selector==='details:not([open])'&&!section.open?section:null;}
      return section;
    });
    const button=el({textContent:channel==='email'?'Save preferences':'Save Pushover'});
    const fields=[{name:'csrf_token',value:'synthetic-csrf'},{name:'action',value:channel},toggle];
    if(channel==='email') fields.push({name:'theme_mode',value:'system'});
    const form=el({action:'http://localhost/preferences',getAttribute(name){return name==='action'?(this.actionAttribute??'http://localhost/preferences'):null;},channel,groups,sections,toggle,button,fields,
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
    const testForm=el({action:'http://localhost/preferences',getAttribute(name){return name==='action'?(this.actionAttribute??'http://localhost/preferences'):null;},button,fields:[{name:'csrf_token',value:'synthetic-csrf'},{name:'action',value:testAction},...(testAction==='discard-pushover-test'?[{name:'test_id',value:'a'.repeat(32)}]:[])],
      querySelector:s=>s==='.save-button'?button:s===`[name="action"][value="${testAction}"]`?{value:testAction}:null});
    return {email,push,key,testForm};
  };
  let forms=build(),html='',error;
  const trigger=el(),close=el(),cancel=el(),title=el({id:'preferences-title'});
  const content=el({prepend(e){error=e;},
    querySelector(s){return s==='.request-error'?error:s==='form[data-notification-channel]'||s==='form'?forms.email:s==='.notice'&&html==='saved'?{}:null;},
    querySelectorAll(s){return s==='[data-notification-channel]'?[forms.email,forms.push]:s==='[data-secret-control]'?[forms.key.control]:s==='[data-preference-section]'?forms.email.sections:[];}});
  Object.defineProperty(content,'innerHTML',{get:()=>html,set:value=>{html=value;forms=build();}});
  const dialog=el({open:false,showModal(){this.open=true;},close(){this.open=false;this.emit('close');},
    querySelector:s=>s==='.welcome-close'?close:cancel,
    querySelectorAll:selector=>[close,forms.email.toggle,forms.key.mode,...forms.email.sections.flatMap(section=>[...(selector.includes('summary')?[section.summary]:[]),...section.group.inputs]),forms.email.button,cancel].filter(control=>!control.disabled)});
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
test('collapsed preference sections summarize available checkbox selections independently',()=>{
  const f=fixture(success,{fullPage:true,collectionChoices:[true,true],topicChoices:[true,false]}),[collections,events]=f.forms.email.sections;
  assert.equal(collections.open,false);assert.equal(events.open,false);
  assert.equal(collections.selection.textContent,'All 2 selected');assert.equal(events.selection.textContent,'1 selected');
  events.group.inputs[1].checked=true;events.group.inputs[1].emit('change');
  assert.equal(events.selection.textContent,'All 2 selected');assert.equal(collections.selection.textContent,'All 2 selected');
  collections.group.inputs.forEach(input=>{input.checked=false;input.emit('change');});
  assert.equal(collections.selection.textContent,'None selected');assert.equal(events.selection.textContent,'All 2 selected');
});
test('an empty preference section reports that no choices are available',()=>{
  const f=fixture(success,{fullPage:true,collectionChoices:[]});
  assert.equal(f.forms.email.sections[0].selection.textContent,'None available');
});
test('section summaries rebind once and refresh restored selections without reopening sections',()=>{
  const f=fixture(success,{fullPage:true,collectionChoices:[true,false]}),section=f.forms.email.sections[0];
  f.window.keepBindNotificationPreferences(f.document);f.window.keepBindNotificationPreferences(f.document);
  assert.equal(section.listeners.change.length,1);
  section.group.inputs[1].checked=true;f.window.emit('pageshow');
  assert.equal(section.selection.textContent,'All 2 selected');assert.equal(section.open,false);
  section.group.inputs[0].checked=false;f.window.keepBindNotificationPreferences(f.document);
  assert.equal(section.selection.textContent,'1 selected');assert.equal(section.listeners.change.length,1);
});
test('closed sections preserve their selected form values with email on or off',()=>{
  const f=fixture(success,{fullPage:true,collectionChoices:[true,false,true],topicChoices:[false,true]}),{email}=f.forms;
  for(const enabled of [true,false]){
    email.toggle.checked=enabled;email.toggle.emit('change');
    assert.ok(email.sections.every(section=>!section.open));
    const data=f.data(email);
    assert.deepEqual(data.getAll('collection_id'),['1','3']);
    assert.deepEqual(data.getAll('email_event'),['MEDIA_ABOUT_TO_BE_HANDLED']);
  }
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
  const f=fixture(success);await f.click();f.forms.push.actionAttribute='https://other.example/preferences';await f.submit(f.forms.push);assert.equal(f.calls.length,1);assert.match(f.error.textContent,/Could not confirm/);
});
test('keyboard focus includes the secret mode select and wraps within the dialog',async()=>{
  const f=fixture(success);await f.click();f.document.activeElement=f.cancel;let prevented=false;f.dialog.emit('keydown',{key:'Tab',preventDefault(){prevented=true;}});assert.equal(prevented,true);assert.equal(f.document.activeElement,f.close);
  f.document.activeElement=f.forms.key.mode;prevented=false;f.dialog.emit('keydown',{key:'Tab',preventDefault(){prevented=true;}});assert.equal(prevented,false);
});
test('keyboard focus wraps to closed section summaries and includes their controls only while expanded',async()=>{
  const f=fixture(success);await f.click();
  const section=f.forms.email.sections[1];
  f.cancel.hidden=true;f.forms.email.button.hidden=true;
  const previous=()=>{f.document.activeElement=f.close;let prevented=false;f.dialog.emit('keydown',{key:'Tab',shiftKey:true,preventDefault(){prevented=true;}});assert.equal(prevented,true);};
  previous();assert.equal(f.document.activeElement,section.summary);
  section.open=true;previous();assert.equal(f.document.activeElement,section.group.inputs[0]);
  section.open=false;previous();assert.equal(f.document.activeElement,section.summary);
});

test('the hidden action control cannot shadow the Preferences submission URL',async()=>{
  const f=fixture(async()=>response(f.calls.length>1?'saved':'form'));await f.click();
  f.forms.email.action={name:'action',value:'email',toString:()=> '[object HTMLInputElement]'};
  await f.submit(f.forms.email);
  assert.equal(f.calls.length,2);assert.equal(f.calls[1][0],'/preferences?fragment=1');
  assert.deepEqual(f.calls[1][1].body.getAll('action'),['email']);
  assert.equal(f.dialog.open,false);assert.deepEqual(f.toasts,['Preferences saved']);
});
