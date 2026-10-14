const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');

function fixture(options={}) {
  const el=(props={})=>({listeners:{},hidden:false,disabled:false,...props,
    addEventListener(name,cb,capture=false){(this.listeners[name]||=[]).push({cb,capture});},
    emit(name,event={}){for(const listener of [...(this.listeners[name]||[])].sort((a,b)=>Number(b.capture)-Number(a.capture)))listener.cb(event);},
    focus(settings){this.focusSettings=settings;},scrollIntoView(settings){this.scrollSettings=settings;}});
  const mode=el({value:options.mode||'keep',disabled:options.managed||false}),input=el({value:''});
  const replacement=el({querySelector:()=>input}),secret={querySelector:s=>s==='[data-secret-mode]'?mode:replacement};
  const confirm=el({checked:false}),retry=el(),discard=el(),error=el({hidden:true,textContent:'Confirm the possible duplicate before resending.'});
  const review=el({querySelector:s=>s==='[data-review-confirm]'?confirm:s==='[data-review-retry]'?retry:error});
  const button=el({textContent:'Send me a test',disabled:options.disabledTest||false}),testForm=el({querySelector:()=>button});
  const topics=[el({checked:options.noTopics?false:true,disabled:options.disabledTopics||false}),el({checked:false,disabled:options.disabledTopics||false})];
  const topicError=el({textContent:'Choose at least one email topic.'}),topicSave=el(),classes=new Set();
  const subscriptions=el({querySelectorAll:()=>topics,querySelector:s=>s==='.subscription-error'?topicError:topicSave,
    classList:{toggle(name,value){value?classes.add(name):classes.delete(name);},contains:name=>classes.has(name)}});
  const providers=[el({id:'notification-email',open:false}),el({id:'notification-pushover',open:false})];
  // Existing Save behavior is registered before this page controller's defer script.
  subscriptions.addEventListener('submit',event=>{if(!event.defaultPrevented)topicSave.disabled=true;});
  const serverError=options.serverError?el({textContent:options.serverError}):null,toasts=[];
  const window=el({matchMedia:()=>({matches:options.reducedMotion||false}),
    ...(options.noToast?{}:{showToast:(message,tone)=>toasts.push([message,tone])})});
  const document={body:{classList:{contains:name=>name==='notifications-ui'&&options.notificationsPage!==false}},
    getElementById:id=>id==='settings-error-notice'?serverError:null,
    querySelector:s=>s==='#settings-error-notice'?serverError:null,
    querySelectorAll:s=>s==='details.notification-provider'?providers:s==='.subscriptions'?[subscriptions]:s==='[data-secret-control]'?[secret]:s==='[data-delivery-review]'?[review]:s==='[data-notification-test]'?[testForm]:[]};
  vm.runInNewContext(fs.readFileSync('static/keep-notifications.js','utf8'),{document,window});
  const submit=(form,submitter)=>{let prevented=false;form.emit('submit',{submitter,get defaultPrevented(){return prevented;},preventDefault(){prevented=true;}});return prevented;};
  return {mode,input,replacement,confirm,retry,discard,error,review,button,testForm,window,submit,topics,topicError,topicSave,subscriptions,providers,serverError,toasts};
}
test('server notification errors use a red toast and hide the redundant inline banner',()=>{
  const f=fixture({serverError:'  Check the Pushover settings and try again.  '});
  assert.deepEqual(f.toasts,[['Check the Pushover settings and try again.','error']]);
  assert.equal(f.serverError.hidden,true);
});
test('server notification errors remain inline when the shared toast helper is unavailable',()=>{
  const f=fixture({serverError:'Check the Pushover settings and try again.',noToast:true});
  assert.equal(f.serverError.hidden,false);
  assert.deepEqual(f.toasts,[]);
});
test('clean notification pages do not emit a toast',()=>{
  const f=fixture();assert.deepEqual(f.toasts,[]);
});
test('notification error handling leaves other pages unchanged',()=>{
  const f=fixture({serverError:'Other page error.',notificationsPage:false});
  assert.deepEqual(f.toasts,[]);assert.equal(f.serverError.hidden,false);
});
test('empty recipient topics show a red toast while retaining field guidance and focus',()=>{
  const f=fixture({noTopics:true});
  assert.equal(f.submit(f.subscriptions,f.topicSave),true);
  assert.deepEqual(f.toasts,[['Choose at least one email topic.','error']]);
  assert.equal(f.subscriptions.classList.contains('invalid'),true);
  assert.equal(f.topics[0].focusSettings.preventScroll,true);
  assert.equal(f.topicSave.disabled,false);
});
test('duplicate confirmation errors show a red toast and remain actionable beside the checkbox',()=>{
  const f=fixture();
  assert.equal(f.submit(f.review,f.retry),true);
  assert.deepEqual(f.toasts,[['Confirm the possible duplicate before resending.','error']]);
  assert.equal(f.error.hidden,false);
  assert.equal(f.confirm.focusSettings.preventScroll,true);
  f.confirm.checked=true;f.confirm.emit('change');
  assert.equal(f.submit(f.review,f.retry),false);
  assert.equal(f.error.hidden,true);
  assert.equal(f.toasts.length,1);
});
test('client validation still blocks invalid submissions without a toast helper',()=>{
  const f=fixture({noTopics:true,noToast:true});
  assert.equal(f.submit(f.subscriptions,f.topicSave),true);
  assert.equal(f.subscriptions.classList.contains('invalid'),true);
  assert.equal(f.submit(f.review,f.retry),true);
  assert.equal(f.error.hidden,false);
});
test('native invalid fields reveal only their containing provider disclosure',()=>{
  const f=fixture();
  assert.equal(f.providers.every(provider=>!provider.open),true);
  assert.equal(f.providers[1].listeners.invalid[0].capture,true,'Native invalid events do not bubble');
  f.providers[1].emit('invalid',{target:f.input});
  assert.equal(f.providers[1].open,true);
  assert.equal(f.providers[0].open,false);
});
test('collapsing and reopening a provider preserves a typed credential and replacement mode',()=>{
  const f=fixture({mode:'replace'}),provider=f.providers[1];
  f.input.value='synthetic-unsaved-token';
  provider.open=true;provider.emit('toggle');
  provider.open=false;provider.emit('toggle');
  assert.equal(f.input.value,'synthetic-unsaved-token');
  assert.equal(f.mode.value,'replace');
  assert.equal(f.input.disabled,false);
  provider.open=true;provider.emit('toggle');
  assert.equal(f.input.value,'synthetic-unsaved-token');
  assert.equal(f.replacement.hidden,false);
});
test('saved app token is hidden and excluded unless replacement is selected',()=>{
  const f=fixture();assert.equal(f.input.disabled,true);assert.equal(f.replacement.hidden,true);f.mode.value='replace';f.mode.emit('change');assert.equal(f.input.disabled,false);assert.equal(f.replacement.hidden,false);
});
test('leaving replacement mode clears a typed app token',()=>{
  const f=fixture({mode:'replace'});f.input.value='synthetic-draft-token';f.mode.value='clear';f.mode.emit('change');assert.equal(f.input.value,'');assert.equal(f.input.disabled,true);
});
test('environment-managed app token has no writable replacement field',()=>{
  const f=fixture({mode:'replace',managed:true});assert.equal(f.input.disabled,true);assert.equal(f.replacement.hidden,true);
});
test('Resend requires duplicate confirmation and focuses the confirmation control',()=>{
  const f=fixture();assert.equal(f.submit(f.review,f.retry),true);assert.equal(f.error.hidden,false);assert.equal(f.confirm.focusSettings.preventScroll,true);
  f.confirm.checked=true;f.confirm.emit('change');assert.equal(f.error.hidden,true);assert.equal(f.submit(f.review,f.retry),false);
});
test('Discard remains available without consenting to resend',()=>{
  const f=fixture();assert.equal(f.submit(f.review,f.discard),false);assert.equal(f.error.hidden,true);
});
test('saved-credential test prevents duplicate submits and resets after page restoration',()=>{
  const f=fixture();assert.equal(f.submit(f.testForm,f.button),false);assert.equal(f.button.disabled,true);assert.equal(f.button.textContent,'Sending…');assert.equal(f.submit(f.testForm,f.button),true);
  f.window.emit('pageshow');assert.equal(f.button.disabled,false);assert.equal(f.button.textContent,'Send me a test');assert.equal(f.submit(f.testForm,f.button),false);
});
test('unavailable test stays disabled after restoration and refuses programmatic submit',()=>{
  const f=fixture({disabledTest:true});assert.equal(f.submit(f.testForm,f.button),true);f.window.emit('pageshow');assert.equal(f.button.disabled,true);
});
test('page restoration resynchronizes app-token mode and clears stale review errors',()=>{
  const f=fixture();f.mode.value='replace';f.error.hidden=false;f.window.emit('pageshow');assert.equal(f.input.disabled,false);assert.equal(f.error.hidden,true);
});
test('empty recipient collections are blocked before the shared Save handler disables its button',()=>{
  const f=fixture({noTopics:true});assert.equal(f.submit(f.subscriptions,f.topicSave),true);assert.equal(f.topicSave.disabled,false);assert.equal(f.subscriptions.classList.contains('invalid'),true);assert.equal(f.topics[0].focusSettings.preventScroll,true);
});
test('choosing a collection clears the immediate error and allows the ordinary saved form submission',()=>{
  const f=fixture({noTopics:true});f.submit(f.subscriptions,f.topicSave);f.topics[0].checked=true;f.topics[0].emit('change');assert.equal(f.subscriptions.classList.contains('invalid'),false);assert.equal(f.submit(f.subscriptions,f.topicSave),false);assert.equal(f.topicSave.disabled,true);
});
test('disabled recipient topics cannot produce an enabled saved subscription',()=>{
  const f=fixture({disabledTopics:true});assert.equal(f.submit(f.subscriptions,f.topicSave),true);assert.equal(f.topicSave.disabled,false);assert.equal(f.topics[0].focusSettings,undefined);
});
test('invalid collection guidance respects reduced motion while preserving focus',()=>{
  const f=fixture({noTopics:true,reducedMotion:true});f.submit(f.subscriptions,f.topicSave);assert.equal(f.topicError.scrollSettings.behavior,'instant');assert.equal(f.topics[0].focusSettings.preventScroll,true);
});
