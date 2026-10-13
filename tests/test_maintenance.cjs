const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/keep-maintenance.js'),'utf8');
const requestId='10000000-0000-4000-8000-000000000001';
const otherId='10000000-0000-4000-8000-000000000002';
const base=changes=>({supported:true,enrolled:true,helper_available:true,can_install:true,can_restart:true,reason:'ready',installed_version:'2.25.0',latest_version:'2.26.0',confirmation:'a'.repeat(64),operation:null,...changes});
const operation=changes=>({request_id:requestId,operation:'install',state:'queued',phase:'queued',sequence:null,target_version:'2.26.0',...changes});
const running=changes=>base({can_install:false,can_restart:false,reason:'busy',operation:operation(),...changes});
async function settle(){for(let i=0;i<14;i++)await Promise.resolve();}
function fixture(options={}){
  let now=1000000,document,timerId=0,reloads=0,idsCreated=0;
  const timers=new Map(),calls=[],toasts=[],stored=new Map(options.pendingId?[['keep-maintenance-request',options.pendingId]]:[]);
  class ClockDate extends Date{static now(){return now;}}
  class Element{
    constructor(){this.attrs={};this.listeners={};this.hidden=false;this.disabled=false;this.open=false;this.value='';this._text='';this.classes=new Set();
      this.classList={toggle:(name,on)=>on?this.classes.add(name):this.classes.delete(name),contains:name=>this.classes.has(name)};}
    set innerHTML(_){throw Error('No HTML interpretation');}
    set textContent(value){this._text=String(value);}get textContent(){return this._text;}
    setAttribute(name,value){this.attrs[name]=value;}getAttribute(name){return this.attrs[name]??null;}
    addEventListener(name,fn){(this.listeners[name]||=[]).push(fn);}
    async fire(name,extra={}){const event={target:this,defaultPrevented:false,preventDefault(){this.defaultPrevented=true;},...extra};await Promise.all((this.listeners[name]||[]).map(fn=>fn(event)));return event;}
    focus(settings){document.activeElement=this;this.focusSettings=settings;}
    showModal(){this.open=true;}close(){this.open=false;void this.fire('close');}
  }
  document=new Element();document.hidden=options.hidden||false;document.activeElement=null;
  const ids={};
  for(const name of ['maintenance-snapshot','maintenance-confirm','maintenance-confirm-form','maintenance-install','maintenance-restart',
    'maintenance-refresh','maintenance-feedback','maintenance-actions','maintenance-reason','maintenance-guide','maintenance-operation',
    'maintenance-operation-title','maintenance-phase','maintenance-reload','maintenance-confirm-submit','maintenance-confirm-title',
    'maintenance-confirm-description','maintenance-confirm-cancel','maintenance-csrf','maintenance-title','about-comparison'])ids[name]=new Element();
  ids['maintenance-actions'].hidden=true;ids['maintenance-feedback'].hidden=true;ids['maintenance-install'].disabled=ids['maintenance-restart'].disabled=true;
  ids['maintenance-csrf'].value='synthetic-csrf';ids['maintenance-snapshot'].textContent=options.json??JSON.stringify(options.snapshot||base());
  document.getElementById=name=>ids[name]||null;
  ids['about-comparison'].attrs['data-comparison']=options.comparison||'unknown';
  const window=new Element();window.events=[];window.dispatchEvent=event=>{window.events.push(event.type);return true;};if(options.toast)window.showToast=(message,tone)=>toasts.push({message,tone});window.location={reload(){reloads++;}};
  window.crypto=options.crypto===false?null:options.crypto==='fallback'?{getRandomValues(bytes){bytes.fill(1);return bytes;}}:{randomUUID(){idsCreated++;return idsCreated===1?requestId:otherId;}};
  window.sessionStorage={getItem(key){if(options.storageFailure==='read')throw Error('Blocked');return stored.get(key)||null;},
    setItem(key,value){if(options.storageFailure==='write')throw Error('Blocked');stored.set(key,value);},
    removeItem(key){stored.delete(key);}};
  const fetch=(url,settings)=>{let resolve,reject;const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});settings.signal.addEventListener('abort',()=>reject(Error('Aborted')),{once:true});calls.push({url,settings,resolve,reject});return promise;};
  vm.runInNewContext(source,{document,window,CustomEvent:class{constructor(type){this.type=type;}},fetch:options.fetchAvailable===false?undefined:fetch,AbortController,Date:ClockDate,Uint8Array,
    setTimeout(fn,delay){const key=++timerId;timers.set(key,{fn,due:now+delay});return key;},clearTimeout:key=>timers.delete(key)});
  return {ids,document,window,calls,timers,toasts,stored,reloads:()=>reloads,idsCreated:()=>idsCreated,
    respond(index,status,body,extra={}){calls[index].resolve({ok:status>=200&&status<300,status,redirected:false,json:async()=>body,...extra});},
    fail(index){calls[index].reject(Error('offline'));},
    async advance(ms){now+=ms;const ready=[...timers].filter(([,timer])=>timer.due<=now);for(const [key,timer]of ready){timers.delete(key);timer.fn();}await settle();},
    async open(action='install'){await ids[`maintenance-${action}`].fire('click');},
    async start(next=running(),status=202,extra={}){await this.open();const posting=ids['maintenance-confirm-form'].fire('submit');await settle();const index=calls.length-1;this.respond(index,status,{snapshot:next,...extra});await posting;await settle();},
    async poll(next,extra={}){await this.advance(2000);this.respond(calls.length-1,200,{snapshot:next,...extra});await settle();}
  };
}
test('ready enrolled capability displays controls without making a request',()=>{
  const f=fixture();assert.equal(f.calls.length,0);assert.equal(f.ids['maintenance-actions'].hidden,false);assert.equal(f.ids['maintenance-install'].disabled,false);assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-guide'].hidden,true);
});
test('unsupported or unenrolled runtime never exposes an active maintenance control',async()=>{
  for(const changes of [{supported:false,enrolled:false,can_install:false,can_restart:false,reason:'unsupported'},
    {enrolled:false,can_install:false,can_restart:false,reason:'not_enrolled'}]){
    const f=fixture({snapshot:base(changes)});assert.equal(f.ids['maintenance-actions'].hidden,true);assert.equal(f.ids['maintenance-guide'].hidden,false);await f.open();assert.equal(f.ids['maintenance-confirm'].open,false);assert.equal(f.calls.length,0);
  }
});
test('native host capability cannot be inferred from invalid contradictory flags',async()=>{
  const f=fixture({snapshot:base({supported:false})});await f.open();assert.equal(f.ids['maintenance-actions'].hidden,true);assert.equal(f.calls.length,0);
});
test('confirmed helper unavailability remains locked while its heartbeat recovers automatically through GET',async()=>{
  const f=fixture({snapshot:base({helper_available:false,can_install:false,can_restart:false,reason:'helper_unavailable'})});assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-refresh'].hidden,true);
  await f.advance(2000);assert.equal(f.calls[0].url,'/settings/about/maintenance/status');assert.equal(f.calls[0].settings.method,undefined);
  f.respond(0,200,{snapshot:base({can_install:false,latest_version:null,reason:'target_unavailable'})});await settle();
  assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-install'].hidden,true);assert.equal(f.ids['maintenance-refresh'].hidden,true);assert.equal(f.timers.size,0);
});
test('helper readiness retry is bounded and exposes status recovery only after failure or timeout',async()=>{
  const f=fixture({snapshot:base({helper_available:false,can_install:false,can_restart:false,reason:'helper_unavailable'})});
  await f.advance(2000);f.fail(0);await settle();assert.equal(f.ids['maintenance-refresh'].hidden,false);assert.equal(f.ids['maintenance-restart'].disabled,true);
  assert.equal(f.timers.size,0);await f.ids['maintenance-refresh'].fire('click');await settle();f.respond(1,200,{snapshot:base({helper_available:false,can_install:false,can_restart:false,reason:'helper_unavailable'})});await settle();
  assert.equal(f.ids['maintenance-refresh'].hidden,true);await f.advance(300000);assert.equal(f.ids['maintenance-refresh'].hidden,false);assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.timers.size,0);
});
test('a background capability read does not temporarily disable an already verified Restart action',async()=>{
  const f=fixture();await f.window.fire('keep-release-updated');await settle();assert.equal(f.calls.length,1);assert.equal(f.ids['maintenance-restart'].disabled,false);
  f.respond(0,200,{snapshot:base({can_restart:false,can_install:false,reason:'busy'})});await settle();assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-refresh'].hidden,true);
});
test('a failed idle capability read requires a confirmed status recovery before another action',async()=>{
  const f=fixture();await f.window.fire('keep-release-updated');await settle();f.fail(0);await settle();
  assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-refresh'].hidden,false);
  await f.ids['maintenance-refresh'].fire('click');await settle();
  assert.equal(f.calls.length,2);assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-install'].disabled,true);
  await f.open('restart');assert.equal(f.ids['maintenance-confirm'].open,false);assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,0);
  f.respond(1,200,{snapshot:base()});await settle();
  assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-refresh'].hidden,true);
});
test('returning to a visible or restored page retains the recovery lock until its GET succeeds',async()=>{
  for(const restore of ['visibilitychange','pageshow']){
    const f=fixture();await f.window.fire('keep-release-updated');await settle();f.fail(0);await settle();
    if(restore==='pageshow'){await f.window.fire('pagehide');await f.window.fire('pageshow');}
    else{f.document.hidden=false;await f.document.fire('visibilitychange');}
    await settle();assert.equal(f.calls.length,2);assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-install'].disabled,true);
    await f.open('restart');assert.equal(f.ids['maintenance-confirm'].open,false);
    f.respond(1,200,{snapshot:base()});await settle();assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-refresh'].hidden,true);
  }
});
test('a verified enrolled installation may restart without exposing an unverified update',async()=>{
  const f=fixture({snapshot:base({can_install:false,latest_version:null,reason:'target_unavailable'})});assert.equal(f.ids['maintenance-install'].hidden,true);assert.equal(f.ids['maintenance-restart'].disabled,false);await f.open('restart');assert.equal(f.ids['maintenance-confirm-description'].textContent,'Restart Keep 2.25.0?');
});
test('confirmation names the concrete server target and cancellation does not create a request',async()=>{
  const f=fixture();await f.open();assert.equal(f.ids['maintenance-confirm'].open,true);assert.equal(f.ids['maintenance-confirm-description'].textContent,'Install Keep 2.26.0?');assert.equal(f.document.activeElement,f.ids['maintenance-confirm-cancel']);
  await f.ids['maintenance-confirm-cancel'].fire('click');assert.equal(f.document.activeElement,f.ids['maintenance-install']);assert.equal(f.calls.length,0);assert.equal(f.idsCreated(),0);assert.equal(f.stored.size,0);
});
test('restart confirmation uses the installed version and fixed restart operation',async()=>{
  const f=fixture();await f.open('restart');assert.equal(f.ids['maintenance-confirm-description'].textContent,'Restart Keep 2.25.0?');const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();assert.equal(JSON.parse(f.calls[0].settings.body).operation,'restart');f.respond(0,202,{snapshot:running({operation:operation({operation:'restart',target_version:'2.25.0'})})});await posting;
});
test('confirmed action persists only its nonsecret request UUID before a CSRF-bound fixed JSON POST',async()=>{
  const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();const call=f.calls[0];
  assert.equal(f.stored.get('keep-maintenance-request'),requestId);assert.equal(call.url,'/settings/about/maintenance/start');assert.equal(call.settings.credentials,'same-origin');assert.equal(call.settings.headers['X-CSRF-Token'],'synthetic-csrf');
  assert.deepEqual(JSON.parse(call.settings.body),{request_id:requestId,operation:'install',confirmation:'a'.repeat(64)});assert.equal(f.ids['maintenance-confirm'].open,false);assert.equal(f.document.activeElement,f.ids['maintenance-feedback']);
  f.respond(0,202,{snapshot:running()});await posting;assert.equal(f.ids['maintenance-restart'].disabled,true);
});
test('another confirm submit while a request is in flight cannot create a second POST',async()=>{
  const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();await f.ids['maintenance-confirm-form'].fire('submit');await f.open();assert.equal(f.calls.length,1);f.respond(0,202,{snapshot:running()});await posting;
});
test('confirmation keeps keyboard focus inside in both directions',async()=>{
  const f=fixture();await f.open();const dialog=f.ids['maintenance-confirm'];
  let event=await dialog.fire('keydown',{key:'Tab',shiftKey:true});
  assert.equal(event.defaultPrevented,true);assert.equal(f.document.activeElement,f.ids['maintenance-confirm-submit']);
  event=await dialog.fire('keydown',{key:'Tab'});
  assert.equal(event.defaultPrevented,true);assert.equal(f.document.activeElement,f.ids['maintenance-confirm-cancel']);
  event=await dialog.fire('keydown',{key:'Tab'});assert.equal(event.defaultPrevented,false);
  dialog.close();event=await dialog.fire('keydown',{key:'Tab',shiftKey:true});assert.equal(event.defaultPrevented,false);
});
test('storage failures or missing crypto prevent actions and expose the manual guide',async()=>{
  for(const options of [{storageFailure:'read'},{storageFailure:'write'},{crypto:false}]){
    const f=fixture(options);await f.open();await f.ids['maintenance-confirm-form'].fire('submit');assert.equal(f.calls.length,0);assert.equal(f.ids['maintenance-guide'].hidden,false);assert.equal(f.ids['maintenance-restart'].disabled,true);
  }
});
test('secure random-value fallback supports canonical UUIDs on supported browser contexts',async()=>{
  const f=fixture({crypto:'fallback'});await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();const body=JSON.parse(f.calls[0].settings.body);assert.match(body.request_id,/^01010101-0101-4101-8101-010101010101$/);f.respond(0,202,{snapshot:running({operation:operation({request_id:body.request_id})})});await posting;
});
test('queued progress follows the original request ID and never sends a polling POST',async()=>{
  const f=fixture();await f.start();await f.poll(running({operation:operation({state:'claimed',phase:'backing-up',sequence:5})}));assert.equal(f.calls[1].url,`/settings/about/maintenance/status?request_id=${requestId}`);assert.equal(f.calls[1].settings.method,undefined);assert.equal(f.ids['maintenance-phase'].textContent,'Saving backup');assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,1);
});
test('success requires matching recorded completion before unlocking and offers a page reload',async()=>{
  const f=fixture();await f.start();const complete=base({installed_version:'2.26.0',can_install:false,operation:operation({state:'completed',phase:'success',sequence:10}),requested_request_id:requestId,request_state:'completed'});await f.poll(complete);
  assert.equal(f.stored.size,0);assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-reload'].hidden,false);assert.equal(f.ids['maintenance-feedback'].textContent,'Keep 2.26.0 is ready.');assert.equal(f.timers.size,0);await f.ids['maintenance-reload'].fire('click');assert.equal(f.reloads(),1);
  assert.deepEqual(f.window.events,['keep-maintenance-completed']);assert.equal(f.ids['maintenance-refresh'].hidden,true);
});
test('the durable commit boundary remains in progress until final host completion is recorded',async()=>{
  const f=fixture();await f.start();await f.poll(base({operation:operation({state:'completed',phase:'committed',sequence:9}),requested_request_id:requestId,request_state:'completed'}));
  assert.equal(f.stored.get('keep-maintenance-request'),requestId);assert.equal(f.ids['maintenance-phase'].textContent,'Finishing');assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.timers.size>0,true);
  await f.poll(base({installed_version:'2.26.0',operation:operation({state:'completed',phase:'success',sequence:10}),requested_request_id:requestId,request_state:'completed'}));assert.equal(f.stored.size,0);assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.timers.size,0);
});
test('busy recorded gate without an operation still watches status and never permits a host action',async()=>{
  const f=fixture({snapshot:base({can_install:false,can_restart:false,reason:'busy'})});assert.equal(f.ids['maintenance-restart'].disabled,true);assert.equal(f.ids['maintenance-refresh'].hidden,true);await f.advance(2000);assert.equal(f.calls[0].settings.method,undefined);assert.equal(f.calls[0].url,'/settings/about/maintenance/status');
});
test('an uncertain transport retains the UUID and resolves through GET rather than replay',async()=>{
  const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();f.fail(0);await posting;assert.equal(f.stored.get('keep-maintenance-request'),requestId);assert.equal(f.ids['maintenance-restart'].disabled,true);
  await f.poll(running({requested_request_id:requestId,request_state:'queued'}));assert.equal(f.ids['maintenance-phase'].textContent,'Waiting to start');assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,1);
});
test('a verified not_received response is the only null-operation result that unlocks an uncertain request',async()=>{
  const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();f.fail(0);await posting;
  await f.poll(base());assert.equal(f.ids['maintenance-install'].disabled,true);assert.equal(f.stored.get('keep-maintenance-request'),requestId);
  await f.poll(base({requested_request_id:otherId,request_state:'not_received'}));assert.equal(f.ids['maintenance-install'].disabled,true);
  await f.poll(base({requested_request_id:requestId,request_state:'unknown'}));assert.equal(f.ids['maintenance-install'].disabled,true);
  await f.poll(base({requested_request_id:requestId,request_state:'not_received'}));assert.equal(f.ids['maintenance-install'].disabled,false);assert.equal(f.stored.size,0);assert.match(f.ids['maintenance-feedback'].textContent,/not received/);
});
test('a confirmed HTTP rejection still reconciles recorded state before permitting another action',async()=>{
  const f=fixture();await f.start(base(),409,{error:'The available update changed. Review it again.'});assert.equal(f.ids['maintenance-install'].disabled,true);assert.match(f.ids['maintenance-feedback'].textContent,/available update changed/);
  await f.poll(base({requested_request_id:requestId,request_state:'not_received'}));assert.equal(f.ids['maintenance-install'].disabled,false);assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,1);
});
test('an aborted recorded request unlocks only its matching UUID and never reports update success',async()=>{
  const f=fixture();await f.start();await f.poll(base({operation:operation({state:'aborted'}),requested_request_id:requestId,request_state:'aborted'}));assert.equal(f.stored.size,0);assert.equal(f.ids['maintenance-restart'].disabled,false);assert.equal(f.ids['maintenance-feedback'].textContent,'Maintenance did not complete.');assert.equal(f.ids['maintenance-reload'].hidden,true);
});
test('timed-out POST aborts transport and continues with the original recorded-state query',async()=>{
  const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();await f.advance(15000);await posting;assert.equal(f.calls[0].settings.signal.aborted,true);await f.advance(2000);assert.equal(f.calls[1].url,`/settings/about/maintenance/status?request_id=${requestId}`);assert.equal(f.idsCreated(),1);
});
test('connection loss during downtime retains progress and announces a successful reconnect',async()=>{
  const f=fixture();await f.start();await f.advance(2000);f.fail(1);await settle();assert.equal(f.ids['maintenance-phase'].textContent,'Waiting to start');assert.match(f.ids['maintenance-feedback'].textContent,/Connection lost/);
  await f.poll(running({operation:operation({state:'claimed',phase:'verifying',sequence:8})}));assert.equal(f.ids['maintenance-phase'].textContent,'Checking Keep');assert.equal(f.ids['maintenance-feedback'].textContent,'Reconnected. Maintenance is in progress.');
});
test('malformed or regressive progress cannot overwrite a confirmed newer stage',async()=>{
  const f=fixture();await f.start(running({operation:operation({state:'claimed',phase:'backing-up',sequence:5})}));await f.poll(running({operation:operation({phase:'pulling',sequence:2})}));assert.equal(f.ids['maintenance-phase'].textContent,'Saving backup');
  await f.poll(running({operation:operation({phase:'<script>alert(1)</script>',sequence:6})}));assert.equal(f.ids['maintenance-phase'].textContent,'Saving backup');assert.equal(f.ids['maintenance-restart'].disabled,true);
});
test('polling stops after five minutes and manual recovery performs only a status GET',async()=>{
  const f=fixture();await f.start();await f.advance(300000);assert.equal(f.timers.size,0);assert.equal(f.ids['maintenance-refresh'].hidden,false);assert.match(f.ids['maintenance-feedback'].textContent,/not confirmed completion/);
  await f.ids['maintenance-refresh'].fire('click');await settle();assert.equal(f.calls[1].settings.method,undefined);assert.equal(f.calls[1].url,`/settings/about/maintenance/status?request_id=${requestId}`);assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,1);
});
test('owner/session expiry stops requests without permitting a retry',async()=>{
  for(const response of [{status:403},{status:200,redirected:true}]){
    const f=fixture();await f.open();const posting=f.ids['maintenance-confirm-form'].fire('submit');await settle();f.respond(0,response.status,null,{redirected:response.redirected||false});await posting;await f.advance(300000);assert.equal(f.calls.length,1);assert.equal(f.ids['maintenance-install'].disabled,true);assert.match(f.ids['maintenance-feedback'].textContent,/sign in again/);assert.equal(f.stored.get('keep-maintenance-request'),requestId);
  }
});
test('page exit and restoration abort reads and recover the original operation without another POST',async()=>{
  const f=fixture();await f.start();await f.advance(2000);await f.window.fire('pagehide');await settle();assert.equal(f.calls[1].settings.signal.aborted,true);assert.equal(f.timers.size,0);await f.window.fire('pageshow');await settle();assert.equal(f.calls[2].url,`/settings/about/maintenance/status?request_id=${requestId}`);assert.equal(f.calls.filter(call=>call.settings.method==='POST').length,1);
});
test('reload with a saved UUID starts a read-only lookup and does not generate a new request',async()=>{
  const f=fixture({pendingId:requestId});await settle();assert.equal(f.calls[0].url,`/settings/about/maintenance/status?request_id=${requestId}`);assert.equal(f.idsCreated(),0);assert.equal(f.ids['maintenance-restart'].disabled,true);
});
test('hidden documents pause progress polling until visible again',async()=>{
  const f=fixture({snapshot:running(),hidden:true});assert.equal(f.calls.length,0);assert.equal(f.timers.size,0);f.document.hidden=false;await f.document.fire('visibilitychange');await settle();assert.equal(f.calls[0].settings.method,undefined);assert.equal(f.calls[0].url,`/settings/about/maintenance/status?request_id=${requestId}`);
});
test('a release check refreshes maintenance capability and invalidates a changed confirmation',async()=>{
  const f=fixture();await f.open();await f.window.fire('keep-release-updated');await settle();f.respond(0,200,{snapshot:base({latest_version:'2.27.0',confirmation:'b'.repeat(64)})});await settle();assert.equal(f.ids['maintenance-confirm'].open,false);assert.equal(f.document.activeElement,f.ids['maintenance-install']);assert.match(f.ids['maintenance-feedback'].textContent,/status changed/);await f.ids['maintenance-confirm-form'].fire('submit');assert.equal(f.calls.length,1);await f.open();assert.equal(f.ids['maintenance-confirm-description'].textContent,'Install Keep 2.27.0?');
});
test('the confirmed operation retains its original target after another latest release is advertised',async()=>{
  const f=fixture();await f.start();await f.poll(running({latest_version:'2.27.0',operation:operation({state:'claimed',phase:'pulling',sequence:2})}));assert.equal(f.ids['maintenance-operation-title'].textContent,'Update to 2.26.0');
});
test('recovery-needed and held states remain locked; verified recovery is never reported as an installed update',async()=>{
  const f=fixture();await f.start();await f.poll(running({operation:operation({state:'claimed',phase:'held',sequence:9})}));assert.equal(f.ids['maintenance-restart'].disabled,true);assert.match(f.ids['maintenance-feedback'].textContent,/needs attention/);
  await f.poll(base({operation:operation({state:'completed',phase:'recovered',sequence:12}),requested_request_id:requestId,request_state:'completed'}));assert.equal(f.ids['maintenance-feedback'].textContent,'The previous version was restored.');assert.equal(f.ids['maintenance-reload'].hidden,true);assert.equal(f.stored.size,0);
});
test('HTML-looking error data stays plain text and injected version data cannot enable actions',async()=>{
  const f=fixture();await f.start(base(),409,{error:'<img onerror=alert(1)>'});assert.equal(f.ids['maintenance-feedback'].textContent,'<img onerror=alert(1)>');assert.equal(f.ids['maintenance-install'].disabled,true);
  const invalid=fixture({snapshot:base({latest_version:'2.26.0\n'})});await invalid.open();assert.equal(invalid.calls.length,0);assert.equal(invalid.ids['maintenance-actions'].hidden,true);
});
test('missing fetch or malformed initial JSON leaves the manual fallback without active controls',async()=>{
  for(const options of [{fetchAvailable:false},{json:'<invalid>'}]){const f=fixture(options);await f.open();assert.equal(f.ids['maintenance-actions'].hidden,true);assert.equal(f.calls.length,0);}
});

test('maintenance acknowledges requests neutrally, preserves progress, and toasts verified completion',async()=>{
  const f=fixture({toast:true});await f.start();assert.equal(f.toasts.at(-1).tone,'neutral');assert.equal(f.ids['maintenance-feedback'].hidden,true);
  assert.equal(f.document.activeElement,f.ids['maintenance-title']);assert.equal(f.ids['maintenance-operation'].hidden,false);assert.equal(f.ids['maintenance-phase'].attrs['data-status'],'neutral');
  await f.poll(base({installed_version:'2.26.0',operation:operation({state:'completed',phase:'success',sequence:10}),requested_request_id:requestId,request_state:'completed'}));
  assert.equal(f.toasts.at(-1).tone,'ok');assert.equal(f.toasts.at(-1).message,'Keep 2.26.0 is ready.');assert.equal(f.ids['maintenance-phase'].attrs['data-status'],'ok');
});
test('maintenance shows up-to-date copy only with a fresh positive release comparison',()=>{
  const snapshot=base({can_install:false,latest_version:null,reason:'target_unavailable'});
  assert.equal(fixture({snapshot,comparison:'up_to_date'}).ids['maintenance-reason'].textContent,'Keep is up to date.');
  assert.equal(fixture({snapshot,comparison:'unknown'}).ids['maintenance-reason'].textContent,'An update is not ready to install.');
});
test('release refresh does not announce a historical maintenance completion',async()=>{
  const snapshot=base({operation:operation({state:'completed',phase:'success',sequence:10})});
  const f=fixture({toast:true,snapshot});await f.window.fire('keep-release-updated');await settle();
  f.respond(0,200,{snapshot});await settle();assert.equal(f.toasts.length,0);
});
