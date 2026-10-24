const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/keep-plex-users.js'),'utf8');
const baseline=changes=>({id:'plex-access-sync',status:'success',queued:false,can_run:true,label:'Completed',result:'Completed',
  action_reason:null,last_run:'2026-10-24T12:00:00Z',last_success:'2026-10-24T12:00:00Z',last_attempt_status:'success',...changes});
const queued=changes=>baseline({status:'queued',queued:true,can_run:false,label:'Queued',...changes});
const running=changes=>baseline({status:'running',can_run:false,label:'Running',last_run:null,...changes});
const complete=changes=>baseline({last_run:'2026-10-24T12:01:00Z',last_success:'2026-10-24T12:01:00Z',...changes});
async function settle(){for(let i=0;i<18;i++)await Promise.resolve();}
function fixture({job=baseline(),initialJson,hidden=false,fetchAvailable=true,abortAvailable=true,toast=true,ignoreAbort=false,listAvailable=true}={}){
  let now=Date.parse('2026-10-24T12:00:00Z'),nextTimer=0;
  const timers=new Map(),calls=[],listCalls=[],toasts=[],navigation=[];
  class ClockDate extends Date{static now(){return now;}}
  class Element{
    constructor(text=''){this.textContent=text;this.listeners={};this.attrs={};this.disabled=false;}
    set innerHTML(_){throw new Error('Status must remain text');}
    addEventListener(type,handler){(this.listeners[type]||=[]).push(handler);}
    setAttribute(name,value){this.attrs[name]=String(value);}
    async fire(type,options={}){const event={preventDefault(){this.defaultPrevented=true;},...options};
      await Promise.all((this.listeners[type]||[]).map(handler=>handler(event)));return event;}
  }
  const ids=Object.fromEntries(['plex-user-sync-form','plex-user-sync-button','plex-user-sync-status','plex-user-sync-snapshot'].map(id=>[id,new Element()]));
  ids['plex-user-sync-snapshot'].textContent=initialJson??JSON.stringify(job);
  ids['plex-user-sync-button'].textContent='Sync Plex users';ids['plex-user-sync-status'].textContent='Server-rendered job status';
  const unsaved={value:'Unsaved account display name'};
  const document=new Element();document.hidden=hidden;document.getElementById=id=>ids[id]||null;
  const window=new Element();if(toast)window.showToast=(message,tone)=>toasts.push({message,tone});
  const location={reload(){navigation.push('reload');},assign(value){navigation.push(value);}};
  Object.defineProperty(location,'href',{set(value){navigation.push(value);}});
  for(const node of[window,document])Object.defineProperty(node,'location',{get(){return location;},set(value){navigation.push(value);}});
  const installList=()=>{window.KeepUsers={refresh(){let resolve,reject;
    const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});listCalls.push({resolve,reject,at:now});return promise;}};};
  if(listAvailable)installList();
  const fetch=(url,options)=>{let resolve,reject;const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});
    if(!ignoreAbort)options.signal.addEventListener('abort',()=>reject(new Error('Aborted')),{once:true});
    calls.push({url,options,resolve,reject,at:now});return promise;};
  class FormData{constructor(form){assert.equal(form,ids['plex-user-sync-form']);return new Map([['csrf_token','preview-csrf']]);}}
  vm.runInNewContext(source,{document,window,fetch:fetchAvailable?fetch:undefined,AbortController:abortAvailable?AbortController:undefined,
    FormData,URLSearchParams,Date:ClockDate,location,setTimeout:(fn,delay)=>{const id=++nextTimer;timers.set(id,{fn,delay,due:now+delay});return id;},clearTimeout:id=>timers.delete(id)});
  return{ids,document,window,timers,calls,listCalls,toasts,navigation,unsaved,installList,
    respond(index,status,body,extra={}){calls[index].resolve({ok:status>=200&&status<300,status,redirected:false,json:async()=>body,...extra});},
    fail(index){calls[index].reject(new Error('Connection lost'));},
    async advance(ms){now+=ms;for(const[id,timer]of[...timers].filter(([,timer])=>timer.due<=now)){timers.delete(id);timer.fn();}await settle();},
    async queue(next=queued(),status=202,extra={}){const action=ids['plex-user-sync-form'].fire('submit');await settle();
      this.respond(calls.length-1,status,{job:next,message:'Plex user sync queued.',...extra});await action;await settle();},
    async poll(next,delay=3000){await this.advance(delay);this.respond(calls.length-1,200,{job:next});await settle();},
    async merge(index=0,result=true){listCalls[index].resolve(result);await settle();}
  };
}

test('idle uses concise status and automatically reads after 15 seconds without optional controls',async()=>{
  const f=fixture();assert.equal(f.calls.length,0);assert.equal(f.listCalls.length,0);
  assert.equal(f.ids['plex-user-sync-status'].textContent,'Plex users synced.');
  assert.equal(f.ids['plex-user-sync-button'].textContent,'Sync Plex users');
  await f.advance(14999);assert.equal(f.calls.length,0);await f.advance(1);assert.equal(f.calls[0].options.method,'GET');
  f.respond(0,200,{job:baseline()});await settle();assert.equal(f.listCalls.length,0);assert.equal(f.toasts.length,0);
});
test('invalid state and unsupported browsers preserve ordinary form submission',async()=>{
  for(const options of[{fetchAvailable:false},{abortAvailable:false},{initialJson:'<html>'},{job:baseline({id:'other'})},{job:baseline({queued:'false'})}]){
    const f=fixture(options),event=await f.ids['plex-user-sync-form'].fire('submit');
    assert.equal(event.defaultPrevented,undefined);assert.equal(f.calls.length,0);assert.equal(f.timers.size,0);
  }
});
test('one CSRF POST uses GET polling and announces success only after the user-list update',async()=>{
  const f=fixture();await f.queue();const first=f.calls[0];
  assert.equal(first.url,'/settings/users/plex-sync');assert.equal(first.options.method,'POST');assert.equal(first.options.body.get('csrf_token'),'preview-csrf');
  assert.equal(first.options.credentials,'same-origin');assert.equal(first.options.cache,'no-store');assert.equal(first.options.headers.Accept,'application/json');
  assert.equal(f.toasts.at(-1).tone,'neutral');await f.poll(running());assert.equal(f.ids['plex-user-sync-button'].textContent,'Syncing…');
  await f.poll(complete());assert.equal(f.listCalls.length,1);assert.equal(f.toasts.some(toast=>toast.tone==='ok'),false);
  assert.equal(f.ids['plex-user-sync-status'].textContent,'Updating Plex users…');await f.merge();
  assert.equal(f.toasts.at(-1).tone,'ok');assert.equal(f.toasts.at(-1).message,'Plex users synced.');
  assert.equal(f.ids['plex-user-sync-button'].disabled,false);assert.equal(f.ids['plex-user-sync-form'].attrs['aria-busy'],'false');
  assert.deepEqual(f.navigation,[]);assert.equal(f.unsaved.value,'Unsaved account display name');assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('duplicate submissions cannot overlap queueing, active jobs or recorded reads',async()=>{
  const f=fixture(),action=f.ids['plex-user-sync-form'].fire('submit');await settle();
  await f.ids['plex-user-sync-form'].fire('submit');assert.equal(f.calls.length,1);f.respond(0,202,{job:queued()});await action;await settle();
  await f.ids['plex-user-sync-form'].fire('submit');assert.equal(f.calls.length,1);
  await f.advance(3000);await f.ids['plex-user-sync-form'].fire('submit');assert.equal(f.calls.length,2);
  f.respond(1,200,{job:complete()});await settle();await f.merge();
});
test('initially busy and scheduled idle syncs both update users automatically once',async()=>{
  const active=fixture({job:queued()});await active.poll(complete());await active.merge();assert.equal(active.calls.every(call=>call.options.method==='GET'),true);
  const idle=fixture();await idle.poll(complete(),15000);await idle.merge();await idle.poll(complete(),15000);
  assert.equal(idle.listCalls.length,1);assert.equal(idle.toasts.filter(toast=>toast.tone==='ok').length,1);
});
test('fast completion still waits for the merged user list before showing success',async()=>{
  const f=fixture();await f.queue(complete());assert.equal(f.listCalls.length,1);assert.equal(f.toasts.length,0);
  await f.merge();assert.equal(f.toasts.length,1);assert.equal(f.toasts[0].tone,'ok');
});
test('false and thrown list updates retry automatically with capped backoff',async()=>{
  const f=fixture();await f.poll(complete(),15000);await f.merge(0,false);assert.equal(f.toasts.length,0);
  assert.match(f.ids['plex-user-sync-status'].textContent,/retry automatically/);
  await f.advance(5999);assert.equal(f.listCalls.length,1);await f.advance(1);assert.equal(f.listCalls.length,2);
  f.listCalls[1].reject(new Error('Offline'));await settle();await f.advance(12000);assert.equal(f.listCalls.length,3);await f.merge(2);
  assert.equal(f.toasts.filter(toast=>toast.tone==='ok').length,1);assert.equal(f.calls.every(call=>call.options.method==='GET'),true);
  assert.ok([...f.timers.values()].every(timer=>timer.delay<=60000));
});
test('a temporarily missing user-list helper is retried when available',async()=>{
  const f=fixture({listAvailable:false});await f.poll(complete(),15000);assert.equal(f.toasts.length,0);
  f.installList();await f.advance(6000);assert.equal(f.listCalls.length,1);await f.merge();assert.equal(f.toasts.at(-1).tone,'ok');
});
test('repeated list failures back off to 60 seconds without reporting success',async()=>{
  const f=fixture();await f.poll(complete(),15000);await f.merge(0,false);
  for(const delay of[6000,12000,24000,48000,60000,60000]){
    const before=f.listCalls.at(-1).at;await f.advance(delay);
    assert.equal(f.listCalls.at(-1).at-before,delay);await f.merge(f.listCalls.length-1,false);
  }
  assert.equal(f.toasts.length,0);assert.deepEqual(f.navigation,[]);
});
test('newer successful jobs serialize list updates and announce only the latest applied result',async()=>{
  const f=fixture();await f.poll(complete(),15000);assert.equal(f.listCalls.length,1);
  await f.poll(complete({last_run:'2026-10-24T12:02:00Z',last_success:'2026-10-24T12:02:00Z'}),15000);assert.equal(f.listCalls.length,1);
  await f.merge();assert.equal(f.toasts.length,0);await f.advance(0);assert.equal(f.listCalls.length,2);await f.merge(1);
  assert.equal(f.toasts.filter(toast=>toast.tone==='ok').length,1);
});
test('a fresh idle GET resolves an uncertain POST and permits explicit retry without resending',async()=>{
  const f=fixture(),action=f.ids['plex-user-sync-form'].fire('submit');await settle();f.fail(0);await action;await settle();
  assert.equal(f.ids['plex-user-sync-button'].disabled,true);await f.ids['plex-user-sync-form'].fire('submit');assert.equal(f.calls.length,1);
  await f.poll(baseline());assert.equal(f.ids['plex-user-sync-button'].disabled,false);assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('an unchanged POST result is checked promptly before permitting an explicit retry',async()=>{
  const f=fixture();await f.queue(baseline());assert.equal(f.ids['plex-user-sync-button'].disabled,true);
  await f.poll(baseline());assert.equal(f.calls.length,2);assert.equal(f.ids['plex-user-sync-button'].disabled,false);
  assert.equal(f.listCalls.length,0);assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('a server error with idle recorded state receives a prompt GET without another POST',async()=>{
  const f=fixture();await f.queue(baseline(),503,{error:'Temporarily unavailable.'});
  assert.equal(f.ids['plex-user-sync-button'].disabled,true);await f.poll(baseline());
  assert.equal(f.calls.length,2);assert.equal(f.calls[1].options.method,'GET');assert.equal(f.ids['plex-user-sync-button'].disabled,false);
  assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('request timeouts abort and recover through automatic recorded reads',async()=>{
  const f=fixture(),action=f.ids['plex-user-sync-form'].fire('submit');await settle();await f.advance(15000);await action;await settle();
  assert.equal(f.calls[0].options.signal.aborted,true);await f.poll(queued());await f.poll(complete());await f.merge();
  assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('status transport backoff is capped at 60 seconds and resets on recovery',async()=>{
  const f=fixture();await f.advance(15000);f.fail(0);await settle();
  await f.advance(29999);assert.equal(f.calls.length,1);await f.advance(1);assert.equal(f.calls.length,2);f.fail(1);await settle();
  await f.advance(60000);assert.equal(f.calls.length,3);f.respond(2,200,{job:baseline()});await settle();await f.advance(15000);assert.equal(f.calls.length,4);
  assert.equal(f.calls.every(call=>call.options.method==='GET'),true);assert.ok([...f.timers.values()].every(timer=>timer.delay<=60000));
});
test('busy polling slows after two minutes and continues automatically',async()=>{
  const f=fixture({job:queued()});for(let i=0;i<40;i++)await f.poll(queued());assert.equal(f.calls.length,40);
  await f.advance(14999);assert.equal(f.calls.length,40);await f.advance(1);assert.equal(f.calls.length,41);
  f.respond(40,200,{job:complete()});await settle();await f.merge();assert.equal(f.calls.every(call=>call.options.method==='GET'),true);
});
test('worker failure never refreshes users or announces success',async()=>{
  const f=fixture();await f.queue();await f.poll(complete({status:'failed',last_attempt_status:'failed',last_success:'2026-10-24T12:00:00Z',result:'Plex is unavailable.'}));
  assert.match(f.ids['plex-user-sync-status'].textContent,/failed.*Plex is unavailable/);assert.equal(f.listCalls.length,0);
  assert.equal(f.toasts.at(-1).tone,'error');assert.equal(f.ids['plex-user-sync-button'].disabled,false);
});
test('an older list update cannot overwrite a newer failed sync with success feedback',async()=>{
  const f=fixture();await f.poll(complete(),15000);
  await f.poll(complete({status:'failed',last_attempt_status:'failed',last_run:'2026-10-24T12:02:00Z',result:'Plex is unavailable.'}),15000);
  await f.merge();assert.equal(f.toasts.some(toast=>toast.tone==='ok'),false);
  assert.match(f.ids['plex-user-sync-status'].textContent,/failed.*Plex is unavailable/);
});
test('a failed durable retry remains queued and is announced once',async()=>{
  const f=fixture();await f.queue();const retry=queued({last_run:'2026-10-24T12:00:03Z',last_attempt_status:'failed',result:'Plex is unavailable.'});
  await f.poll(retry);await f.poll(retry);assert.equal(f.toasts.filter(toast=>toast.tone==='error').length,1);
  assert.match(f.ids['plex-user-sync-status'].textContent,/retry automatically/);assert.equal(f.ids['plex-user-sync-button'].disabled,true);
});
test('401, 403 and login redirects stop automatic work until pageshow rechecks the session',async()=>{
  for(const code of[401,403,200]){
    const f=fixture({job:queued()});await f.advance(3000);f.respond(0,code,null,code===200?{redirected:true,json:async()=>{throw new Error('HTML');}}:{});await settle();
    assert.match(f.ids['plex-user-sync-status'].textContent,/session expired or access changed/);assert.equal(f.timers.size,0);
    await f.advance(120000);assert.equal(f.calls.length,1);f.document.hidden=true;await f.document.fire('visibilitychange');
    f.document.hidden=false;await f.document.fire('visibilitychange');assert.equal(f.calls.length,1);
    await f.window.fire('pageshow');assert.equal(f.calls[1].options.method,'GET');f.respond(1,200,{job:complete()});await settle();await f.merge();
    assert.equal(f.toasts.at(-1).tone,'ok');
  }
});
test('unauthorized POST is not retried or reported as queued',async()=>{
  const f=fixture();await f.queue(null,403);assert.equal(f.timers.size,0);assert.equal(f.toasts.length,0);
  assert.equal(f.ids['plex-user-sync-button'].disabled,true);assert.equal(f.calls.length,1);
});
test('invalid JSON and foreign jobs preserve state and retry GET only',async()=>{
  for(const extra of[{json:async()=>{throw new Error('HTML');}},{json:async()=>({job:baseline({id:'other'})})}]){
    const f=fixture({job:queued()});await f.advance(3000);f.respond(0,200,null,extra);await settle();
    assert.match(f.ids['plex-user-sync-status'].textContent,/Retrying automatically/);assert.equal(f.listCalls.length,0);
    assert.equal(f.ids['plex-user-sync-button'].disabled,true);await f.advance(6000);assert.equal(f.calls[1].options.method,'GET');
  }
});
test('configuration availability is detected automatically and provider prose stays text-only',async()=>{
  const f=fixture({job:baseline({status:'disabled',can_run:false,action_reason:'<img src=x onerror=alert(1)>'})});
  assert.equal(f.ids['plex-user-sync-status'].textContent,'<img src=x onerror=alert(1)>');await f.ids['plex-user-sync-form'].fire('submit');assert.equal(f.calls.length,0);
  await f.poll(baseline(),15000);assert.equal(f.ids['plex-user-sync-button'].disabled,false);assert.equal(f.toasts.length,0);
});
test('hidden pages cancel reads and resume GETs without touching unsaved editors',async()=>{
  const f=fixture({job:queued()});await f.advance(3000);f.document.hidden=true;await f.document.fire('visibilitychange');await settle();
  assert.equal(f.calls[0].options.signal.aborted,true);assert.equal(f.timers.size,0);await f.advance(120000);assert.equal(f.calls.length,1);
  f.document.hidden=false;await f.document.fire('visibilitychange');assert.equal(f.calls[1].options.method,'GET');f.respond(1,200,{job:complete()});await settle();await f.merge();
  assert.deepEqual(f.navigation,[]);assert.equal(f.unsaved.value,'Unsaved account display name');
});
test('pagehide rejects stale POST results and pageshow recovers through GET',async()=>{
  const f=fixture({ignoreAbort:true}),action=f.ids['plex-user-sync-form'].fire('submit');await settle();await f.window.fire('pagehide');
  assert.equal(f.calls[0].options.signal.aborted,true);assert.equal(f.timers.size,0);await f.window.fire('pageshow');f.respond(1,200,{job:queued()});await settle();
  f.respond(0,202,{job:complete()});await action;await settle();assert.equal(f.listCalls.length,0);await f.poll(complete());await f.merge();
  assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('a list response after pagehide cannot toast and is retried when visible',async()=>{
  const f=fixture();await f.poll(complete(),15000);await f.window.fire('pagehide');await f.merge();assert.equal(f.toasts.length,0);assert.equal(f.timers.size,0);
  await f.window.fire('pageshow');assert.equal(f.listCalls.length,2);f.respond(1,200,{job:complete()});await settle();await f.merge(1);
  assert.equal(f.toasts.filter(toast=>toast.tone==='ok').length,1);assert.deepEqual(f.navigation,[]);
});
test('initially hidden pages wait for visibility and do not require shared toasts',async()=>{
  const f=fixture({hidden:true,toast:false});assert.equal(f.calls.length,0);assert.equal(f.timers.size,0);
  f.document.hidden=false;await f.document.fire('visibilitychange');f.respond(0,200,{job:complete()});await settle();await f.merge();
  assert.equal(f.ids['plex-user-sync-status'].textContent,'Plex users synced.');assert.deepEqual(f.navigation,[]);
});
