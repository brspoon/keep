const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../static/keep-about.js'), 'utf8');
const baseline = changes => ({status:'success', comparison:'up_to_date', installed_version:'2.25.0', latest_version:'2.25.0', latest_tag:'2.25.0',
  last_attempt_at:'2026-10-11T12:00:00Z', last_success_at:'2026-10-11T12:00:00Z', stale:false, check_state:'idle', can_check:true,
  worker_available:true, reason:'', retry_after_seconds:0, message:'Release information checked.', releases:[{version:'2.25.0', tag:'2.25.0', published_at:'2026-10-11T12:00:00Z', url:'https://github.com/brspoon/keep/releases/tag/2.25.0'}], ...changes});
async function settle() { for (let i=0;i<12;i++) await Promise.resolve(); }
function fixture({snapshot=baseline(), clipboard=true, fetchAvailable=true, initialJson, hidden=false, toast=false}={}) {
  let now=Date.parse('2026-10-11T12:00:00Z'),document,timeoutId=0;
  const timers=new Map(),calls=[],copies=[],toasts=[];
  class ClockDate extends Date { constructor(...args){super(...(args.length?args:[now]));} static now(){return now;} }
  class Element {
    constructor(tag='div',text=''){this.tagName=tag.toUpperCase();this.children=[];this._text=text;this.textWrites=[];this.attrs={};this.listeners={};this.hidden=false;this.disabled=false;this.value='';this.selectionStart=0;this.selectionEnd=0;this.open=false;this.className='';
      this.classList={toggle:(name,on)=>{const current=new Set(this.className.split(/\s+/).filter(Boolean));on?current.add(name):current.delete(name);this.className=[...current].join(' ');},contains:name=>this.className.split(/\s+/).includes(name)};}
    set innerHTML(_){throw new Error('Release data must remain text');}
    get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
    set textContent(value){this._text=String(value);this.textWrites.push(String(value));this.children=[];}
    append(...nodes){this.children.push(...nodes);}
    replaceChildren(...nodes){this.children=nodes;this._text='';}
    setAttribute(name,value){this.attrs[name]=String(value);}
    getAttribute(name){return this.attrs[name]??null;}
    addEventListener(type,handler){(this.listeners[type]||=[]).push(handler);}
    async fire(type,props={}){const event={target:this,preventDefault(){this.defaultPrevented=true;},...props};await Promise.all((this.listeners[type]||[]).map(handler=>handler(event)));return event;}
    focus(options){const before=document.activeElement;document.activeElement=this;this.focusOptions=options;if(before!==this)void before?.fire('blur');}
    select(){this.selectionStart=0;this.selectionEnd=this.value.length;this.selected=true;}
  }
  document=new Element();document.hidden=hidden;document.activeElement=null;document.createElement=tag=>new Element(tag);
  const window=new Element();if(toast)window.showToast=(message,tone)=>toasts.push({message,tone});window.events=[];window.dispatchEvent=event=>{window.events.push(event.type);return true;};
  const ids={};
  for(const id of ['about-feedback','about-copy','about-diagnostics','about-diagnostics-details','about-copy-feedback','about-check-form','about-check','about-refresh','about-snapshot','about-installed','about-latest','about-comparison','about-last-check','about-check-state','about-check-reason','about-releases-empty','about-releases'])ids[id]=new Element();
  ids['about-diagnostics'].value='{"keep_version":"2.25.0"}';
  ids['about-snapshot'].textContent=initialJson===undefined?JSON.stringify(snapshot):initialJson;
  ids['about-feedback'].hidden=ids['about-copy-feedback'].hidden=ids['about-refresh'].hidden=true;
  document.getElementById=id=>ids[id]||null;
  const fetch=(url,options)=>{let resolve,reject;const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});
    options.signal.addEventListener('abort',()=>reject(new Error('Aborted')),{once:true});calls.push({url,options,resolve,reject});return promise;};
  class FormData {constructor(){return new Map([['csrf_token','synthetic-csrf']]);}}
  const navigator={clipboard:clipboard?{writeText:async value=>{copies.push(value);if(clipboard==='fail')throw new Error('Denied');}}:undefined};
  vm.runInNewContext(source,{document,window,navigator,CustomEvent:class{constructor(type){this.type=type;}},fetch:fetchAvailable?fetch:undefined,AbortController,FormData,URLSearchParams,Intl,Date:ClockDate,
    setTimeout:(fn,delay)=>{const id=++timeoutId;timers.set(id,{fn,due:now+delay,delay});return id;},clearTimeout:id=>timers.delete(id)});
  return {ids,document,window,calls,copies,timers,toasts,now:()=>now,
    respond(index,status,body,extra={}){calls[index].resolve({ok:status>=200&&status<300,status,redirected:false,json:async()=>body,...extra});},
    fail(index){calls[index].reject(new Error('Network lost'));},
    async advance(ms){now+=ms;const due=[...timers].filter(([,timer])=>timer.due<=now);due.forEach(([id,timer])=>{timers.delete(id);timer.fn();});await settle();},
    async queue(next=baseline({check_state:'queued',can_check:false}),status=202,extra={}){const action=ids['about-check-form'].fire('submit');await settle();const index=calls.length-1;this.respond(index,status,{snapshot:next,message:'Update check queued.',...extra});await action;await settle();},
    async poll(next,extra={}){await this.advance(2000);const index=calls.length-1;this.respond(index,200,{snapshot:next,...extra});await settle();}
  };
}

test('idle About renders installed/current/latest facts without fetching or executing calls',()=>{
  const f=fixture();assert.equal(f.calls.length,0);assert.equal(f.ids['about-installed'].textContent,'2.25.0');assert.equal(f.ids['about-comparison'].textContent,'Up to date');assert.equal(f.ids['about-check'].disabled,false);
  assert.match(f.ids['about-releases'].textContent,/CurrentLatest/);assert.doesNotMatch(f.ids['about-last-check'].textContent,/T12:/);
});
test('a new installed version watches the worker refresh through status GETs without queueing a manual check',async()=>{
  const f=fixture({snapshot:baseline({installed_version:'2.26.0',latest_version:'2.25.0',stale:true,comparison:'unknown',version_refresh_pending:true})});
  assert.equal(f.ids['about-comparison'].textContent,'Last known');assert.equal(f.calls.length,0);
  await f.advance(2000);assert.equal(f.calls[0].url,'/settings/about/status');assert.equal(f.calls[0].options.method,undefined);
  f.respond(0,200,{snapshot:baseline({installed_version:'2.26.0',latest_version:'2.26.0',version_refresh_pending:false})});await settle();
  assert.equal(f.ids['about-comparison'].textContent,'Up to date');assert.equal(f.timers.size,0);assert.equal(f.calls.length,1);
});
test('one CSRF form POST queues work, polling follows recorded status, and completion updates controls',async()=>{
  const f=fixture(),action=f.ids['about-check-form'].fire('submit');await settle();assert.equal(f.calls.length,1);assert.equal(f.calls[0].url,'/settings/about/check');assert.equal(f.calls[0].options.method,'POST');assert.equal(f.calls[0].options.body.get('csrf_token'),'synthetic-csrf');assert.equal(f.calls[0].options.credentials,'same-origin');
  await f.ids['about-check-form'].fire('submit');assert.equal(f.calls.length,1);f.respond(0,202,{snapshot:baseline({check_state:'queued',can_check:false}),message:'Update check queued.'});await action;await settle();assert.equal(f.ids['about-check'].textContent,'Queued');assert.equal(f.ids['about-check'].disabled,true);
  await f.poll(baseline({check_state:'running',can_check:false}));assert.equal(f.ids['about-check'].textContent,'Checking…');assert.equal(f.calls[1].url,'/settings/about/status');assert.equal(f.calls[1].options.method,undefined);
  await f.poll(baseline({comparison:'update_available',latest_version:'2.26.0',latest_tag:'2.26.0'}));assert.equal(f.ids['about-comparison'].textContent,'Update available');assert.equal(f.ids['about-latest'].textContent,'2.26.0');assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.timers.size,0);assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('worker unavailable keeps the check disabled without pretending release state changed',async()=>{
  const f=fixture({snapshot:baseline({worker_available:false,can_check:false,reason:'The background worker is unavailable.'})});assert.equal(f.ids['about-check'].disabled,true);assert.equal(f.ids['about-check-reason'].hidden,false);await f.ids['about-check-form'].fire('submit');assert.equal(f.calls.length,0);assert.equal(f.ids['about-comparison'].textContent,'Up to date');
});
test('a newly failed manual attempt is announced while its durable retry remains queued',async()=>{
  const f=fixture();await f.queue();
  const attempt='2026-10-11T12:00:02Z';
  await f.poll(baseline({status:'never',comparison:'unknown',stale:true,check_state:'running',can_check:false,last_attempt_at:attempt,error_code:null}));
  const failure=baseline({status:'failed',comparison:'unknown',stale:true,check_state:'queued',can_check:false,last_attempt_at:attempt,error_code:'github_unavailable',message:'GitHub release information is unavailable. Try again later.'});
  await f.poll(failure);assert.equal(f.ids['about-check'].textContent,'Queued');assert.equal(f.ids['about-feedback'].textContent,failure.message);
  assert.equal(f.ids['about-feedback'].classList.contains('is-error'),true);const writes=f.ids['about-feedback'].textWrites.length;
  await f.poll(failure);assert.equal(f.ids['about-feedback'].textWrites.length,writes);
  await f.advance(120000);assert.equal(f.ids['about-refresh'].hidden,false);assert.equal(f.ids['about-feedback'].textContent,failure.message);
});
test('a newly rate-limited attempt is announced and preserved at the polling timeout',async()=>{
  const f=fixture();await f.queue();
  const limited=baseline({status:'rate_limited',comparison:'unknown',stale:true,check_state:'queued',can_check:false,last_attempt_at:'2026-10-11T12:00:03Z',error_code:'rate_limited',retry_after_seconds:3600,message:'GitHub release checks are temporarily rate limited.'});
  await f.poll(limited);assert.equal(f.ids['about-feedback'].textContent,limited.message);assert.equal(f.ids['about-check'].disabled,true);
  await f.advance(120000);assert.equal(f.ids['about-feedback'].textContent,limited.message);assert.equal(f.ids['about-refresh'].hidden,false);
});
test('queueing a fresh manual retry does not announce an unchanged failure from the prior attempt',async()=>{
  const old=baseline({status:'failed',comparison:'unknown',stale:true,error_code:'github_unavailable',message:'GitHub release information is unavailable. Try again later.'});
  const f=fixture({snapshot:old}),queued={...old,check_state:'queued',can_check:false};await f.queue(queued);
  assert.equal(f.ids['about-feedback'].textContent,'Update check queued.');assert.equal(f.ids['about-feedback'].classList.contains('is-error'),false);
  const writes=f.ids['about-feedback'].textWrites.length;await f.poll(queued);assert.equal(f.ids['about-feedback'].textWrites.length,writes);
});
test('failed cached observations show last-known release data and never claim up to date',()=>{
  const f=fixture({snapshot:baseline({status:'failed',stale:true,comparison:'up_to_date',can_check:false})});assert.equal(f.ids['about-comparison'].textContent,'Last known');assert.match(f.ids['about-releases'].textContent,/Last known/);assert.doesNotMatch(f.ids['about-releases'].textContent,/Latest/);assert.equal(f.ids['about-check-state'].textContent,'Failed');
});
test('release links ignore supplied URLs and reject invalid tags without HTML execution',()=>{
  const f=fixture({snapshot:baseline({releases:[{version:'2.25.0',tag:'2.25.0',published_at:'2026-10-11T12:00:00Z',url:'javascript:alert(1)',name:'<img onerror=alert(1)>'},{version:'2.26.0',tag:'javascript:alert(1)',published_at:'invalid'}]})});
  const rows=f.ids['about-releases'].children;assert.equal(rows.length,1);assert.equal(rows[0].children[1].href,'https://github.com/brspoon/keep/releases/tag/2.25.0');assert.equal(rows[0].children[1].rel,'noopener noreferrer');assert.doesNotMatch(rows[0].textContent,/<img|javascript/);
});
test('release paths accept exact version tags and reject quotes, separators and final line breaks',()=>{
  for(const tag of ['2.26.0" onmouseover="alert(1)', '2.26.0/../../login', '2.26.0%2Flogin', '2.26.0?url=https://outside.example', '2.26.0\n', 'v2.26.0\r\n']){
    const f=fixture({snapshot:baseline({releases:[{version:tag.replace(/^v/,''),tag,published_at:'2026-10-11T12:00:00Z'}]})});
    assert.equal(f.ids['about-releases'].children.length,0);assert.equal(f.ids['about-releases-empty'].hidden,false);
  }
  const f=fixture({snapshot:baseline({releases:[{version:'2.26.0',tag:'v2.26.0',published_at:'2026-10-11T12:00:00Z',url:'https://outside.example'}]})});
  assert.equal(f.ids['about-releases'].children[0].children[1].href,'https://github.com/brspoon/keep/releases/tag/v2.26.0');
});
test('CSRF or owner authorization failures preserve the server message and stop requests',async()=>{
  const f=fixture(),action=f.ids['about-check-form'].fire('submit');await settle();f.respond(0,403,{error:'Your session changed. Refresh the page and try again.'});await action;await settle();assert.match(f.ids['about-feedback'].textContent,/Your session changed/);assert.equal(f.ids['about-check'].disabled,true);await f.advance(200000);await f.ids['about-check-form'].fire('submit');assert.equal(f.calls.length,1);
});
test('an expired-session redirect to an HTML login page stops polling with a sign-in message',async()=>{
  const f=fixture({snapshot:baseline({check_state:'running',can_check:false})});await f.advance(2000);
  f.respond(0,200,null,{redirected:true,json:async()=>{throw new Error('HTML login');}});await settle();
  assert.match(f.ids['about-feedback'].textContent,/sign in again/);assert.equal(f.ids['about-check'].disabled,true);
  await f.advance(200000);assert.equal(f.calls.length,1);assert.equal(f.timers.size,0);
});
test('an unavailable worker exposes a GET-only recovery control',async()=>{
  const f=fixture({snapshot:baseline({worker_available:false,can_check:false})});assert.equal(f.ids['about-refresh'].hidden,false);
  await f.ids['about-refresh'].fire('click');await settle();assert.equal(f.calls[0].url,'/settings/about/status');
  f.respond(0,200,{snapshot:baseline()});await settle();assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.ids['about-refresh'].hidden,true);
});
test('confirmed action failure with a null snapshot preserves recorded data and shows supplied error',async()=>{
  const f=fixture();await f.queue(null,503,{error:'Keep could not queue the check. Try again shortly.'});assert.equal(f.ids['about-latest'].textContent,'2.25.0');assert.match(f.ids['about-feedback'].textContent,/could not queue/);assert.equal(f.ids['about-check'].disabled,false);await f.advance(2000);assert.equal(f.calls.length,1);
});
test('busy polling stops at two minutes and explicit status recovery only performs a GET',async()=>{
  const f=fixture({snapshot:baseline({check_state:'queued',can_check:false})});await f.advance(120000);assert.equal(f.calls.length,0);assert.equal(f.ids['about-refresh'].hidden,false);assert.match(f.ids['about-feedback'].textContent,/still pending/);
  await f.ids['about-refresh'].fire('click');await settle();assert.equal(f.calls[0].url,'/settings/about/status');f.respond(0,200,{snapshot:baseline()});await settle();assert.equal(f.ids['about-refresh'].hidden,true);assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.timers.size,0);
});
test('poll transport failures preserve known state and retry within the bounded watch',async()=>{
  const f=fixture({snapshot:baseline({check_state:'running',can_check:false})});await f.advance(2000);f.fail(0);await settle();assert.equal(f.ids['about-latest'].textContent,'2.25.0');assert.match(f.ids['about-feedback'].textContent,/Connection lost/);await f.poll(baseline());assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.timers.size,0);
});
test('malformed status responses cannot overwrite a confirmed snapshot',async()=>{
  const f=fixture({snapshot:baseline({check_state:'running',can_check:false})});await f.advance(2000);f.respond(0,200,{snapshot:{latest_version:'999.0.0'}});await settle();assert.equal(f.ids['about-latest'].textContent,'2.25.0');assert.equal(f.ids['about-check'].disabled,true);assert.equal(f.ids['about-check'].textContent,'Checking…');await f.advance(120000);assert.equal(f.ids['about-refresh'].hidden,false);
});
test('an uncertain POST is resolved through recorded status without issuing a second POST',async()=>{
  const f=fixture(),action=f.ids['about-check-form'].fire('submit');await settle();f.fail(0);await action;await settle();assert.equal(f.ids['about-check'].disabled,true);assert.match(f.ids['about-feedback'].textContent,/could not confirm/);
  await f.poll(baseline({check_state:'queued',can_check:false}));await f.poll(baseline());assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('a timed-out POST aborts transport and resolves uncertainty through recorded status',async()=>{
  const f=fixture(),action=f.ids['about-check-form'].fire('submit');await settle();await f.advance(15000);await action;
  assert.equal(f.calls[0].options.signal.aborted,true);assert.equal(f.ids['about-check'].disabled,true);
  await f.poll(baseline());assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
});
test('an inflight poll is aborted at the two-minute watch boundary',async()=>{
  const f=fixture({snapshot:baseline({check_state:'running',can_check:false})});await f.advance(119000);assert.equal(f.calls.length,1);
  await f.advance(1000);assert.equal(f.calls[0].options.signal.aborted,true);assert.equal(f.ids['about-refresh'].hidden,false);
  assert.match(f.ids['about-feedback'].textContent,/still pending/);assert.equal(f.timers.size,0);
});
test('cooldown expires through one recorded-state GET and re-enables the check',async()=>{
  const f=fixture({snapshot:baseline({can_check:false,retry_after_seconds:60,reason:'Wait briefly before checking again.'})});assert.equal(f.ids['about-check'].disabled,true);await f.advance(60000);assert.equal(f.calls.length,0);await f.advance(100);assert.equal(f.calls[0].url,'/settings/about/status');f.respond(0,200,{snapshot:baseline()});await settle();assert.equal(f.ids['about-check'].disabled,false);assert.equal(f.timers.size,0);
});
test('a failed idle cooldown refresh offers recovery without restarting an endless timer',async()=>{
  const f=fixture({snapshot:baseline({can_check:false,retry_after_seconds:60})});await f.advance(60100);f.fail(0);await settle();
  assert.equal(f.ids['about-refresh'].hidden,false);assert.equal(f.timers.size,0);await f.advance(180000);assert.equal(f.calls.length,1);
});
test('a poll started before a manual check cannot overwrite the newer queued state',async()=>{
  const f=fixture();await f.ids['about-refresh'].fire('click');await settle();assert.equal(f.calls.length,1);
  const action=f.ids['about-check-form'].fire('submit');await settle();assert.equal(f.calls[0].options.signal.aborted,true);f.respond(1,202,{snapshot:baseline({check_state:'queued',can_check:false}),message:'Update check queued.'});await action;await settle();f.respond(0,200,{snapshot:baseline({latest_version:'9.0.0'})});await settle();assert.equal(f.ids['about-check'].textContent,'Queued');assert.equal(f.ids['about-latest'].textContent,'2.25.0');
});
test('page exit aborts inflight reads and restoration refreshes without replaying actions',async()=>{
  const f=fixture({snapshot:baseline({check_state:'running',can_check:false})});await f.advance(2000);await f.window.fire('pagehide');await settle();assert.equal(f.calls[0].options.signal.aborted,true);assert.equal(f.timers.size,0);f.respond(0,200,{snapshot:baseline({latest_version:'9.0.0'})});await settle();assert.equal(f.ids['about-latest'].textContent,'2.25.0');await f.window.fire('pageshow');await settle();assert.equal(f.calls[1].url,'/settings/about/status');f.respond(1,200,{snapshot:baseline()});await settle();assert.equal(f.ids['about-check'].disabled,false);
});
test('hidden documents pause polling and visible return refreshes the recorded snapshot',async()=>{
  const f=fixture({snapshot:baseline({check_state:'queued',can_check:false}),hidden:true});assert.equal(f.timers.size,0);await f.advance(10000);assert.equal(f.calls.length,0);f.document.hidden=false;await f.document.fire('visibilitychange');await settle();assert.equal(f.calls[0].url,'/settings/about/status');f.respond(0,200,{snapshot:baseline()});await settle();assert.equal(f.timers.size,0);
});
test('polling preserves selected diagnostics until focus leaves, then copying uses the refreshed text',async()=>{
  const f=fixture({snapshot:baseline({check_state:'queued',can_check:false})}),diagnostics=f.ids['about-diagnostics'];diagnostics.focus();diagnostics.selectionStart=0;diagnostics.selectionEnd=5;const original=diagnostics.value;
  await f.poll(baseline(),{diagnostics:'{"keep_version":"2.26.0"}'});assert.equal(diagnostics.value,original);f.ids['about-copy'].focus();await settle();assert.equal(diagnostics.value,'{"keep_version":"2.26.0"}');await f.ids['about-copy'].fire('click');assert.equal(f.copies[0],diagnostics.value);assert.equal(f.ids['about-copy-feedback'].textContent,'Copied.');
});
test('clipboard failure exposes a focused selectable diagnostic fallback without network work',async()=>{
  for(const clipboard of [false,'fail']){const f=fixture({clipboard});await f.ids['about-copy'].fire('click');assert.equal(f.ids['about-diagnostics-details'].open,true);assert.equal(f.ids['about-diagnostics'].selected,true);assert.equal(f.document.activeElement,f.ids['about-diagnostics']);assert.equal(f.ids['about-diagnostics'].focusOptions.preventScroll,true);assert.equal(f.ids['about-copy'].disabled,false);assert.match(f.ids['about-copy-feedback'].textContent,/Copy the selected/);assert.equal(f.calls.length,0);}
});
test('missing fetch or malformed initial JSON preserves ordinary form fallback and diagnostic copying',async()=>{
  for(const options of [{fetchAvailable:false},{initialJson:'<not-json>'}]){const f=fixture(options);assert.equal((f.ids['about-check-form'].listeners.submit||[]).length,0);await f.ids['about-copy'].fire('click');assert.equal(f.copies.length,1);assert.equal(f.calls.length,0);}
});


test('fresh positive badges are green while stale and ongoing checks remain neutral',()=>{
  const ready=fixture();assert.equal(ready.ids['about-comparison'].attrs['data-status'],'ok');assert.equal(ready.ids['about-check-state'].attrs['data-status'],'ok');
  const stale=fixture({snapshot:baseline({stale:true})});assert.equal(stale.ids['about-comparison'].attrs['data-status'],'neutral');assert.equal(stale.ids['about-check-state'].attrs['data-status'],'neutral');
  const busy=fixture({snapshot:baseline({check_state:'queued',can_check:false})});assert.equal(busy.ids['about-check-state'].attrs['data-status'],'neutral');
});
test('update-check acknowledgements and completion use shared toast while actionable failures persist',async()=>{
  const f=fixture({toast:true});await f.queue();
  assert.equal(f.toasts[0].tone,'neutral');assert.equal(f.toasts.at(-1).tone,'neutral');assert.equal(f.ids['about-feedback'].hidden,true);
  await f.poll(baseline());assert.equal(f.toasts.at(-1).tone,'ok');assert.equal(f.ids['about-feedback'].hidden,true);
  await f.queue(null,503,{error:'Check unavailable.'});assert.equal(f.ids['about-feedback'].hidden,false);assert.equal(f.ids['about-feedback'].textContent,'Check unavailable.');
});
test('manual status reads reserve success feedback for fresh completed release checks',async()=>{
  for (const [changes,tone] of [
    [{status:'never',comparison:'unknown',latest_version:null,stale:true,message:'Release information has not been checked yet.'},'neutral'],
    [{stale:true},'neutral'],
    [{check_state:'queued'},'neutral'],
    [{},'ok']
  ]) {
    const snapshot=baseline({...changes,worker_available:false,can_check:false});
    const f=fixture({snapshot,toast:true});
    await f.ids['about-refresh'].fire('click');f.respond(0,200,{snapshot});await settle();
    assert.equal(f.toasts.at(-1).tone,tone);assert.equal(f.toasts.at(-1).message,snapshot.message);
    assert.equal(f.ids['about-feedback'].hidden,true);
  }
});
test('queue acknowledgements remain neutral if the worker has already returned to idle',async()=>{
  const f=fixture({toast:true});await f.queue(baseline());
  assert.equal(f.toasts.at(-1).message,'Update check queued.');assert.equal(f.toasts.at(-1).tone,'neutral');
});
