/* Fixed owner actions; only recorded status can resolve an uncertain request. */
(() => {
  'use strict';
  const id = value => document.getElementById(value);
  const panel = id('maintenance-snapshot'), dialog = id('maintenance-confirm');
  const form = id('maintenance-confirm-form'), install = id('maintenance-install'), restart = id('maintenance-restart');
  const refresh = id('maintenance-refresh'), feedback = id('maintenance-feedback');
  if (!panel || !dialog || !form || !install || !restart || typeof fetch !== 'function' || typeof AbortController !== 'function') return;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const version = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/;
  const exact = (pattern, value) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
  const states = new Set(['queued','claimed','completed','aborted']);
  const reasons = {
    ready:'', unsupported:'In-app maintenance is not available for this installation.',
    not_enrolled:'In-app maintenance is not configured.',
    helper_unavailable:'Maintenance is unavailable. Refresh status to check again.',
    owner_unavailable:'Your session changed. Refresh the page and sign in again.',
    busy:'Maintenance is already in progress.', target_unavailable:'An update is not ready to install.',
    state_unavailable:'Maintenance status is unavailable. Refresh status to check again.'
  };
  const phases = {
    queued:'Waiting to start', accepted:'Starting', resolving:'Checking update', pulling:'Downloading update',
    draining:'Finishing current work', stopping:'Stopping Keep', 'backing-up':'Saving backup', prepared:'Backup ready',
    activating:'Starting Keep', verifying:'Checking Keep', committed:'Finishing', success:'Complete', failed:'Failed',
    'recovery-needed':'Recovery needed', recovering:'Restoring previous version',
    'recovery-committed':'Verifying recovery', recovered:'Previous version restored', held:'Needs attention'
  };
  const normalize = value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid maintenance status');
    for (const field of ['supported','enrolled','helper_available','can_install','can_restart'])
      if (typeof value[field] !== 'boolean') throw Error('Invalid capability');
    if (!Object.hasOwn(reasons, value.reason) || !exact(version, value.installed_version)
        || value.latest_version !== null && !exact(version, value.latest_version)
        || value.confirmation !== null && !exact(/^[a-f0-9]{64}$/, value.confirmation)) throw Error('Invalid maintenance status');
    if ((value.can_install || value.can_restart) && (!value.supported || !value.enrolled || !value.helper_available || !value.confirmation))
      throw Error('Unverified capability');
    if (value.can_install && !value.latest_version) throw Error('No update target');
    let operation = null;
    if (value.operation !== null) {
      const op = value.operation;
      const queuedWithoutProgress = op?.sequence === null && op?.phase === 'queued';
      const sequence = queuedWithoutProgress ? -1 : op?.sequence;
      if (!op || !exact(uuid, op.request_id) || !['install','restart'].includes(op.operation) || !states.has(op.state)
          || !Object.hasOwn(phases, op.phase) || !Number.isInteger(sequence) || sequence < 0 && !queuedWithoutProgress || sequence > 128
          || !exact(version, op.target_version)) throw Error('Invalid operation');
      operation = {request_id:op.request_id, operation:op.operation, state:op.state, phase:op.phase,
        sequence, target_version:op.target_version};
    }
    return {supported:value.supported, enrolled:value.enrolled, helper_available:value.helper_available,
      can_install:value.can_install, can_restart:value.can_restart, reason:value.reason,
      installed_version:value.installed_version, latest_version:value.latest_version, confirmation:value.confirmation,
      operation, requested_request_id:exact(uuid,value.requested_request_id)?value.requested_request_id:null,
      request_state:['queued','claimed','completed','aborted','not_received','unknown'].includes(value.request_state)?value.request_state:null};
  };
  let snapshot;
  try { snapshot = normalize(JSON.parse(panel.textContent)); } catch (_) { return; }
  const originalVersion = snapshot.installed_version;
  const storageKey = 'keep-maintenance-request';
  let pendingId = null, storageFailed = false, submitting = false, refreshing = false, stopped = false;
  let unauthorized = false, recovery = false, connectionLost = false, deadline = 0, timer = 0, mutation = 0, modal = null;
  const controllers = new Set();
  const text = (node, value) => { if (node && node.textContent !== value) node.textContent = value; };
  const notify = (message, error=false) => {
    text(feedback, message); feedback.hidden = !message; feedback.classList.toggle('is-error', error);
  };
  const cryptographicIds = () => Boolean(window.crypto?.randomUUID || window.crypto?.getRandomValues);
  const newId = () => {
    if (window.crypto?.randomUUID) return window.crypto.randomUUID();
    const bytes = window.crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    const hex = [...bytes].map(byte => byte.toString(16).padStart(2,'0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  };
  try {
    const saved = window.sessionStorage.getItem(storageKey);
    if (saved && exact(uuid,saved)) pendingId = saved;
    else if (saved) window.sessionStorage.removeItem(storageKey);
  } catch (_) { storageFailed = true; }
  const persist = value => {
    try {
      if (value) window.sessionStorage.setItem(storageKey,value);
      else window.sessionStorage.removeItem(storageKey);
      pendingId = value;
    } catch (_) { storageFailed = true; throw Error('Progress storage unavailable'); }
  };
  const terminalPhases = new Set(['success','failed','recovered']);
  const active = () => ['queued','claimed'].includes(snapshot.operation?.state)
    || snapshot.operation?.state === 'completed' && !terminalPhases.has(snapshot.operation.phase);
  const waiting = () => Boolean(pendingId) || active() || snapshot.reason === 'busy';
  const locked = () => submitting || refreshing || Boolean(pendingId) || active() || unauthorized || storageFailed || !cryptographicIds();
  const target = operation => operation === 'install' ? snapshot.latest_version : snapshot.installed_version;
  const permitted = operation => !locked() && snapshot.supported && snapshot.enrolled && snapshot.helper_available
    && Boolean(snapshot.confirmation) && (operation === 'install' ? snapshot.can_install : snapshot.can_restart);
  const render = () => {
    const eligible = snapshot.supported && snapshot.enrolled;
    id('maintenance-actions').hidden = !eligible;
    install.hidden = !snapshot.can_install && !(modal?.operation === 'install' || snapshot.operation?.operation === 'install' && active());
    install.disabled = !permitted('install'); restart.disabled = !permitted('restart');
    const reason = !snapshot.supported ? 'In-app maintenance is not available for this installation.'
      : storageFailed || !cryptographicIds() ? 'This browser cannot track maintenance. Use the update guide.'
      : unauthorized ? reasons.owner_unavailable : reasons[snapshot.reason];
    text(id('maintenance-reason'), reason); id('maintenance-reason').hidden = !reason;
    id('maintenance-guide').hidden = eligible && snapshot.helper_available && !storageFailed && cryptographicIds() && !unauthorized;
    const op = snapshot.operation;
    id('maintenance-operation').hidden = !op;
    if (op) {
      text(id('maintenance-operation-title'), `${op.operation === 'install' ? 'Update to' : 'Restart Keep'} ${op.target_version}`);
      text(id('maintenance-phase'), op.operation === 'restart' && op.phase === 'resolving' ? 'Checking installation' : phases[op.phase]);
    }
    refresh.hidden = !recovery && !waiting() && snapshot.reason !== 'helper_unavailable' && snapshot.reason !== 'state_unavailable';
    refresh.disabled = submitting || refreshing || unauthorized;
    id('maintenance-reload').hidden = !(snapshot.operation?.phase === 'success' && !active() && snapshot.installed_version !== originalVersion);
    if (dialog.open) id('maintenance-confirm-submit').disabled = !modal || !permitted(modal.operation);
  };
  const adopt = (body, recorded=false) => {
    const next = normalize(body.snapshot);
    if (snapshot.operation && next.operation?.request_id === snapshot.operation.request_id && next.operation.sequence < snapshot.operation.sequence)
      throw Error('Outdated operation');
    snapshot = next;
    const recordedTerminal = next.request_state === 'aborted' || next.request_state === 'not_received'
      || next.request_state === 'completed' && next.operation?.request_id === pendingId && terminalPhases.has(next.operation.phase);
    if (recorded && pendingId && next.requested_request_id === pendingId && recordedTerminal) persist(null);
    if (!pendingId && active()) { try { persist(next.operation.request_id); } catch (_) {} }
    if (dialog.open && modal && (modal.confirmation !== snapshot.confirmation || modal.target !== target(modal.operation))) {
      dialog.close(); notify('Maintenance status changed. Review the current action.', true);
    }
    render();
  };
  const request = async (url, options={}) => {
    const controller = new AbortController(); controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(), Math.max(1,Math.min(15000,deadline?deadline-Date.now():15000)));
    try {
      const response = await fetch(url,{credentials:'same-origin',cache:'no-store',...options,signal:controller.signal,
        headers:{Accept:'application/json',...options.headers}});
      if (response.redirected || [401,403].includes(response.status)) {
        const error = Error('Your session changed. Refresh the page and sign in again.'); error.unauthorized = true; throw error;
      }
      const body = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error('Invalid response');
      return {response,body};
    } finally { clearTimeout(timeout); controllers.delete(controller); }
  };
  const wait = () => {
    recovery = true; render();
    notify('Keep has not confirmed completion. Refresh status to check again.', true);
  };
  const plan = () => {
    clearTimeout(timer);
    if (stopped || document.hidden || unauthorized || recovery || submitting) return;
    if (waiting()) {
      if (!deadline) deadline = Date.now()+300000;
      if (Date.now() >= deadline) { wait(); return; }
      timer = setTimeout(() => void readStatus(), Math.min(2000,deadline-Date.now()));
    } else deadline = 0;
  };
  const completion = () => {
    const op = snapshot.operation;
    if (op?.phase === 'success') notify(`Keep ${op.target_version} is ready.`);
    else if (op?.phase === 'recovered') notify('The previous version was restored.', true);
    else if (op?.state === 'aborted' || op?.phase === 'failed') notify('Maintenance did not complete.', true);
    else if (op?.phase === 'held' || op?.phase === 'recovery-needed') notify('Maintenance needs attention. Check the installation before continuing.', true);
  };
  async function readStatus(manual=false) {
    if (stopped || document.hidden || unauthorized || submitting || refreshing) return;
    if (manual) { recovery=false; deadline=Date.now()+300000; }
    if (!manual && deadline && Date.now()>=deadline) { wait(); return; }
    const epoch=mutation, query=pendingId?`?request_id=${encodeURIComponent(pendingId)}`:'';
    refreshing=true; render();
    try {
      const {response,body}=await request(`/settings/about/maintenance/status${query}`);
      if (stopped || epoch!==mutation) return;
      if (!response.ok) throw Error('Status unavailable');
      const wasPending=pendingId;
      adopt(body,true); recovery=false;
      if (!pendingId && !active()) {
        if (wasPending && snapshot.request_state==='not_received') notify('The request was not received. You can try again.');
        else completion();
        if (!snapshot.operation && manual && !wasPending) notify('Maintenance status refreshed.');
      } else if (snapshot.request_state==='unknown') notify('Keep could not confirm this request. Checking its recorded status.',true);
      else if (snapshot.operation?.phase==='held' || snapshot.operation?.phase==='recovery-needed') completion();
      else if (connectionLost) notify('Reconnected. Maintenance is in progress.');
      connectionLost=false;
    } catch (error) {
      if (stopped || epoch!==mutation) return;
      if (error.unauthorized) { unauthorized=true; recovery=false; notify(error.message,true); }
      else if (pendingId || active()) { connectionLost=true; notify('Connection lost. Waiting to reconnect to Keep.',true); }
      else { recovery=true; notify('Could not read maintenance status. Refresh status to try again.',true); }
    } finally {
      if (!stopped && epoch===mutation) { refreshing=false; render(); plan(); }
    }
  }
  const open = (operation,trigger) => {
    if (!permitted(operation) || dialog.open) return;
    modal={operation,trigger,target:target(operation),confirmation:snapshot.confirmation,accepted:false};
    text(id('maintenance-confirm-title'),operation==='install'?'Install update':'Restart Keep');
    text(id('maintenance-confirm-description'),`${operation==='install'?'Install Keep':'Restart Keep'} ${modal.target}?`);
    text(id('maintenance-confirm-submit'),operation==='install'?'Install update':'Restart');
    dialog.showModal(); id('maintenance-confirm-cancel').focus({preventScroll:true}); render();
  };
  install.addEventListener('click',()=>open('install',install));
  restart.addEventListener('click',()=>open('restart',restart));
  id('maintenance-confirm-cancel').addEventListener('click',()=>dialog.close());
  dialog.addEventListener('keydown',event=>{
    if (!dialog.open || event.key !== 'Tab') return;
    const first=id('maintenance-confirm-cancel'), last=id('maintenance-confirm-submit');
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault(); last.focus({preventScroll:true});
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus({preventScroll:true});
    }
  });
  dialog.addEventListener('close',()=>{
    const previous=modal; modal=null; render();
    if (previous?.accepted) feedback.focus({preventScroll:true});
    else (previous?.trigger && !previous.trigger.disabled && !previous.trigger.hidden ? previous.trigger : id('maintenance-title')).focus({preventScroll:true});
  });
  form.addEventListener('submit',async event=>{
    event.preventDefault();
    if (!modal || !permitted(modal.operation)) return;
    if (modal.confirmation!==snapshot.confirmation || modal.target!==target(modal.operation)) { dialog.close(); notify('Maintenance status changed. Review the current action.',true); return; }
    let requestId;
    try { requestId=newId(); if (!exact(uuid,requestId)) throw Error('Invalid request ID'); persist(requestId); }
    catch (_) { storageFailed=true; dialog.close(); render(); notify('This browser cannot track maintenance. Use the update guide.',true); return; }
    const operation=modal.operation, confirmation=modal.confirmation;
    modal.accepted=true; submitting=true; recovery=false; deadline=Date.now()+300000;
    const epoch=++mutation; controllers.forEach(controller=>controller.abort()); clearTimeout(timer); refreshing=false;
    notify('Requesting maintenance…'); dialog.close(); render();
    try {
      const {response,body}=await request('/settings/about/maintenance/start',{method:'POST',
        headers:{'Content-Type':'application/json','X-CSRF-Token':id('maintenance-csrf').value},
        body:JSON.stringify({request_id:requestId,operation,confirmation})});
      if (stopped || epoch!==mutation) return;
      if (body.snapshot) { try { adopt(body); } catch (_) {} }
      if (!response.ok) notify(typeof body.error==='string'&&body.error.length<=600?body.error:'Keep could not confirm the request. Checking its recorded status.',true);
      else notify('Maintenance requested.');
    } catch (error) {
      if (stopped || epoch!==mutation) return;
      if (error.unauthorized) { unauthorized=true; notify(error.message,true); }
      else notify('Keep could not confirm the request. Checking its recorded status.',true);
    } finally {
      if (!stopped && epoch===mutation) { submitting=false; render(); plan(); }
    }
  });
  refresh.addEventListener('click',()=>void readStatus(true));
  id('maintenance-reload').addEventListener('click',()=>window.location.reload());
  window.addEventListener('keep-release-updated',()=>void readStatus());
  document.addEventListener('visibilitychange',()=>{
    clearTimeout(timer); if (!document.hidden&&!stopped) { recovery=false; deadline=0; void readStatus(); }
  });
  window.addEventListener('pagehide',()=>{
    stopped=true; clearTimeout(timer); ++mutation; submitting=refreshing=false;
    controllers.forEach(controller=>controller.abort());
  });
  window.addEventListener('pageshow',()=>{
    if (!stopped) return; stopped=false; recovery=false; deadline=0; render(); void readStatus();
  });
  if (!pendingId&&active()) { try { persist(snapshot.operation.request_id); } catch (_) {} }
  render();
  if (pendingId) void readStatus(); else plan();
})();
