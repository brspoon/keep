/* Keep the recorded Plex sync and user list current without replacing editors. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const form = byId('plex-user-sync-form'), button = byId('plex-user-sync-button');
  const status = byId('plex-user-sync-status');
  const endpoint = '/settings/users/plex-sync';
  const statuses = new Set(['waiting', 'success', 'failed', 'review', 'stale', 'disabled', 'running', 'queued', 'interrupted']);
  const plain = value => typeof value === 'string' && value.length <= 2000 ? value : '';
  const normalize = value => {
    if (!value || value.id !== 'plex-access-sync' || !statuses.has(value.status)
        || typeof value.queued !== 'boolean' || typeof value.can_run !== 'boolean') throw new Error('Invalid Plex user status');
    return {...value, label:plain(value.label), result:plain(value.result), action_reason:plain(value.action_reason),
      last_run:plain(value.last_run), last_success:plain(value.last_success)};
  };
  let job;
  try { job = normalize(JSON.parse(byId('plex-user-sync-snapshot')?.textContent || 'null')); } catch (_) { return; }
  if (!form || !button || !status || typeof fetch !== 'function' || typeof AbortController !== 'function') return;

  let pending = false, reading = false, uncertain = false, unauthorized = false, stopped = false;
  let retryFailure = false, statusFailures = 0, listFailures = 0, generation = 0;
  let timer, listTimer, activeList = null;
  const controllers = new Map();
  const busy = () => job.queued || job.status === 'running' || job.status === 'queued';
  const successMarker = value => value.last_success
    || (value.status === 'success' || value.last_attempt_status === 'success' ? value.last_run : '');
  let wantedList = successMarker(job), appliedList = wantedList;
  let fastUntil = busy() ? Date.now() + 120000 : 0;
  const needsList = () => Boolean(wantedList && wantedList !== appliedList);
  const failed = () => ['failed', 'review', 'interrupted'].includes(job.status) || retryFailure;
  const detail = () => job.result && !['Completed', 'No recorded run'].includes(job.result) ? ` ${job.result}` : '';
  const summary = () => {
    if (unauthorized) return 'Your session expired or access changed. Sign in again to continue.';
    if (pending) return 'Queuing Plex user sync…';
    if (uncertain) return 'Checking the recorded Plex sync status…';
    if (needsList()) return listFailures ? 'Plex sync completed. Updating users will retry automatically.' : 'Updating Plex users…';
    if (failed()) return `Plex user sync ${retryFailure ? 'failed. Keep will retry automatically.'
      : job.status === 'review' ? 'needs review.' : job.status === 'interrupted' ? 'was interrupted.' : 'failed.'}${detail()}`;
    if (job.status === 'running') return 'Syncing Plex users…';
    if (busy()) return 'Plex user sync queued.';
    if (job.status === 'success') return 'Plex users synced.';
    return job.action_reason || `${job.label || 'No Plex user sync recorded yet.'}${detail()}`;
  };
  const message = (value, tone = 'neutral', toast = false) => {
    status.textContent = value;
    status.setAttribute('data-status', tone);
    if (toast) window.showToast?.(value, tone);
  };
  const controls = () => {
    button.disabled = pending || reading || unauthorized || uncertain || busy() || !job.can_run;
    button.textContent = pending ? 'Queuing…' : job.status === 'running' ? 'Syncing…' : busy() ? 'Queued' : 'Sync Plex users';
    form.setAttribute('aria-busy', String(pending || uncertain || busy()));
  };
  const render = () => { message(summary(), unauthorized || failed() ? 'error' : 'neutral'); controls(); };
  const available = () => !stopped && !document.hidden && !unauthorized;
  const backoff = (base, failures) => Math.min(60000, base * 2 ** Math.min(failures, 5));
  const plan = () => {
    clearTimeout(timer);
    if (!available()) return;
    const fast = (busy() || uncertain) && Date.now() < fastUntil;
    timer = setTimeout(() => void readStatus(), backoff(fast ? 3000 : 15000, statusFailures));
  };
  const planList = (immediate = false) => {
    clearTimeout(listTimer);
    if (!available() || !needsList() || activeList) return;
    listTimer = setTimeout(() => void updateUsers(), immediate ? 0 : backoff(3000, listFailures));
  };
  async function updateUsers() {
    if (!available() || !needsList() || activeList) return;
    clearTimeout(listTimer);
    const attempt = {generation, marker:wantedList}; activeList = attempt;
    let succeeded = false;
    try {
      succeeded = typeof window.KeepUsers?.refresh === 'function' && await window.KeepUsers.refresh() === true;
      if (!available() || attempt.generation !== generation) return;
      if (succeeded) {
        appliedList = attempt.marker; listFailures = 0;
        if (!needsList()) {
          render();
          if (!pending && !uncertain && !busy() && !failed()) message('Plex users synced.', 'ok', true);
        }
      } else { listFailures++; render(); }
    } catch (_) {
      if (!available() || attempt.generation !== generation) return;
      listFailures++; render();
    } finally {
      if (activeList === attempt) activeList = null;
      if (available() && needsList()) planList(succeeded || attempt.generation !== generation);
    }
  }
  const adopt = (next, announce = true) => {
    const previous = job, wasBusy = busy();
    job = normalize(next);
    const newAttempt = Boolean(job.last_run && (job.last_run !== previous.last_run
      || job.last_attempt_status !== previous.last_attempt_status));
    if (job.status === 'running' || !busy()) retryFailure = false;
    if (newAttempt && busy() && job.last_attempt_status === 'failed') retryFailure = true;
    if (busy() && !wasBusy) fastUntil = Date.now() + 120000;
    if (!busy() && !uncertain) fastUntil = 0;
    const nextSuccess = successMarker(job), newSuccess = Boolean(nextSuccess && nextSuccess !== wantedList);
    if (newSuccess) { wantedList = nextSuccess; listFailures = 0; }
    render();
    if (announce && newAttempt && failed()) message(summary(), 'error', true);
    if (newSuccess) void updateUsers();
    return newSuccess;
  };
  async function request(options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    controllers.set(controller, timeout);
    try {
      const response = await fetch(endpoint, {...options, credentials:'same-origin', cache:'no-store',
        signal:controller.signal, headers:{Accept:'application/json'}});
      if (response.redirected || [401, 403].includes(response.status)) {
        const error = new Error('Session unavailable'); error.unauthorized = true; throw error;
      }
      const body = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid Plex user status');
      return {response, body};
    } finally { clearTimeout(timeout); controllers.delete(controller); }
  }
  async function readStatus() {
    if (!available() || pending || reading) return;
    reading = true; controls();
    const version = generation;
    try {
      const {response, body} = await request({method:'GET'});
      if (!available() || version !== generation) return;
      if (!response.ok) throw new Error('Status unavailable');
      // A fresh recorded read resolves an uncertain POST, including idle state.
      const next = normalize(body.job);
      uncertain = false; statusFailures = 0;
      adopt(next);
    } catch (error) {
      if (stopped || version !== generation) return;
      if (error.unauthorized) { unauthorized = true; clearTimeout(listTimer); render(); }
      else { statusFailures++; message('Could not check Plex sync status. Retrying automatically.', 'error'); }
    } finally {
      if (!stopped && version === generation) { reading = false; controls(); plan(); }
    }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!available() || pending || reading || uncertain || busy() || !job.can_run) return;
    pending = true; retryFailure = false; statusFailures = 0;
    fastUntil = Date.now() + 120000; clearTimeout(timer); render();
    const version = generation;
    try {
      const {response, body} = await request({method:'POST', body:new URLSearchParams(new FormData(form))});
      if (!available() || version !== generation) return;
      if (!response.ok) {
        if (body.job) { try { adopt(body.job, false); } catch (_) {} }
        const error = new Error(plain(body.error) || 'Plex user sync could not be queued.');
        error.confirmed = response.status < 500; throw error;
      }
      pending = false;
      const completed = adopt(body.job);
      if (!busy() && !completed) { uncertain = true; fastUntil = Date.now() + 120000; }
      if (!completed) message(plain(body.message) || 'Plex user sync queued.', 'neutral', true);
    } catch (error) {
      if (stopped || version !== generation) return;
      if (error.unauthorized) { unauthorized = true; clearTimeout(listTimer); render(); }
      else if (error.confirmed) message(error.message, 'error');
      else {
        uncertain = true;
        if (!fastUntil) fastUntil = Date.now() + 120000;
        message('Keep could not confirm the sync. Checking its recorded status.', 'error');
      }
    } finally {
      if (!stopped && version === generation) { pending = false; controls(); plan(); }
    }
  });
  const pause = () => {
    clearTimeout(timer); clearTimeout(listTimer); ++generation;
    uncertain = uncertain || pending;
    if (uncertain && !fastUntil) fastUntil = Date.now() + 120000;
    pending = reading = false;
    controllers.forEach((timeout, controller) => { clearTimeout(timeout); controller.abort(); });
    controllers.clear(); controls();
  };
  const resume = () => {
    controls();
    if (!available()) return;
    void readStatus();
    if (needsList()) void updateUsers();
  };
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) pause(); else if (!stopped) resume();
  });
  window.addEventListener('pagehide', () => { stopped = true; pause(); });
  window.addEventListener('pageshow', () => {
    if (stopped || unauthorized) { stopped = unauthorized = false; statusFailures = 0; resume(); }
  });
  render(); plan();
})();
