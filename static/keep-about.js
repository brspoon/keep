/* Owner release checks use recorded worker state; the browser never contacts GitHub. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const feedback = byId('about-feedback'), copy = byId('about-copy');
  const diagnostics = byId('about-diagnostics'), diagnosticDetails = byId('about-diagnostics-details');
  const copyFeedback = byId('about-copy-feedback');
  let latestDiagnostics = diagnostics?.value || '';
  const text = (node, value) => { if (node) node.textContent = String(value ?? ''); };
  const syncDiagnostics = () => {
    if (!diagnostics || document.activeElement === diagnostics && diagnostics.selectionStart !== diagnostics.selectionEnd) return;
    diagnostics.value = latestDiagnostics;
  };
  diagnostics?.addEventListener('blur', syncDiagnostics);
  copy?.addEventListener('click', async () => {
    if (!diagnostics || copy.disabled) return;
    copy.disabled = true;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(diagnostics.value);
      text(copyFeedback, 'Copied.');
    } catch (_) {
      if (diagnosticDetails) diagnosticDetails.open = true;
      diagnostics.focus({preventScroll:true}); diagnostics.select();
      text(copyFeedback, 'Copy the selected diagnostics.');
    } finally { copy.disabled = false; if (copyFeedback) copyFeedback.hidden = false; }
  });

  const form = byId('about-check-form'), check = byId('about-check'), retry = byId('about-refresh');
  const statuses = new Set(['never', 'success', 'failed', 'rate_limited']);
  const comparisons = new Set(['unknown', 'update_available', 'up_to_date', 'ahead']);
  const states = new Set(['idle', 'queued', 'running']);
  const versionPattern = /^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$/;
  const validVersion = value => typeof value === 'string' && versionPattern.exec(value)?.[0] === value;
  const releaseUrl = tag => typeof tag === 'string' && validVersion(tag.replace(/^v/, ''))
    ? `https://github.com/brspoon/keep/releases/tag/${encodeURIComponent(tag)}` : null;
  const normalize = value => {
    if (!value || !statuses.has(value.status) || !comparisons.has(value.comparison) || !states.has(value.check_state)
      || typeof value.can_check !== 'boolean' || typeof value.worker_available !== 'boolean') throw new Error('Invalid release status');
    const latest = validVersion(value.latest_version) ? value.latest_version : null;
    return {...value, installed_version:validVersion(value.installed_version) ? value.installed_version : 'Unknown',
      latest_version:latest, comparison:value.status === 'success' && value.stale === false && latest ? value.comparison : 'unknown',
      version_refresh_pending:value.version_refresh_pending === true,
      stale:value.stale !== false, reason:typeof value.reason === 'string' ? value.reason : '',
      message:typeof value.message === 'string' ? value.message : 'Release information checked.',
      retry_after_seconds:Number.isInteger(value.retry_after_seconds) && value.retry_after_seconds > 0 ? Math.min(value.retry_after_seconds, 86400) : 0};
  };
  let snapshot;
  try { snapshot = normalize(JSON.parse(byId('about-snapshot')?.textContent || 'null')); } catch (_) { return; }
  if (!form || !check || typeof fetch !== 'function') return;
  const dateFormat = new Intl.DateTimeFormat(undefined, {dateStyle:'medium', timeStyle:'short'});
  let pending = false, refreshing = false, uncertain = false, unauthorized = false, stopped = false;
  let recovery = false, timer, deadline = 0, mutationVersion = 0, pollController;
  let releasesSignature = '';
  const controllers = new Set();
  const busy = () => snapshot.check_state !== 'idle';
  const awaitingCheck = () => busy() || uncertain || snapshot.version_refresh_pending && snapshot.worker_available;
  const failed = () => ['failed', 'rate_limited'].includes(snapshot.status);
  const newFailure = previous => failed() && ['status', 'last_attempt_at', 'error_code'].some(key => snapshot[key] !== previous[key]);
  const notify = (message, error = false, tone = !busy() && snapshot.status === 'success' && !snapshot.stale ? 'ok' : 'neutral') => {
    text(feedback, message); if (!feedback) return;
    feedback.hidden = !message || !error && typeof window.showToast === 'function';
    feedback.classList.toggle('is-error', error);
    if (message && !error) window.showToast?.(message, tone);
  };
  const formatTime = (node, value, fallback = 'Not checked') => {
    const date = new Date(value || '');
    if (Number.isNaN(date.getTime())) { text(node, fallback); return; }
    const time = document.createElement('time'); time.dateTime = value;
    time.textContent = dateFormat.format(date); time.title = date.toLocaleString(undefined, {timeZoneName:'short'});
    node?.replaceChildren(time);
  };
  const controls = () => {
    check.disabled = pending || uncertain || unauthorized || busy() || !snapshot.can_check || !snapshot.worker_available;
    text(check, pending ? 'Queuing…' : snapshot.check_state === 'queued' ? 'Queued' : snapshot.check_state === 'running' ? 'Checking…' : 'Check for updates');
    form.setAttribute('aria-busy', String(pending || busy()));
    if (retry) { retry.hidden = !recovery && snapshot.worker_available || unauthorized; retry.disabled = pending || refreshing; }
  };
  const badge = (label, status = 'ok') => {
    const node = document.createElement('span'); node.className = 'about-badge status-badge';
    node.setAttribute('data-status', status); node.textContent = label; return node;
  };
  const renderReleases = () => {
    const releases = Array.isArray(snapshot.releases) ? snapshot.releases.slice(0, 5).filter(release =>
      release && releaseUrl(release.tag) && release.version === release.tag.replace(/^v/, '')) : [];
    const signature = JSON.stringify([releases.map(({version, tag, published_at}) => ({version, tag, published_at})),
      snapshot.installed_version, snapshot.latest_tag, snapshot.stale]);
    const empty = byId('about-releases-empty'); if (empty) empty.hidden = releases.length > 0;
    if (signature === releasesSignature) return;
    releasesSignature = signature;
    const rows = releases.map(release => {
      const row = document.createElement('article'); row.className = 'about-release';
      const main = document.createElement('div'); main.className = 'about-release-main';
      const title = document.createElement('div'); title.className = 'about-release-title';
      const heading = document.createElement('h3'); heading.textContent = release.version; title.append(heading);
      if (release.version === snapshot.installed_version) title.append(badge('Current'));
      if (release.tag === snapshot.latest_tag) title.append(badge(snapshot.stale ? 'Last known' : 'Latest', snapshot.stale ? 'neutral' : 'ok'));
      const published = document.createElement('div'); formatTime(published, release.published_at, '');
      const link = document.createElement('a'); link.className = 'about-link secondary';
      link.href = releaseUrl(release.tag); link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = 'View changelog';
      const context = document.createElement('span'); context.className = 'visually-hidden';
      context.textContent = ` for ${release.version} (opens a new tab)`; link.append(context);
      main.append(title, published); row.append(main, link); return row;
    });
    byId('about-releases')?.replaceChildren(...rows);
  };
  const render = () => {
    text(byId('about-installed'), snapshot.installed_version);
    text(byId('about-latest'), snapshot.latest_version || 'Not checked');
    const comparison = byId('about-comparison');
    const label = snapshot.stale && snapshot.latest_version ? 'Last known'
      : ({update_available:'Update available', up_to_date:'Up to date', ahead:'Ahead of latest stable'})[snapshot.comparison] || '';
    text(comparison, label);
    if (comparison) {
      comparison.hidden = !label;
      comparison.setAttribute('data-comparison', snapshot.comparison);
      comparison.setAttribute('data-status', snapshot.comparison === 'up_to_date' ? 'ok' : snapshot.comparison === 'update_available' ? 'warn' : 'neutral');
    }
    formatTime(byId('about-last-check'), snapshot.last_attempt_at);
    text(byId('about-check-state'), snapshot.check_state === 'queued' ? 'Queued' : snapshot.check_state === 'running' ? 'Checking'
      : ({never:'Not checked', success:'Checked', failed:'Failed', rate_limited:'Rate limited'})[snapshot.status]);
    byId('about-check-state')?.setAttribute('data-status', busy() ? 'neutral' : snapshot.status === 'failed' ? 'error'
      : snapshot.status === 'rate_limited' ? 'warn' : snapshot.status === 'success' && !snapshot.stale ? 'ok' : 'neutral');
    const reason = byId('about-check-reason'); text(reason, snapshot.reason);
    if (reason) reason.hidden = !snapshot.reason || busy() && snapshot.worker_available;
    renderReleases(); controls();
  };
  const adopt = body => {
    snapshot = normalize(body.snapshot);
    if (typeof body.diagnostics === 'string' && body.diagnostics.length <= 20000) {
      latestDiagnostics = body.diagnostics; syncDiagnostics();
    }
    render();
  };
  async function request(url, options = {}, polling = false) {
    const controller = new AbortController(); controllers.add(controller);
    if (polling) pollController = controller;
    const timeout = setTimeout(() => controller.abort(), polling && deadline ? Math.max(1, Math.min(15000, deadline - Date.now())) : 15000);
    try {
      const response = await fetch(url, {...options, credentials:'same-origin', cache:'no-store', signal:controller.signal,
        headers:{Accept:'application/json'}});
      if (response.redirected || [401, 403].includes(response.status)) {
        let message = 'Your session expired. Refresh the page and sign in again.';
        try { const body = await response.json(); if (typeof body.error === 'string') message = body.error; } catch (_) {}
        const error = new Error(message); error.unauthorized = true; throw error;
      }
      const body = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid release status');
      return {response, body};
    } finally { clearTimeout(timeout); controllers.delete(controller); if (pollController === controller) pollController = null; }
  }
  const waitMessage = () => {
    recovery = true; controls();
    notify(failed() ? snapshot.message : 'The check is still pending. Refresh status to check again.', true);
  };
  const plan = () => {
    clearTimeout(timer);
    if (stopped || document.hidden || unauthorized) return;
    if (awaitingCheck()) {
      if (!deadline) deadline = Date.now() + 120000;
      if (Date.now() >= deadline) { waitMessage(); return; }
      timer = setTimeout(() => void refreshStatus(), Math.min(2000, deadline - Date.now()));
    } else {
      deadline = 0;
      if (!recovery && !snapshot.can_check && snapshot.worker_available && snapshot.retry_after_seconds > 0)
        timer = setTimeout(() => void refreshStatus(), snapshot.retry_after_seconds * 1000 + 100);
    }
  };
  async function refreshStatus(manual = false) {
    if (stopped || document.hidden || refreshing || pending || unauthorized) return;
    if (!manual && deadline && Date.now() >= deadline) { waitMessage(); return; }
    if (manual) { deadline = Date.now() + 120000; recovery = false; }
    refreshing = true; controls();
    const version = mutationVersion, wasBusy = awaitingCheck();
    try {
      const {response, body} = await request('/settings/about/status', {}, true);
      if (stopped || version !== mutationVersion) return;
      const previous = snapshot;
      adopt(body);
      if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : 'Could not refresh release information.');
      uncertain = false; recovery = false;
      if (newFailure(previous) || (wasBusy && !awaitingCheck()) || manual) notify(snapshot.message, failed());
    } catch (error) {
      if (stopped || version !== mutationVersion) return;
      if (error.unauthorized) { unauthorized = true; recovery = false; notify(error.message, true); }
      else if (wasBusy) notify('Connection lost. Keep will retry.', true);
      else { recovery = true; notify('Could not refresh release information. Refresh status to try again.', true); }
    } finally {
      if (!stopped && version === mutationVersion) { refreshing = false; controls(); plan(); }
    }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (pending || uncertain || unauthorized || busy() || !snapshot.can_check || !snapshot.worker_available) return;
    pending = true; recovery = false; deadline = 0;
    const version = ++mutationVersion; pollController?.abort(); refreshing = false; clearTimeout(timer); controls();
    notify('Checking for updates…', false, 'neutral');
    try {
      const {response, body} = await request('/settings/about/check', {method:'POST', body:new URLSearchParams(new FormData(form))});
      if (stopped || version !== mutationVersion) return;
      if (!response.ok) {
        if (body.snapshot) { try { adopt(body); } catch (_) {} }
        const error = new Error(typeof body.error === 'string' ? body.error : 'The check could not be queued.');
        error.confirmed = true; throw error;
      }
      const previous = snapshot;
      adopt(body);
      if (newFailure(previous)) notify(snapshot.message, true);
      else notify(typeof body.message === 'string' ? body.message : busy() ? 'Release check queued.' : snapshot.message, !busy() && failed(), 'neutral');
    } catch (error) {
      if (stopped || version !== mutationVersion) return;
      if (error.unauthorized) { unauthorized = true; notify(error.message, true); }
      else if (error.confirmed) notify(error.message, true);
      else { uncertain = true; notify('Keep could not confirm the check. Refreshing its status.', true); }
    } finally {
      if (!stopped && version === mutationVersion) { pending = false; controls(); plan(); }
    }
  });
  retry?.addEventListener('click', () => void refreshStatus(true));
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (!document.hidden && !stopped) { deadline = 0; void refreshStatus(); }
  });
  window.addEventListener('pagehide', () => {
    stopped = true; clearTimeout(timer); ++mutationVersion;
    uncertain = uncertain || pending; pending = refreshing = false;
    controllers.forEach(controller => controller.abort());
  });
  window.addEventListener('pageshow', () => {
    if (!stopped) return;
    stopped = false; deadline = 0; controls(); void refreshStatus();
  });
  render(); plan();
})();
