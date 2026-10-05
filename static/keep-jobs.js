(() => {
  'use strict';
  const format = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  const rows = new Map(Array.from(document.querySelectorAll('[data-job-id]'), row => [row.dataset.jobId, row]));
  const feedback = document.getElementById('jobs-feedback');
  const dialog = document.getElementById('job-schedule-dialog');
  const scheduleForm = document.getElementById('job-schedule-form');
  const interval = document.getElementById('job-interval');
  const currentFrequency = document.getElementById('job-current-frequency');
  const scheduleError = document.getElementById('job-schedule-error');
  const save = document.getElementById('job-save-schedule');
  const cancel = dialog?.querySelector('[data-cancel-schedule]');
  let selectedRow = null, opener = null, saving = false, refreshing = false, stopped = false, timer, countdownTimer, mutationVersion = 0;
  const statuses = new Set(['success', 'failed', 'review', 'stale', 'waiting', 'disabled', 'running', 'queued', 'interrupted']);
  const terminalStatuses = new Set(['success', 'failed', 'review', 'waiting', 'interrupted', 'disabled', 'stale']);
  const announcementVersions = new WeakMap();

  function text(node, value) {
    if (node && node.textContent !== String(value || '')) node.textContent = String(value || '');
  }
  function relativeTime(date, compact = true) {
    let seconds = Math.ceil((date.getTime() - Date.now()) / 1000);
    if (seconds <= 0) return 'Due now';
    const parts = [];
    for (const [short, unit, divisor] of [['d', 'day', 86400], ['h', 'hour', 3600], ['m', 'minute', 60], ['s', 'second', 1]]) {
      const value = Math.floor(seconds / divisor);
      if (value || parts.length || short === 's') parts.push(compact ? `${value}${short}` : `${value} ${unit}${value === 1 ? '' : 's'}`);
      seconds %= divisor;
    }
    return `in ${parts.join(compact ? ' ' : ', ')}`;
  }
  function formatCountdown(element, date) {
    text(element, relativeTime(date));
    element.setAttribute('aria-label', relativeTime(date, false));
  }
  function formatTime(element) {
    const date = new Date(element.dateTime);
    if (Number.isNaN(date.getTime())) return;
    if (element.hasAttribute('data-relative')) formatCountdown(element, date);
    else text(element, format.format(date));
    element.title = date.toLocaleString(undefined, {timeZoneName: 'short'});
  }
  function updateTime(container, value, fallback, isRelative = false) {
    if (!container) return;
    if (!value) { text(container, fallback); return; }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) { text(container, fallback); return; }
    let element = container.querySelector('time');
    if (!element) { element = document.createElement('time'); container.replaceChildren(element); }
    element.dateTime = value;
    if (isRelative) element.setAttribute('data-relative', '');
    formatTime(element);
  }
  function updateCountdowns() {
    rows.forEach(row => {
      const element = row.querySelector('[data-next-run]')?.querySelector('time');
      if (!element) return;
      const date = new Date(element.dateTime);
      if (!Number.isNaN(date.getTime())) formatCountdown(element, date);
    });
  }
  function planCountdown() {
    clearTimeout(countdownTimer);
    if (stopped || document.hidden || !rows.size) return;
    updateCountdowns();
    // Derive every tick from the scheduled timestamp so delayed timers catch up.
    countdownTimer = setTimeout(planCountdown, 1000 - Date.now() % 1000);
  }
  function notify(message, failed = false) {
    if (!feedback) return;
    text(feedback, message);
    feedback.hidden = false;
    feedback.classList.toggle('is-error', failed);
  }
  function clearAnnouncement(row) {
    announcementVersions.set(row, (announcementVersions.get(row) || 0) + 1);
    row.dataset.announcedAttempt = '';
    text(row.querySelector('[data-job-announcement]'), '');
  }
  function announceResult(row, job, status, retrying = false) {
    const marker = `${status}:${job.last_run || ''}`;
    if (row.dataset.announcedAttempt === marker) return;
    row.dataset.announcedAttempt = marker;
    const announcement = row.querySelector('[data-job-announcement]');
    if (!announcement) return;
    const title = row.querySelector('[data-job-title]').textContent;
    const outcome = ({success: 'Completed', failed: 'Failed', review: 'Needs review', interrupted: 'Interrupted'})[status] || job.label;
    const detail = job.result && !['Completed', 'No recorded run'].includes(job.result) ? ` ${job.result}` : '';
    const retryNote = retrying ? `${detail && !/[.!?]$/.test(detail) ? '.' : ''} Keep will retry automatically.` : '';
    const message = `${title}: ${outcome}.${detail}${retryNote}`;
    const version = (announcementVersions.get(row) || 0) + 1;
    announcementVersions.set(row, version);
    if (announcement.textContent === message) {
      // A second finished attempt can have the same result. Separate the live-region
      // mutations so assistive technology receives the new attempt once as well.
      text(announcement, '');
      setTimeout(() => { if (announcementVersions.get(row) === version) text(announcement, message); }, 0);
    } else text(announcement, message);
  }
  function syncControls(row) {
    const pending = row.dataset.pending === 'true', busy = row.dataset.busy === 'true';
    const editable = row.dataset.editable === 'true', enhanced = row.dataset.scheduleEnhanced === 'true';
    const run = row.querySelector('[data-run-job] button');
    if (run) run.disabled = pending || busy || row.dataset.canRun !== 'true';
    const edit = row.querySelector('[data-edit-job]');
    if (edit) { edit.disabled = pending || !editable; edit.hidden = !enhanced || !editable; }
    const fallback = row.querySelector('[data-schedule-fallback]');
    if (fallback) fallback.hidden = enhanced || !editable;
    const source = row.querySelector('[data-schedule-job]');
    if (source) {
      source.querySelector('select').disabled = !editable;
      source.querySelector('button[type="submit"]').disabled = pending || !editable;
    }
  }
  function updateRow(row, job) {
    const wasBusy = row.dataset.busy === 'true';
    const wasDisabled = row.dataset.status === 'disabled';
    const newAttempt = Boolean(job.last_run && job.last_run !== row.dataset.lastAttempt);
    row.dataset.canRun = String(Boolean(job.can_run));
    row.dataset.editable = String(Boolean(job.editable));
    row.dataset.busy = String(Boolean(job.queued || job.status === 'running'));
    row.dataset.interval = job.interval == null ? '' : String(job.interval);
    row.dataset.status = job.status;
    row.dataset.lastAttempt = job.last_run || '';
    const status = row.querySelector('[data-job-status]');
    text(status, job.label);
    if (status) status.className = `job-status job-status-${statuses.has(job.status) ? job.status : 'waiting'}`;
    const result = row.querySelector('[data-job-result]');
    text(result, job.result);
    if (result) result.hidden = !job.result || ['Completed', 'No recorded run'].includes(job.result);
    text(row.querySelector('[data-job-schedule]'), job.schedule);
    text(row.querySelector('[data-run-label]'), job.queued ? 'Queued' : job.status === 'running' ? 'Running' : 'Run now');
    const reason = row.querySelector('[data-action-reason]');
    text(reason, job.action_reason);
    if (reason) reason.hidden = !job.action_reason;
    updateTime(row.querySelector('[data-last-run]'), job.last_run, 'Not run yet');
    updateTime(row.querySelector('[data-next-run]'), job.next_run, '—', true);
    const duration = row.querySelector('[data-job-duration]');
    text(duration, job.duration);
    if (duration) duration.hidden = !job.duration;
    syncControls(row);
    if (wasBusy && !wasDisabled && job.queued && job.status === 'queued' &&
        job.last_attempt_status === 'failed' && newAttempt) {
      // A completed failed manual attempt remains queued while native backoff retries.
      // The underlying outcome and a new finished timestamp distinguish it from an
      // older failure and from a callback that is still executing.
      announceResult(row, job, 'failed', true);
    } else if (row.dataset.busy === 'true' && !wasBusy) {
      clearAnnouncement(row);
    } else if (wasBusy && row.dataset.busy !== 'true' && terminalStatuses.has(job.status)) {
      // Each row has its own live region; background results never replace action errors.
      announceResult(row, job, job.status);
    }
  }
  async function request(url, options = {}) {
    const response = await fetch(url, {credentials: 'same-origin', ...options, headers: {Accept: 'application/json'}});
    let body;
    try { body = await response.json(); } catch (_) { throw new Error('Keep could not confirm the action. Refresh the page and try again.'); }
    if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : typeof body.message === 'string' ? body.message : 'The action could not be completed. Refresh the page and try again.');
    return body;
  }
  function planRefresh() {
    clearTimeout(timer);
    if (stopped) return;
    const busy = Array.from(rows.values()).some(row => row.dataset.busy === 'true');
    timer = setTimeout(refresh, busy ? 3000 : 15000);
  }
  async function refresh() {
    if (stopped || refreshing) return;
    if (document.hidden) { planRefresh(); return; }
    refreshing = true;
    const version = mutationVersion;
    try {
      const snapshot = await request('/settings/jobs?format=json');
      if (!Array.isArray(snapshot.jobs)) throw new Error('Invalid job status');
      if (version !== mutationVersion) return;
      snapshot.jobs.forEach(job => { const row = rows.get(job.id); if (row) updateRow(row, job); });
    } catch (_) {
      // Preserve the confirmed action and the last known state; the next poll retries.
    } finally { refreshing = false; planRefresh(); }
  }
  function closeDialog() {
    if (!saving) dialog.close();
  }
  function setSaving(value) {
    saving = value;
    interval.disabled = value;
    save.disabled = value;
    cancel.disabled = value;
    text(save, value ? 'Saving…' : 'Save changes');
    scheduleForm.setAttribute('aria-busy', String(value));
  }

  document.querySelectorAll('.jobs-ui time[datetime]').forEach(formatTime);
  const canRefresh = rows.size && feedback && typeof fetch === 'function';
  document.addEventListener('visibilitychange', () => {
    planCountdown();
    if (!document.hidden && canRefresh) void refresh();
  });
  window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); clearTimeout(countdownTimer); });
  window.addEventListener('pageshow', () => {
    if (stopped) {
      stopped = false; planCountdown();
      if (canRefresh) void refresh();
    }
  });
  if (rows.size) planCountdown();
  if (!canRefresh) return;
  rows.forEach(row => {
    const form = row.querySelector('[data-run-job]');
    form?.addEventListener('submit', async event => {
      event.preventDefault();
      if (row.dataset.pending === 'true' || row.dataset.busy === 'true' || row.dataset.canRun !== 'true') return;
      row.dataset.pending = 'true'; syncControls(row);
      form.setAttribute('aria-busy', 'true');
      text(row.querySelector('[data-run-label]'), 'Queueing…');
      try {
        const body = await request(form.action, {method: 'POST', body: new FormData(form)});
        mutationVersion++;
        row.dataset.busy = 'true'; row.dataset.canRun = 'false';
        row.dataset.status = 'queued'; row.dataset.announcedAttempt = '';
        if (Object.hasOwn(body, 'last_run')) row.dataset.lastAttempt = body.last_run || '';
        clearAnnouncement(row);
        text(row.querySelector('[data-run-label]'), 'Queued');
        const status = row.querySelector('[data-job-status]');
        text(status, 'Queued'); status.className = 'job-status job-status-queued';
        notify(body.message || `${row.querySelector('[data-job-title]').textContent} is queued to run.`);
        void refresh();
      } catch (error) {
        notify(error instanceof Error ? error.message : 'The job could not be queued. Try again.', true);
        text(row.querySelector('[data-run-label]'), 'Run now');
      } finally { row.dataset.pending = 'false'; form.setAttribute('aria-busy', 'false'); syncControls(row); }
    });
    const edit = row.querySelector('[data-edit-job]');
    if (!edit || typeof dialog?.showModal !== 'function') { syncControls(row); return; }
    const source = row.querySelector('[data-schedule-job]');
    row.dataset.scheduleEnhanced = 'true'; syncControls(row);
    edit.addEventListener('click', () => {
      if (edit.disabled) return;
      selectedRow = row; opener = edit;
      scheduleForm.action = source.action;
      interval.replaceChildren(...Array.from(source.querySelector('select').options, option => option.cloneNode(true)));
      interval.value = row.dataset.interval;
      // Existing deployment overrides remain visible above; choose a supported preset to replace one.
      if (!interval.value && row.dataset.interval) {
        const option = document.createElement('option');
        option.value = ''; option.textContent = 'Choose a frequency'; option.disabled = true;
        interval.prepend(option); interval.value = '';
      }
      text(document.getElementById('job-schedule-title'), row.querySelector('[data-job-title]').textContent);
      text(currentFrequency, row.querySelector('[data-job-schedule]').textContent);
      scheduleError.hidden = true; text(scheduleError, '');
      dialog.showModal(); document.documentElement.classList.add('job-schedule-open');
      interval.focus();
    });
  });
  if (dialog && scheduleForm) {
    cancel?.addEventListener('click', closeDialog);
    dialog.addEventListener('cancel', event => { if (saving) event.preventDefault(); });
    dialog.addEventListener('close', () => {
      document.documentElement.classList.remove('job-schedule-open');
      opener?.focus(); selectedRow = null; opener = null;
    });
    scheduleForm.addEventListener('submit', async event => {
      event.preventDefault();
      if (!selectedRow || saving) return;
      const row = selectedRow, chosen = interval.value, label = interval.options[interval.selectedIndex]?.textContent;
      const data = new FormData(scheduleForm);
      setSaving(true); scheduleError.hidden = true;
      try {
        const body = await request(scheduleForm.action, {method: 'POST', body: data});
        mutationVersion++;
        row.dataset.interval = chosen; text(row.querySelector('[data-job-schedule]'), label);
        notify(body.message || 'Job frequency saved.');
        setSaving(false); dialog.close(); void refresh();
      } catch (error) {
        text(scheduleError, error instanceof Error ? error.message : 'The frequency could not be saved. Try again.');
        scheduleError.hidden = false; setSaving(false);
      }
    });
  }
  planRefresh();
})();
