const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('static/keep-jobs.js', 'utf8');

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function fixture({fetchAvailable = true, modalAvailable = true, currentInterval = 900, initiallyEditable = true, initiallyBusy = false} = {}) {
  class Element {
    constructor(tag = 'div', content = '') {
      this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attrs = {};
      this.listeners = {}; this.nodes = {}; this.hidden = false; this.disabled = false; this._text = content; this.textWrites = [];
      const classes = new Set();
      this.classList = {add: value => classes.add(value), remove: value => classes.delete(value),
        contains: value => classes.has(value), toggle: (value, on) => on ? classes.add(value) : classes.delete(value)};
    }
    set innerHTML(_) { throw Error('Status and job names must remain plain text'); }
    get textContent() { return this.children.length ? this.children.map(child => child.textContent).join('') : this._text; }
    set textContent(value) { this._text = String(value); this.children = []; this.textWrites.push(String(value)); }
    append(...children) { this.children.push(...children); }
    prepend(child) { this.children.unshift(child); }
    replaceChildren(...children) { this.children = children; this._text = ''; }
    setAttribute(key, value) { this.attrs[key] = String(value); }
    hasAttribute(key) { return Object.hasOwn(this.attrs, key); }
    querySelector(selector) { return this.nodes[selector] || (selector === 'time' ? this.children.find(child => child.tagName === 'TIME') : null); }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    async fire(type, props = {}) {
      const event = {target: this, preventDefault() { this.prevented = true; }, ...props};
      await Promise.all((this.listeners[type] || []).map(handler => handler(event)));
      return event;
    }
    focus() { document.activeElement = this; }
    cloneNode() { const copy = new Element(this.tagName, this.textContent); copy.value = this.value; copy.disabled = this.disabled; return copy; }
  }
  class Select extends Element {
    constructor() { super('select'); this.selectedIndex = -1; }
    get options() { return this.children; }
    get value() { return this.options[this.selectedIndex]?.value || ''; }
    set value(value) { this.selectedIndex = this.options.findIndex(option => option.value === String(value)); }
  }
  const document = new Element(), window = new Element();
  document.documentElement = new Element('html'); document.createElement = tag => new Element(tag); document.hidden = false;
  const row = new Element('article'); row.dataset = {jobId: 'plex-access-sync', interval: String(currentInterval), canRun: String(initiallyEditable && !initiallyBusy), editable: String(initiallyEditable), busy: String(initiallyBusy)};
  for (const [selector, content] of Object.entries({'[data-job-title]': 'Plex account access', '[data-job-status]': 'Completed', '[data-job-result]': 'Completed', '[data-job-schedule]': 'Every 15 minutes', '[data-run-label]': 'Run now', '[data-action-reason]': '', '[data-job-duration]': '0.1 seconds', '[data-last-run]': '', '[data-next-run]': '', '[data-job-announcement]': ''})) row.nodes[selector] = new Element('span', content);
  const pastTime = new Element('time'), nextTime = new Element('time');
  pastTime.dateTime = new Date(Date.now() - 60000).toISOString(); nextTime.dateTime = new Date(Date.now() + 300000).toISOString();
  row.dataset.lastAttempt = pastTime.dateTime;
  row.dataset.status = initiallyEditable ? initiallyBusy ? 'running' : 'success' : 'disabled';
  nextTime.setAttribute('data-relative', ''); row.nodes['[data-last-run]'].append(pastTime); row.nodes['[data-next-run]'].append(nextTime);
  const runForm = new Element('form'), runButton = new Element('button'), edit = new Element('button');
  runForm.action = '/settings/jobs/plex-access-sync/run'; runForm.nodes.button = runButton;
  row.nodes['[data-run-job]'] = runForm; row.nodes['[data-run-job] button'] = runButton; row.nodes['[data-edit-job]'] = edit;
  edit.hidden = true; edit.disabled = !initiallyEditable;
  const fallback = new Element('details'), fallbackForm = new Element('form'), fallbackSelect = new Select(), fallbackSave = new Element('button');
  fallback.hidden = !initiallyEditable; fallbackSelect.disabled = !initiallyEditable; fallbackSave.disabled = !initiallyEditable;
  for (const [seconds, label] of [[300, 'Every 5 minutes'], [900, 'Every 15 minutes'], [3600, 'Every hour']]) {
    const option = new Element('option', label); option.value = String(seconds); fallbackSelect.append(option);
  }
  fallbackForm.action = '/settings/jobs/plex-access-sync/schedule'; fallbackForm.nodes.select = fallbackSelect; fallbackForm.nodes['button[type="submit"]'] = fallbackSave;
  row.nodes['[data-schedule-fallback]'] = fallback; row.nodes['[data-schedule-job]'] = fallbackForm;
  const dialog = new Element('dialog'), scheduleForm = new Element('form'), interval = new Select();
  const cancel = new Element('button'), save = new Element('button', 'Save changes'), feedback = new Element('p'), error = new Element('p');
  feedback.hidden = true; error.hidden = true; dialog.open = false; dialog.nodes['[data-cancel-schedule]'] = cancel;
  if (modalAvailable) dialog.showModal = () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; void dialog.fire('close'); };
  const ids = {'jobs-feedback': feedback, 'job-schedule-dialog': dialog, 'job-schedule-form': scheduleForm,
    'job-interval': interval, 'job-current-frequency': new Element(), 'job-schedule-error': error,
    'job-save-schedule': save, 'job-schedule-title': new Element()};
  document.getElementById = id => ids[id];
  document.querySelectorAll = selector => selector === '[data-job-id]' ? [row] : selector === '.jobs-ui time[datetime]' ? [pastTime, nextTime] : [];
  const calls = [], timers = new Map(); let timerId = 0, postHandler, getHandler;
  let job = {id: 'plex-access-sync', label: 'Completed', status: 'success', result: 'Completed', schedule: 'Every 15 minutes', interval: currentInterval,
    can_run: initiallyEditable && !initiallyBusy, editable: initiallyEditable, queued: false, action_reason: '', last_run: pastTime.dateTime, last_attempt_status: 'success', next_run: nextTime.dateTime, duration: '0.1 seconds'};
  const fetch = async (url, options) => {
    calls.push({url, options});
    if (options.method === 'POST') return postHandler ? postHandler(url, options) : {ok: true, json: async () => ({message: 'Confirmed action'})};
    return getHandler ? getHandler() : {ok: true, json: async () => ({jobs: [job]})};
  };
  class FormData {
    constructor(form) { this.values = new Map([['csrf_token', 'synthetic-csrf']]); if (form === scheduleForm) this.values.set('interval', interval.value); }
    get(key) { return this.values.get(key); }
  }
  vm.runInNewContext(source, {document, window, fetch: fetchAvailable ? fetch : undefined, FormData, Intl, Date, Error,
    setTimeout: (fn, delay) => { const id = ++timerId; if (delay === 0) queueMicrotask(fn); else timers.set(id, fn); return id; }, clearTimeout: id => timers.delete(id)});
  return {row, runForm, runButton, edit, fallback, fallbackSelect, fallbackSave, dialog, scheduleForm, interval, cancel, save, feedback, error, ids, document, window, calls,
    pastTime, nextTime, setJob: values => { job = {...job, ...values}; }, setPost: handler => { postHandler = handler; }, setGet: handler => { getHandler = handler; },
    async poll() { const [id, fn] = timers.entries().next().value; timers.delete(id); await fn(); }};
}

test('dates are readable locally and next execution includes a relative time and exact timestamp', () => {
  const f = fixture();
  assert.doesNotMatch(f.pastTime.textContent, /T\d\d:/);
  assert.match(f.nextTime.textContent, /in 5 minutes/);
  assert.ok(f.nextTime.title);
});

test('Run now sends CSRF once, prevents duplicates and follows queued work to completion', async () => {
  const f = fixture(), post = deferred();
  f.setPost(() => post.promise);
  const pending = f.runForm.fire('submit');
  assert.equal(f.runButton.disabled, true);
  await f.runForm.fire('submit');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].options.headers.Accept, 'application/json');
  assert.equal(f.calls[0].options.body.get('csrf_token'), 'synthetic-csrf');
  f.setJob({status: 'queued', label: 'Queued', queued: true, can_run: false});
  post.resolve({ok: true, json: async () => ({message: 'Plex account access queued.'})});
  await pending; await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.row.nodes['[data-run-label]'].textContent, 'Queued');
  assert.equal(f.runButton.disabled, true);
  assert.equal(f.feedback.textContent, 'Plex account access queued.');
  f.setJob({status: 'success', label: 'Completed', queued: false, can_run: true, result: 'Updated 3 accounts'});
  await f.poll();
  assert.equal(f.runButton.disabled, false);
  assert.equal(f.row.nodes['[data-job-result]'].textContent, 'Updated 3 accounts');
  assert.equal(f.row.nodes['[data-job-announcement]'].textContent, 'Plex account access: Completed. Updated 3 accounts');
});

test('a rejected run shows the server reason and allows a retry', async () => {
  const f = fixture();
  f.setPost(async () => ({ok: false, json: async () => ({error: 'Configure Plex before running this job.'})}));
  await f.runForm.fire('submit');
  assert.equal(f.feedback.textContent, 'Configure Plex before running this job.');
  assert.equal(f.feedback.classList.contains('is-error'), true);
  assert.equal(f.runButton.disabled, false);
  assert.equal(f.row.nodes['[data-run-label]'].textContent, 'Run now');
});

test('a poll started before a confirmed run cannot restore an obsolete runnable state', async () => {
  const f = fixture(), snapshot = deferred();
  f.setGet(() => snapshot.promise);
  const poll = f.poll();
  await f.runForm.fire('submit');
  snapshot.resolve({ok: true, json: async () => ({jobs: [{id: 'plex-access-sync', label: 'Completed', status: 'success', can_run: true, queued: false, editable: true, interval: 900, schedule: 'Every 15 minutes'}]})});
  await poll;
  assert.equal(f.row.nodes['[data-run-label]'].textContent, 'Queued');
  assert.equal(f.runButton.disabled, true);
});

test('editing opens the current frequency, preserves an unsaved choice during polling, and restores focus on cancel', async () => {
  const f = fixture();
  assert.equal(f.edit.hidden, false); assert.equal(f.fallback.hidden, true);
  await f.edit.fire('click');
  assert.equal(f.dialog.open, true); assert.equal(f.interval.value, '900');
  assert.equal(f.ids['job-current-frequency'].textContent, 'Every 15 minutes');
  assert.equal(f.document.activeElement, f.interval);
  f.interval.value = '3600';
  f.setJob({status: 'running', label: 'Running', can_run: false});
  await f.poll();
  assert.equal(f.interval.value, '3600'); assert.equal(f.dialog.open, true);
  await f.cancel.fire('click');
  assert.equal(f.dialog.open, false); assert.equal(f.document.activeElement, f.edit);
  assert.equal(f.document.documentElement.classList.contains('job-schedule-open'), false);
});

test('saving sends the selected frequency, guards dismissal while pending, and closes only after confirmation', async () => {
  const f = fixture(), post = deferred();
  f.setPost(() => post.promise);
  await f.edit.fire('click'); f.interval.value = '3600';
  const pending = f.scheduleForm.fire('submit');
  assert.equal(f.interval.disabled, true); assert.equal(f.save.disabled, true);
  assert.equal(f.calls[0].options.body.get('interval'), '3600');
  assert.equal(f.calls[0].options.body.get('csrf_token'), 'synthetic-csrf');
  const escape = await f.dialog.fire('cancel'); assert.equal(escape.prevented, true);
  await f.cancel.fire('click'); assert.equal(f.dialog.open, true);
  f.setJob({interval: 3600, schedule: 'Every hour'});
  post.resolve({ok: true, json: async () => ({message: 'Frequency saved.'})});
  await pending;
  assert.equal(f.dialog.open, false); assert.equal(f.feedback.textContent, 'Frequency saved.');
  assert.equal(f.row.nodes['[data-job-schedule]'].textContent, 'Every hour');
  assert.equal(f.interval.disabled, false); assert.equal(f.save.disabled, false);
});

test('a rejected schedule preserves the edit and keeps its error inside the dialog', async () => {
  const f = fixture();
  f.setPost(async () => ({ok: false, json: async () => ({error: 'Choose an available frequency.'})}));
  await f.edit.fire('click'); f.interval.value = '3600'; await f.scheduleForm.fire('submit');
  assert.equal(f.dialog.open, true); assert.equal(f.interval.value, '3600');
  assert.equal(f.error.hidden, false); assert.equal(f.error.textContent, 'Choose an available frequency.');
  assert.equal(f.save.disabled, false); assert.equal(f.feedback.hidden, true);
});

test('unsupported current deployment frequency requires choosing a supported preset', async () => {
  const f = fixture({currentInterval: 123});
  await f.edit.fire('click');
  assert.equal(f.interval.value, '');
  assert.equal(f.interval.options[0].textContent, 'Choose a frequency');
  assert.equal(f.interval.options[0].disabled, true);
  assert.ok(f.interval.options.slice(1).every(option => option.value !== '123'));
});

test('a newly configured connection reveals Edit without reloading and hides it again when unavailable', async () => {
  const f = fixture({initiallyEditable: false});
  assert.equal(f.edit.hidden, true); assert.equal(f.fallback.hidden, true);
  assert.equal(f.fallbackSelect.disabled, true);
  f.setJob({editable: true, can_run: true}); await f.poll();
  assert.equal(f.edit.hidden, false); assert.equal(f.edit.disabled, false);
  assert.equal(f.fallback.hidden, true); assert.equal(f.fallbackSelect.disabled, false);
  await f.edit.fire('click');
  assert.equal(f.dialog.open, true); assert.equal(f.interval.value, '900');
  await f.cancel.fire('click');
  f.setJob({editable: false, can_run: false}); await f.poll();
  assert.equal(f.edit.hidden, true); assert.equal(f.fallbackSave.disabled, true);
});

test('the regular schedule form follows applicability changes when modal enhancement is unavailable', async () => {
  const f = fixture({initiallyEditable: false, modalAvailable: false});
  assert.equal(f.fallback.hidden, true); assert.equal(f.edit.hidden, true);
  f.setJob({editable: true, can_run: true}); await f.poll();
  assert.equal(f.fallback.hidden, false); assert.equal(f.fallbackSelect.disabled, false); assert.equal(f.fallbackSave.disabled, false);
  assert.equal(f.edit.hidden, true);
  f.setJob({editable: false, can_run: false}); await f.poll();
  assert.equal(f.fallback.hidden, true); assert.equal(f.fallbackSelect.disabled, true);
});

test('completion is announced once per observed run without narrating periodic successful checks', async () => {
  const f = fixture(), announcement = f.row.nodes['[data-job-announcement]'];
  f.setJob({result: 'Updated 3 accounts'}); await f.poll();
  assert.equal(announcement.textWrites.length, 0);
  f.setJob({status: 'running', label: 'Running', can_run: false}); await f.poll();
  f.setJob({status: 'success', label: 'Completed', can_run: true}); await f.poll();
  const message = 'Plex account access: Completed. Updated 3 accounts';
  assert.equal(announcement.textContent, message);
  await f.poll();
  f.setJob({last_run: new Date().toISOString()}); await f.poll();
  assert.deepEqual(announcement.textWrites, [message]);
  f.setJob({status: 'running', label: 'Running', can_run: false}); await f.poll();
  f.setJob({status: 'success', label: 'Completed', can_run: true}); await f.poll();
  assert.deepEqual(announcement.textWrites, [message, '', message]);
});

test('queued-to-failed results are announced without replacing an unrelated action error', async () => {
  const f = fixture(), announcement = f.row.nodes['[data-job-announcement]'];
  f.feedback.textContent = 'A different schedule could not be saved.'; f.feedback.hidden = false; f.feedback.classList.add('is-error');
  f.setJob({status: 'queued', label: 'Queued', queued: true, can_run: false}); await f.poll();
  f.setJob({status: 'failed', label: 'Retrying', result: 'Connection unavailable', queued: false, can_run: true}); await f.poll();
  assert.equal(announcement.textContent, 'Plex account access: Failed. Connection unavailable');
  assert.equal(f.feedback.textContent, 'A different schedule could not be saved.');
  assert.equal(f.feedback.classList.contains('is-error'), true);
  await f.poll(); assert.equal(announcement.textWrites.length, 1);
});

test('failed manual attempts are announced once per finished attempt while the durable request stays queued', async () => {
  const f = fixture({initiallyBusy: true}), announcement = f.row.nodes['[data-job-announcement]'];
  f.feedback.textContent = 'An unrelated action failed.'; f.feedback.hidden = false; f.feedback.classList.add('is-error');
  f.setJob({status: 'queued', label: 'Queued', queued: true, can_run: false, last_attempt_status: 'failed', result: 'Connection unavailable'});
  await f.poll();
  assert.equal(announcement.textWrites.length, 0); // An existing failure is the initial baseline.
  f.setJob({status: 'running', label: 'Running', last_attempt_status: null}); await f.poll();
  assert.equal(announcement.textWrites.length, 0);
  f.setJob({status: 'queued', label: 'Queued', last_attempt_status: 'failed', last_run: '2026-10-05T01:00:01+00:00'}); await f.poll();
  const message = 'Plex account access: Failed. Connection unavailable. Keep will retry automatically.';
  assert.equal(announcement.textContent, message);
  await f.poll(); assert.deepEqual(announcement.textWrites, [message]);
  f.setJob({status: 'running', label: 'Running', last_attempt_status: null}); await f.poll();
  f.setJob({status: 'queued', label: 'Queued', last_attempt_status: 'failed', last_run: '2026-10-05T01:00:31+00:00'}); await f.poll();
  assert.deepEqual(announcement.textWrites, [message, '', message]);
  await f.poll(); assert.deepEqual(announcement.textWrites, [message, '', message]);
  f.setJob({status: 'success', label: 'Completed', queued: false, can_run: true, last_attempt_status: 'success', last_run: '2026-10-05T01:01:01+00:00', result: 'Updated 3 accounts'}); await f.poll();
  assert.equal(announcement.textContent, 'Plex account access: Completed. Updated 3 accounts');
  assert.equal(f.feedback.textContent, 'An unrelated action failed.');
  assert.equal(f.feedback.classList.contains('is-error'), true);
});

test('Run acceptance establishes a fresh baseline so a prior failure is not attributed to newly queued work', async () => {
  const f = fixture(), announcement = f.row.nodes['[data-job-announcement]'];
  const previousFailure = '2026-10-05T01:00:01+00:00';
  f.setJob({status: 'queued', label: 'Queued', queued: true, can_run: false, last_attempt_status: 'failed', last_run: previousFailure, result: 'Connection unavailable'});
  f.setPost(async () => ({ok: true, json: async () => ({message: 'Queued.', last_run: previousFailure})}));
  await f.runForm.fire('submit'); await new Promise(resolve => setImmediate(resolve));
  assert.equal(announcement.textWrites.length, 0);
  f.setJob({last_run: '2026-10-05T01:00:31+00:00'}); await f.poll();
  assert.match(announcement.textContent, /Failed.*retry automatically/);
  assert.equal(announcement.textWrites.length, 1);
});

test('configuration changes baseline a previously completed failure without announcing it as new work', async () => {
  const f = fixture({initiallyEditable: false, initiallyBusy: true}), announcement = f.row.nodes['[data-job-announcement]'];
  f.setJob({editable: true, status: 'queued', label: 'Queued', queued: true, can_run: false, last_attempt_status: 'failed', last_run: '2026-10-05T01:00:01+00:00', result: 'Connection unavailable'});
  await f.poll(); await f.poll();
  assert.equal(announcement.textWrites.length, 0);
  f.setJob({last_run: '2026-10-05T01:00:31+00:00'}); await f.poll();
  assert.match(announcement.textContent, /Failed.*retry automatically/);
});

test('an initially busy job announces completion on its first terminal snapshot', async () => {
  const f = fixture({initiallyBusy: true});
  f.setJob({status: 'success', label: 'Completed', can_run: true}); await f.poll();
  assert.equal(f.row.nodes['[data-job-announcement]'].textContent, 'Plex account access: Completed.');
});

for (const [reason, options] of [['fetch unavailable', {fetchAvailable: false}], ['native dialogs unavailable', {modalAvailable: false}]]) {
  test(`schedule forms remain usable when ${reason}`, () => {
    const f = fixture(options);
    assert.equal(f.fallback.hidden, false); assert.equal(f.edit.hidden, true);
  });
}
