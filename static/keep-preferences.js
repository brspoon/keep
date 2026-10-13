/* Reuse the server's authenticated, CSRF-protected preferences form. */
(() => {
  const channels = new WeakMap();
  const secrets = new WeakMap();
  function bind(container) {
    container.querySelectorAll('[data-notification-channel]').forEach(form => {
      if (channels.has(form)) { channels.get(form)(); return; }
      const toggle = form.querySelector('[data-channel-toggle]');
      const options = [...form.querySelectorAll('[data-channel-options]')];
      if (!toggle || !options.length) return;
      const sync = () => options.forEach(group => { group.disabled = !toggle.checked; });
      channels.set(form, sync);
      toggle.addEventListener('change', sync);
      // Disabled channel choices remain saved when the channel is turned off.
      form.addEventListener('formdata', event => {
        options.filter(group => group.disabled).forEach(group => {
          group.querySelectorAll('input[type="checkbox"]:checked').forEach(input => {
            if (input.name && !input.disabled) event.formData.append(input.name, input.value);
          });
        });
      });
      sync();
    });
    container.querySelectorAll('[data-secret-control]').forEach(control => {
      if (secrets.has(control)) { secrets.get(control)(); return; }
      const mode = control.querySelector('[data-secret-mode]');
      const replacement = control.querySelector('[data-secret-replacement]');
      const input = replacement?.querySelector('input');
      if (!mode || !replacement || !input) return;
      const sync = () => {
        replacement.hidden = mode.disabled || mode.value !== 'replace';
        input.disabled = replacement.hidden;
        if (replacement.hidden) input.value = '';
      };
      secrets.set(control, sync);
      mode.addEventListener('change', sync);
      sync();
    });
  }
  window.keepBindNotificationPreferences = bind;
  bind(document);
  window.addEventListener('pageshow', () => bind(document));
  const trigger = document.getElementById('preferences-open');
  const dialog = document.getElementById('preferences-dialog');
  if (!trigger || !dialog) return;
  const content = document.getElementById('preferences-content');
  const close = dialog.querySelector('.welcome-close');
  let generation = 0;
  let saving = false;
  let savedTheme = document.documentElement.dataset.theme || 'system';
  const controls = () => [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)')].filter(item => !item.closest('[hidden]'));
  const failure = message => {
    let error = content.querySelector('.request-error');
    if (!error) {
      error = document.createElement('p');
      error.className = 'error request-error';
      error.setAttribute('role', 'alert');
      content.prepend(error);
    }
    error.textContent = message;
    if (!content.querySelector('form')) {
      const retry = document.createElement('button');
      retry.type = 'button'; retry.textContent = 'Try again';
      retry.addEventListener('click', () => { dialog.close(); trigger.click(); });
      error.append(retry);
    }
  };
  async function render(response, token) {
    if (!response.ok || new URL(response.url).pathname !== '/preferences') throw Error('Request failed');
    const html = await response.text();
    if (token !== generation || !dialog.open) return;
    content.innerHTML = html;
    if (!content.querySelector('form[data-notification-channel]')) throw Error('Missing form');
    bind(content);
    return Boolean(content.querySelector('.notice'));
  }
  trigger.addEventListener('click', async event => {
    event.preventDefault();
    if (dialog.open) return;
    savedTheme = document.documentElement.dataset.theme || 'system';
    const token = ++generation;
    content.textContent = 'Loading preferences…';
    dialog.showModal();
    document.documentElement.classList.add('preferences-open');
    document.getElementById('preferences-title').focus();
    try {
      await render(await fetch('/preferences?fragment=1', { credentials: 'same-origin' }), token);
    } catch (_) {
      if (token === generation && dialog.open) failure('Could not load preferences. Check your connection and try again.');
    }
  });
  content.addEventListener('submit', async event => {
    event.preventDefault();
    if (saving) return;
    const form = event.target;
    const button = form.querySelector('.save-button');
    if (!button || button.disabled) return;
    const path = new URL(form.action, window.location.href);
    if (path.origin !== window.location.origin || path.pathname !== '/preferences') {
      failure('Could not confirm the save. Please try again.');
      return;
    }
    path.searchParams.set('fragment', '1');
    const data = new FormData(form);
    const token = generation;
    const buttonLabel = button.textContent;
    const discarding = Boolean(form.querySelector('[name="action"][value="discard-pushover-test"]'));
    const testing = discarding || Boolean(form.querySelector('[name="action"][value="test-pushover"]'));
    saving = true;
    button.disabled = true;
    button.textContent = discarding ? 'Updating…' : testing ? 'Sending…' : 'Saving…';
    try {
      const saved = await render(await fetch(`${path.pathname}${path.search}`, { method: 'POST', body: data, credentials: 'same-origin' }), token);
      if (saved && !testing) {
        const selectedTheme = content.querySelector('[name="theme_mode"]:checked')?.value;
        if (['system', 'light', 'dark'].includes(selectedTheme)) {
          savedTheme = selectedTheme;
          window.keepApplyTheme(selectedTheme);
        }
        dialog.close();
        showToast('Preferences saved');
      }
      else if (token === generation && dialog.open) document.getElementById('preferences-title').focus();
    } catch (_) {
      if (token === generation && dialog.open) failure('Could not confirm the save. Please try again.');
    } finally {
      saving = false;
      button.disabled = false;
      button.textContent = buttonLabel;
    }
  });
  close.addEventListener('click', () => dialog.close());
  dialog.querySelector('.preferences-cancel').addEventListener('click', () => dialog.close());
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const items = controls(), first = items[0], last = items[items.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && (document.activeElement === first || document.activeElement.id === 'preferences-title')) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });
  dialog.addEventListener('close', () => {
    generation++;
    window.keepApplyTheme(savedTheme);
    document.documentElement.classList.remove('preferences-open');
    const account = document.getElementById('account-menu');
    (account.querySelector('.user-links').hidden ? account.querySelector('.account-toggle') : trigger).focus({ preventScroll: true });
  });
})();
