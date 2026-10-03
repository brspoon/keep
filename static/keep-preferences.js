/* Reuse the server's authenticated, CSRF-protected preferences form. */
(() => {
  const trigger = document.getElementById('preferences-open');
  const dialog = document.getElementById('preferences-dialog');
  if (!trigger || !dialog) return;
  const content = document.getElementById('preferences-content');
  const close = dialog.querySelector('.welcome-close');
  let generation = 0;
  let saving = false;
  let savedTheme = document.documentElement.dataset.theme || 'system';
  const controls = () => [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled)')];
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
    const receive = content.querySelector('[name="receive_email"]');
    const topics = content.querySelector('fieldset.topics');
    if (!receive || !topics) throw Error('Missing form');
    receive.addEventListener('change', () => { topics.disabled = !receive.checked; });
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
    const data = new FormData(form);
    const token = generation;
    saving = true;
    button.disabled = true;
    button.textContent = 'Saving…';
    try {
      const saved = await render(await fetch('/preferences?fragment=1', { method: 'POST', body: data, credentials: 'same-origin' }), token);
      if (saved) {
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
      button.textContent = 'Save preferences';
    }
  });
  close.addEventListener('click', () => dialog.close());
  dialog.querySelector('.preferences-cancel').addEventListener('click', () => dialog.close());
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const items = controls(), first = items[0], last = items[items.length - 1];
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
