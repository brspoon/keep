/* A meaningful release is shown once per user; any dismissal saves "seen". */
(() => {
  const dialog = document.getElementById('whats-new-dialog');
  if (!dialog || dialog.dataset.autoOpen !== 'true') return;
  const close = dialog.querySelector('.welcome-close');
  const done = dialog.querySelector('.whats-new-done');
  const help = dialog.querySelector('.whats-new-help');
  const error = dialog.querySelector('.whats-new-error');
  let pending = false;
  const seen = async destination => {
    if (pending) return;
    pending = true;
    close.disabled = done.disabled = true;
    error.hidden = true;
    try {
      const response = await fetch('/api/announcements/seen', {
        method: 'POST', credentials: 'same-origin', keepalive: true,
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': dialog.dataset.csrf},
        body: JSON.stringify({version: dialog.dataset.version})
      });
      if (!response.ok || (await response.json()).status !== 'seen') throw new Error('Save failed');
      dialog.close();
      if (destination) window.location.assign(destination);
    } catch (_) {
      error.hidden = false;
      close.disabled = done.disabled = false;
      pending = false;
    }
  };
  close.addEventListener('click', () => seen());
  done.addEventListener('click', () => seen());
  help.addEventListener('click', event => {
    if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    return seen(help.href);
  });
  dialog.addEventListener('cancel', event => {
    event.preventDefault();
    return seen();
  });
  dialog.addEventListener('close', () => {
    document.documentElement.classList.remove('whats-new-open');
    document.getElementById('account-menu')?.querySelector('.account-toggle')?.focus({preventScroll:true});
  });
  dialog.showModal();
  document.documentElement.classList.add('whats-new-open');
})();
