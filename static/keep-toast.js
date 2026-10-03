/* One confirmation style for actions, full-page saves, and refreshed keeps. */
(() => {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');
    toast.setAttribute('aria-atomic', 'true');
    const icon = document.createElement('span');
    icon.className = 'toast-check';
    icon.setAttribute('aria-hidden', 'true');
    const text = document.createElement('span');
    text.id = 'toast-message';
    toast.append(icon, text);
    document.body.append(toast);
  }
  let timer;
  window.showToast = (message, isError = false) => {
    document.getElementById('toast-message').textContent = message;
    toast.classList.toggle('error', isError);
    toast.querySelector('.toast-check').textContent = isError ? '!' : '✓';
    toast.classList.add('visible');
    clearTimeout(timer);
    timer = setTimeout(() => toast.classList.remove('visible'), isError ? 6000 : 4000);
  };
  const key = 'keep-success-toast';
  window.KeepToastAfterReload = message => {
    try { sessionStorage.setItem(key, JSON.stringify({ message, path: location.pathname, at: Date.now() })); } catch (_) {}
  };
  let pending;
  try {
    pending = JSON.parse(sessionStorage.getItem(key) || 'null');
    sessionStorage.removeItem(key);
  } catch (_) {}
  const error = document.querySelector('#settings-error-notice, .settings-error, .preferences-ui .error');
  const notice = document.querySelector('#settings-saved-notice, .preferences-ui .notice, .connections-ui .notice');
  if (!error && notice) {
    window.showToast(notice.textContent.trim());
    notice.hidden = true;
  } else if (!error && pending && pending.path === location.pathname && Date.now() - pending.at < 30000 && typeof pending.message === 'string') {
    window.showToast(pending.message);
  }
})();
