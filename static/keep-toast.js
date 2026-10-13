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
  window.showToast = (message, status = false) => {
    const tone = status === true || status === 'error' ? 'error' : status === 'neutral' ? 'neutral' : 'ok';
    const isError = tone === 'error';
    document.getElementById('toast-message').textContent = message;
    toast.setAttribute('data-status', tone);
    toast.classList.toggle('error', isError);
    toast.querySelector('.toast-check').textContent = isError ? '!' : tone === 'neutral' ? 'i' : '✓';
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
  const error = document.querySelector('#settings-error-notice, .settings-error, .preferences-ui .error, #about-feedback[data-feedback-status="error"]:not([hidden])');
  const notice = document.querySelector('#settings-saved-notice, .preferences-ui .notice, .connections-ui .notice, #about-feedback:is([data-feedback-status="ok"],[data-feedback-status="neutral"]):not([hidden])');
  if (!error && notice) {
    window.showToast(notice.textContent.trim(), notice.getAttribute?.('data-feedback-status') || 'ok');
    notice.hidden = true;
  } else if (!error && pending && pending.path === location.pathname && Date.now() - pending.at < 30000 && typeof pending.message === 'string') {
    window.showToast(pending.message);
  }
})();
