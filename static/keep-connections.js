/* Credentials are fetched only on deliberate owner reveal, never in initial HTML. */
(() => {
  document.querySelectorAll('[data-service-address]').forEach(field => {
    const name = field.dataset.serviceAddress;
    const host = field.querySelector(`#${name}_host`);
    const scheme = field.querySelector(`#${name}_scheme`);
    const port = field.querySelector(`#${name}_port`);
    const path = field.querySelector(`#${name}_path`);
    if (host.readOnly) return;
    host.addEventListener('input', () => {
      if (!/^https?:\/\//i.test(host.value)) return;
      try {
        const parsed = new URL(host.value);
        if (parsed.username || parsed.password || parsed.search || parsed.hash ||
            /[\\\s]/.test(host.value)) return;
        scheme.value = parsed.protocol.slice(0, -1);
        port.value = parsed.port || (scheme.value === 'https' ? '443' : '80');
        path.value = parsed.pathname === '/' ? '' : parsed.pathname;
        host.value = parsed.hostname.replace(/^\[|\]$/g, '');
      } catch (_) { /* The server validates an address that could not be split. */ }
    });
    scheme.addEventListener('change', () => {
      if (scheme.value === 'https' && port.value === '80') port.value = '443';
      else if (scheme.value === 'http' && port.value === '443') port.value = '80';
    });
  });
  document.querySelectorAll('time.service-test-time[datetime]').forEach(element => {
    const tested = new Date(element.dateTime || element.getAttribute('datetime'));
    if (Number.isNaN(tested.getTime())) return;
    try {
      const local = new Intl.DateTimeFormat(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: 'numeric', minute: '2-digit', timeZoneName: 'short'
      }).format(tested);
      element.textContent = `Checked ${local}`;
    } catch (_) { /* Keep the server-rendered UTC time if local formatting fails. */ }
  });
  const concealAll = [];
  document.querySelectorAll('[data-credential]').forEach(field => {
    const input = field.querySelector('input');
    const button = field.querySelector('.reveal');
    const error = field.querySelector('.credential-error');
    let fetched = false, generation = 0, timer;
    const conceal = () => {
      generation++;
      clearTimeout(timer);
      input.type = 'password';
      if (fetched) input.value = '';
      delete input.dataset.revealedSaved;
      fetched = false;
      button.disabled = false;
      button.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-label', 'Show ' + field.querySelector('label').textContent);
    };
    concealAll.push(conceal);
    input.addEventListener('input', () => {
      generation++;
      delete input.dataset.revealedSaved;
      button.disabled = false;
      fetched = false;
    });
    button.hidden = false;
    button.addEventListener('click', async () => {
      if (input.type === 'text') { conceal(); return; }
      const current = ++generation;
      error.hidden = true;
      try {
        if (!input.value && field.dataset.configured === 'true') {
          button.disabled = true;
          const response = await fetch('/settings/connections/reveal', {
            method: 'POST', cache: 'no-store', credentials: 'same-origin',
            body: new URLSearchParams({name: field.dataset.credential,
              csrf_token: field.closest('form').querySelector('[name=csrf_token]').value})
          });
          if (!response.ok) throw new Error('Reveal failed');
          const result = await response.json();
          if (current !== generation || document.hidden) return;
          input.value = result.value;
          input.dataset.revealedSaved = 'true';
          fetched = true;
        }
        input.type = 'text';
        button.setAttribute('aria-pressed', 'true');
        button.setAttribute('aria-label', 'Hide ' + field.querySelector('label').textContent);
        timer = setTimeout(conceal, 30000);
      } catch (_) {
        if (current === generation) error.hidden = false;
      } finally { if (current === generation) button.disabled = false; }
    });
  });
  const conceal = () => concealAll.forEach(hide => hide());
  document.addEventListener('visibilitychange', conceal);
  window.addEventListener('pagehide', conceal);
  document.querySelectorAll('form').forEach(form => form.addEventListener('submit', () => {
    conceal();
    let disclosure = form.querySelector('input[name="open_services"]');
    if (!disclosure) {
      disclosure = document.createElement('input');
      disclosure.type = 'hidden';
      disclosure.name = 'open_services';
      form.appendChild(disclosure);
    }
    disclosure.value = Array.from(document.querySelectorAll('details.service-panel[open]'),
      panel => panel.id).join(',');
  }));
})();
