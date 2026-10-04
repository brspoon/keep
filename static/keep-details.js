/* One read-only dialog shared by every browsing view. */
(() => {
  let dialog, content, opener, controller, generation = 0;
  function create() {
    dialog = document.createElement('dialog');
    dialog.className = 'title-details-dialog';
    dialog.setAttribute('aria-label', 'Title details');
    const close = document.createElement('button');
    close.type = 'button'; close.className = 'details-close';
    close.setAttribute('aria-label', 'Close title details'); close.textContent = '×';
    close.addEventListener('click', () => dialog.close());
    content = document.createElement('div'); content.className = 'details-content';
    dialog.append(close, content); document.body.append(dialog);
    dialog.addEventListener('keydown', event => {
      if (event.key !== 'Tab') return;
      const controls = [...dialog.querySelectorAll('button:not(:disabled), a[href], summary')];
      const first = controls[0], last = controls[controls.length - 1];
      if (!controls.includes(document.activeElement) ||
          (event.shiftKey && document.activeElement === first) ||
          (!event.shiftKey && document.activeElement === last)) {
        event.preventDefault(); (event.shiftKey ? last : first)?.focus();
      }
    });
    dialog.addEventListener('click', event => { if (event.target === dialog) {
      const rect = dialog.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
    }});
    dialog.addEventListener('close', () => {
      generation++; controller?.abort();
      document.documentElement.classList.remove('title-details-open');
      opener?.focus({preventScroll:true});
    });
  }
  async function markup(url, signal) {
    const response = await fetch(url, {credentials:'same-origin', signal});
    if (!response.ok || response.redirected) throw Error('Unavailable');
    return response.text();
  }
  async function loadStatus(host, token, signal, retryControl) {
    host.setAttribute('aria-busy', 'true');
    try {
      const html = await markup(host.dataset.statusUrl, signal);
      if (token !== generation || !dialog.open) return;
      const restoreFocus = retryControl && document.activeElement === retryControl;
      host.innerHTML = html;
      host.setAttribute('aria-busy', 'false');
      if (restoreFocus) { host.tabIndex = -1; host.focus({preventScroll:true}); }
    } catch (error) {
      if (token !== generation || error.name === 'AbortError' || !dialog.open) return;
      host.setAttribute('aria-busy', 'false');
      const status = document.createElement('p'); status.className = 'details-muted';
      status.setAttribute('role', 'alert');
      status.textContent = 'Keep status and watch history are currently unavailable.';
      const retry = document.createElement('button'); retry.type = 'button';
      retry.className = 'details-retry details-status-retry'; retry.textContent = 'Try again';
      retry.addEventListener('click', () => {
        retry.disabled = true;
        status.setAttribute('role', 'status'); status.textContent = 'Checking Keep status and watch history…';
        loadStatus(host, token, signal, retry);
      });
      const restoreFocus = retryControl && document.activeElement === retryControl;
      host.replaceChildren(status, retry);
      if (restoreFocus) retry.focus({preventScroll:true});
    }
  }
  async function load(button) {
    const token = ++generation;
    controller?.abort(); controller = new AbortController();
    const signal = controller.signal;
    content.replaceChildren();
    const card = button.closest('.card');
    const poster = card?.querySelector('img.poster');
    let image;
    if (poster && !poster.hidden) {
      image = document.createElement('img');
      image.className = 'details-poster'; image.alt = ''; image.src = poster.currentSrc || poster.src;
      image.addEventListener('error', () => { image?.remove(); image = null; }); content.append(image);
    }
    // The card's already-visible title and artwork open synchronously. Private
    // metadata is still fetched afresh after the server's current access checks.
    const copy = document.createElement('div'); copy.className = 'details-copy';
    const heading = document.createElement('h2'); heading.tabIndex = -1;
    heading.textContent = card?.querySelector('.title')?.textContent.trim() || 'Title details';
    const status = document.createElement('p'); status.className = 'details-muted';
    status.setAttribute('role', 'status'); status.textContent = 'Loading title details…';
    copy.append(heading, status); content.append(copy); heading.focus({preventScroll:true});
    try {
      const url = button.dataset.detailsUrl;
      const html = await markup(url + (url.includes('?') ? '&' : '?') + 'view=core', signal);
      if (token !== generation || !dialog.open) return;
      const restoreHeadingFocus = document.activeElement === heading;
      content.innerHTML = html;
      if (image) content.prepend(image);
      if (restoreHeadingFocus) content.querySelector('h2')?.focus({preventScroll:true});
      const live = content.querySelector('[data-status-url]');
      if (live) loadStatus(live, token, signal);
    } catch (error) {
      if (token !== generation || error.name === 'AbortError' || !dialog.open) return;
      status.textContent = 'Could not load this title. It may have moved, or the service may be unavailable.';
      status.setAttribute('role', 'alert');
      const retry = document.createElement('button'); retry.type = 'button'; retry.className = 'details-retry details-status-retry';
      retry.textContent = 'Try again'; retry.addEventListener('click', () => load(button)); copy.append(retry);
    }
  }
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-details-url]');
    if (!button) return;
    event.preventDefault();
    if (!dialog) create();
    opener = button;
    if (!dialog.open) dialog.showModal();
    document.documentElement.classList.add('title-details-open');
    load(button);
  });
})();
