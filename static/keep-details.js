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
  async function load(button) {
    const token = ++generation;
    controller?.abort(); controller = new AbortController();
    content.replaceChildren();
    const status = document.createElement('p'); status.className = 'details-loading';
    status.setAttribute('role', 'status'); status.textContent = 'Loading title details…';
    content.append(status);
    try {
      const response = await fetch(button.dataset.detailsUrl, {credentials:'same-origin', signal:controller.signal});
      if (!response.ok || response.redirected) throw Error('Unavailable');
      const markup = await response.text();
      if (token !== generation || !dialog.open) return;
      content.innerHTML = markup;
      const poster = button.closest('.card')?.querySelector('img.poster');
      if (poster && !poster.hidden) {
        const image = document.createElement('img');
        image.className = 'details-poster'; image.alt = ''; image.src = poster.currentSrc || poster.src;
        image.addEventListener('error', () => image.remove()); content.prepend(image);
      }
      content.querySelector('h2')?.focus({preventScroll:true});
    } catch (error) {
      if (token !== generation || error.name === 'AbortError' || !dialog.open) return;
      status.textContent = 'Could not load this title. It may have moved, or the service may be unavailable.';
      status.setAttribute('role', 'alert');
      const retry = document.createElement('button'); retry.type = 'button'; retry.className = 'details-retry';
      retry.textContent = 'Try again'; retry.addEventListener('click', () => load(button)); content.append(retry);
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
