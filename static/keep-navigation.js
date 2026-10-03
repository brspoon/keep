/* Full document navigation with immediate feedback and per-view restoration. */
(() => {
  const reset = () => {
    document.documentElement.classList.remove('navigation-pending');
    document.querySelectorAll('[data-pending]').forEach(link => link.removeAttribute('data-pending'));
  };
  const controls = document.querySelector('.browse-controls') || document.querySelector('.section-nav');
  const resize = () => {
    if (controls) document.documentElement.style.setProperty('--browse-offset', `${controls.getBoundingClientRect().height + 16}px`);
  };
  resize();
  if (controls && window.ResizeObserver) new ResizeObserver(resize).observe(controls);
  const key = `keep-view:${location.pathname}`;
  const search = document.getElementById('media-search');
  document.addEventListener('click', event => {
    const link = event.target.closest('a[href]');
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.target || link.hasAttribute('download')) return;
    const url = new URL(link.href, location.href);
    if (url.origin !== location.origin || url.pathname === location.pathname || link.getAttribute('aria-haspopup') === 'dialog') return;
    document.documentElement.classList.add('navigation-pending');
    link.setAttribute('data-pending', '');
  });
  window.addEventListener('pagehide', () => {
    if (!search) return;
    try { sessionStorage.setItem(key, JSON.stringify({query:search.value, scroll:window.scrollY, scope:document.querySelector('[data-keep-scope][aria-pressed="true"]')?.dataset.keepScope})); } catch (_) {}
  });
  window.addEventListener('pageshow', event => {
    reset();
    if (!search || event.persisted) return;
    try {
      const state = JSON.parse(sessionStorage.getItem(key) || 'null');
      if (!state) return;
      search.value = state.query || '';
      search.dispatchEvent(new Event('input', {bubbles:true}));
      if (state.scope === 'mine') document.querySelector('[data-keep-scope="mine"]')?.click();
      const historyVisit = window.performance?.getEntriesByType('navigation')[0]?.type === 'back_forward';
      if (!location.hash) requestAnimationFrame(() => window.scrollTo(0, historyVisit ? state.scroll || 0 : 0));
    } catch (_) {}
  });
})();
