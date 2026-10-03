/* Small progressive enhancements; server responses remain authoritative. */
(() => {
  document.addEventListener('pointerdown', () => {
    document.documentElement.classList.add('pointer-input');
  }, true);
  document.addEventListener('keydown', event => {
    if (!event.metaKey && !event.ctrlKey && !event.altKey) {
      document.documentElement.classList.remove('pointer-input');
    }
  }, true);

  const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const account = document.getElementById('account-menu');
  if (account) {
    const toggle = account.querySelector('.account-toggle');
    const links = account.querySelector('.user-links');
    const setOpen = open => {
      links.hidden = !open;
      toggle.setAttribute('aria-expanded', String(open));
    };
    toggle.addEventListener('click', () => setOpen(links.hidden));
    document.addEventListener('click', event => {
      if (!account.contains(event.target) && !event.target.closest('dialog')) setOpen(false);
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !links.hidden && !event.target.closest('dialog')) {
        setOpen(false);
        toggle.focus({ preventScroll: true });
      }
    });
    document.addEventListener('focusin', event => {
      if (!account.contains(event.target) && !event.target.closest('dialog') && !document.querySelector('dialog[open]')) setOpen(false);
    });
  }

  const animations = new WeakMap();
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

  async function finishMediaAction(card, button, updateLayout, label, hadFocus = false) {
    button.dataset.confirming = 'false';
    button.classList.add('action-succeeded');
    button.textContent = label;
    if (!reducedMotion()) {
      await pause(180);
      if (card.animate) {
        const exit = card.animate([
          { opacity: 1, transform: 'scale(1)' },
          { opacity: 0, transform: 'scale(.98)' }
        ], { duration: 160, easing: 'ease-out', fill: 'forwards' });
        await exit.finished.catch(() => {});
      }
    }
    const elements = [...document.querySelectorAll('.media-view .card, .media-view .section-header, .media-view .empty')]
      .filter(element => element !== card && element.getClientRects().length);
    const before = new Map(elements.map(element => [element, element.getBoundingClientRect()]));
    elements.forEach(element => animations.get(element)?.cancel());
    const cards = [...document.querySelectorAll('.media-view .card')];
    const index = cards.indexOf(card);
    card.remove();
    updateLayout();
    if (!reducedMotion()) {
      for (const element of elements) {
        if (!element.isConnected || !element.getClientRects().length || !element.animate) continue;
        const previous = before.get(element);
        const current = element.getBoundingClientRect();
        const x = previous.left - current.left;
        const y = previous.top - current.top;
        if (Math.abs(x) + Math.abs(y) < 1) continue;
        const animation = element.animate([
          { transform: `translate(${x}px, ${y}px)` }, { transform: 'translate(0, 0)' }
        ], { duration: 200, easing: 'cubic-bezier(.2,.7,.2,1)' });
        animations.set(element, animation);
      }
    }
    if (hadFocus && (document.activeElement === document.body || document.activeElement === button)) {
      const candidates = [...cards.slice(index + 1), ...cards.slice(0, index).reverse()];
      const next = candidates.find(element => element.isConnected && element.getClientRects().length && element.querySelector('button:not(:disabled)'));
      (next?.querySelector('button:not(:disabled)') || document.getElementById('media-search'))?.focus({ preventScroll: true });
    }
  }
  function preparePoster(poster) {
    const wrap = poster.parentElement;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      poster.removeEventListener('load', finish);
      poster.removeEventListener('error', finish);
      if (!poster.naturalWidth) {
        poster.hidden = true;
        wrap.classList.add('poster-unavailable');
      } else if (!reducedMotion() && wrap.classList.contains('poster-loading') && poster.animate) {
        poster.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: 'ease-out' });
      }
      wrap.classList.remove('poster-loading');
    };
    poster.addEventListener('load', finish);
    poster.addEventListener('error', finish);
    if (poster.complete) finish();
    else wrap.classList.add('poster-loading');
  }
  document.querySelectorAll('.poster-wrap img.poster').forEach(preparePoster);
  window.KeepUI = { finishMediaAction, preparePoster };

  const backToTop = document.getElementById('back-to-top');
  if (backToTop) {
    let visible = false;
    let scheduled = false;
    const update = () => {
      scheduled = false;
      // Separate thresholds avoid flicker and keep the control available until near the top.
      visible = scrollY > (visible ? 160 : Math.max(600, window.innerHeight));
      backToTop.classList.toggle('visible', visible);
      backToTop.disabled = !visible;
    };
    const schedule = () => {
      if (!scheduled) { scheduled = true; requestAnimationFrame(update); }
    };
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    window.addEventListener('pageshow', schedule);
    backToTop.addEventListener('click', () => {
      document.getElementById('main-content')?.focus({ preventScroll: true });
      window.scrollTo({ top: 0, behavior: reducedMotion() ? 'instant' : 'smooth' });
    });
    update();
  }

  const storageKey = 'keep-save-feedback';
  const setUserEditor = (card, open) => {
    const toggle = card.querySelector('[data-user-toggle]');
    const editor = card.querySelector('.user-editor');
    if (!toggle || !editor) return;
    editor.hidden = !open;
    card.classList.toggle('is-editing', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.querySelector('[data-edit-label]').textContent = open ? 'Close' : 'Edit';
    if (!toggle.dataset.editName) toggle.dataset.editName = toggle.getAttribute('aria-label').replace(/^Edit /, '');
    toggle.setAttribute('aria-label', `${open ? 'Close settings for' : 'Edit'} ${toggle.dataset.editName}`);
  };
  document.querySelectorAll('[data-user-toggle]').forEach(toggle => {
    toggle.addEventListener('click', () => setUserEditor(toggle.closest('.user-card, .recipient-row'), toggle.getAttribute('aria-expanded') !== 'true'));
  });
  const forms = [...document.querySelectorAll('form[data-save-key]')];
  const reset = button => {
    button.textContent = button.dataset.saveLabel;
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.classList.remove('action-succeeded');
  };
  for (const form of forms) {
    const button = form.querySelector('.save-button');
    if (!button) continue;
    button.dataset.saveLabel = button.textContent;
    button.setAttribute('aria-live', 'polite');
    form.addEventListener('submit', event => {
      if (event.defaultPrevented) return;
      if (button.disabled) { event.preventDefault(); return; }
      // Store only a form identifier, never its field values or credentials.
      try {
        sessionStorage.setItem(storageKey, JSON.stringify({
          key: form.dataset.saveKey, path: location.pathname, at: Date.now(), scroll: scrollY
        }));
      } catch (_) { /* Native form submission still works without storage. */ }
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
      button.textContent = 'Saving…';
    });
    form.addEventListener('input', () => {
      if (button.classList.contains('action-succeeded')) reset(button);
    });
  }
  let saved;
  try {
    saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
    sessionStorage.removeItem(storageKey);
  } catch (_) { /* Storage can be disabled by browser privacy settings. */ }
  const success = document.querySelector('#settings-saved-notice, .preferences-ui .notice');
  const error = document.querySelector('.settings-error, .preferences-ui .error');
  if (saved && saved.path === location.pathname && Date.now() - saved.at < 30000 && (success || error)) {
    const editor = forms.find(form => form.dataset.saveKey === saved.key)?.closest?.('.user-card, .recipient-row');
    if (editor) setUserEditor(editor, true);
  }
  if (saved && saved.path === location.pathname && Date.now() - saved.at < 30000 && success && !error) {
    const form = forms.find(form => form.dataset.saveKey === saved.key);
    const button = form?.querySelector('.save-button');
    if (button && !button.disabled) {
      button.classList.add('action-succeeded');
      button.textContent = 'Saved ✓';
      requestAnimationFrame(() => window.scrollTo({ top: saved.scroll, behavior: 'instant' }));
      setTimeout(() => reset(button), 2600);
    }
  }
  window.addEventListener('pageshow', event => {
    if (event.persisted) {
      forms.forEach(form => {
        const button = form.querySelector('.save-button[aria-busy="true"]');
        if (button) reset(button);
      });
      try { sessionStorage.removeItem(storageKey); } catch (_) {}
    }
  });
})();
