/* Keep form snapshots in memory only; never persist credentials or field values. */
(() => {
  const tracked = new Map();
  const snapshot = form => JSON.stringify([...form.elements].filter(el => el.name && !['submit', 'hidden', 'button'].includes(el.type)).map(el => [el.name, el.dataset?.revealedSaved === 'true' ? '' : el.value, el.checked]));
  const dirty = form => tracked.has(form) && snapshot(form) !== tracked.get(form);
  const changedForms = () => [...tracked.keys()].filter(form => form.isConnected && dirty(form));
  const prompt = document.getElementById('unsaved-dialog');
  let pending = null;
  let opener = null;
  const ask = action => {
    pending = action; opener = document.activeElement;
    prompt.showModal(); prompt.querySelector('[data-stay]').focus();
  };
  prompt?.querySelector('[data-stay]').addEventListener('click', () => prompt.close());
  prompt?.querySelector('[data-discard]').addEventListener('click', () => {
    const action = pending; pending = null; prompt.close(); action?.();
  });
  prompt?.addEventListener('close', () => { pending = null; opener?.focus({preventScroll:true}); });
  document.addEventListener('keep-confirm-discard', event => ask(event.detail));
  const confirmDiscard = forms => {
    if (!forms.some(dirty)) return true;
    if (!window.confirm('You have unsaved changes. Discard them?')) return false;
    forms.forEach(form => { form.reset(); form.dispatchEvent(new Event('change', {bubbles:true})); });
    return true;
  };
  const attach = () => {
    for (const form of document.querySelectorAll('form[data-save-key], form[data-protect-unsaved]')) {
      if (tracked.has(form)) continue;
      const button = form.querySelector('.save-button');
      if (button?.disabled) continue;
      tracked.set(form, snapshot(form));
      const update = () => { if (button && button.getAttribute('aria-busy') !== 'true') button.disabled = !dirty(form); };
      form.addEventListener('input', update);
      form.addEventListener('change', update);
      if (button) update();
    }
    for (const form of tracked.keys()) if (!form.isConnected) tracked.delete(form);
  };
  attach();
  new MutationObserver(attach).observe(document.body, {childList:true, subtree:true});
  window.addEventListener('beforeunload', event => {
    if (changedForms().length) { event.preventDefault(); event.returnValue = ''; }
  });
  document.addEventListener('submit', event => {
    if (event.defaultPrevented) return;
    const form = event.target;
    const bypassValidation = form.noValidate || event.submitter?.formNoValidate;
    if (!bypassValidation && !form.checkValidity()) return;
    if (form.matches('[data-saved-test]') && dirty(form)) {
      const action = event.submitter?.value || '';
      const isTest = !action.startsWith('save-');
      if (isTest && !window.confirm(
        'This test uses the saved settings, not the edits in this form. The page will reload after the test and discard those edits. Continue?')) {
        event.preventDefault();
        return;
      }
    }
    const otherChanges = changedForms().filter(changed => changed !== form);
    if (otherChanges.length && prompt) {
      event.preventDefault();
      event.stopImmediatePropagation();
      const submitter = event.submitter;
      ask(() => {
        otherChanges.forEach(changed => { changed.reset(); changed.dispatchEvent(new Event('change', {bubbles:true})); });
        form.requestSubmit(submitter || undefined);
      });
      return;
    }
    // Native submissions navigate; asynchronous Preferences retains protection until success.
    if (!form.closest('#preferences-dialog')) tracked.delete(form);
  });
  document.addEventListener('click', event => {
    const link = event.target.closest('a[href]');
    if (link && prompt && !event.defaultPrevented && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey && !link.target && !link.hasAttribute('download') && link.getAttribute('aria-haspopup') !== 'dialog') {
      const destination = new URL(link.href, location.href);
      if (destination.href.split('#')[0] !== location.href.split('#')[0] && changedForms().length) {
        event.preventDefault(); event.stopImmediatePropagation();
        ask(() => { tracked.clear(); location.assign(destination.href); });
        return;
      }
    }
    const close = event.target.closest('[data-user-toggle], .preferences-cancel, #preferences-dialog .welcome-close');
    if (!close) return;
    if (close.matches('[data-user-toggle]') && close.getAttribute('aria-expanded') !== 'true') return;
    const container = close.closest('.user-card, .recipient-row, #preferences-dialog');
    if (!container) return;
    const forms = [...container.querySelectorAll('form')];
    if (prompt && forms.some(dirty)) {
      event.preventDefault(); event.stopImmediatePropagation();
      ask(() => { forms.forEach(form => { form.reset(); form.dispatchEvent(new Event('change', {bubbles:true})); }); close.click(); });
      return;
    }
    if (!confirmDiscard(forms)) { event.preventDefault(); event.stopImmediatePropagation(); }
  }, true);
  document.getElementById('preferences-dialog')?.addEventListener('cancel', event => {
    const forms = [...document.querySelectorAll('#preferences-dialog form')];
    if (prompt && forms.some(dirty)) {
      event.preventDefault();
      ask(() => { forms.forEach(form => form.reset()); document.getElementById('preferences-dialog').close(); });
      return;
    }
    if (!confirmDiscard([...document.querySelectorAll('#preferences-dialog form')])) event.preventDefault();
  });
  const wrapper = document.querySelector('.admin-list-search');
  if (wrapper) {
    const rows = [...document.querySelectorAll(wrapper.dataset.searchRows)];
    const label = wrapper.dataset.searchLabel;
    const input = wrapper.querySelector('input');
    const clear = wrapper.querySelector('.admin-search-clear');
    const status = wrapper.querySelector('[role=status]');
    const filter = () => {
      const query = input.value.trim().toLocaleLowerCase();
      clear.hidden = !input.value;
      let count = 0;
      rows.forEach(row => { row.hidden = !row.textContent.toLocaleLowerCase().includes(query); if (!row.hidden) count++; });
      status.textContent = count ? `${count} ${count === 1 ? label.replace(/s$/, '') : label}`
        : query ? `No matching ${label}. Try a different name or email, or clear your search.`
        : `0 ${label}`;
    };
    input.addEventListener('input', filter); filter();
    clear.addEventListener('click', () => {
      input.value = '';
      filter();
      input.focus({preventScroll:true});
    });
  }
})();
