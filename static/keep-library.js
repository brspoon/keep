(() => {
  const search = document.getElementById('media-search');
  const clear = document.getElementById('search-clear');
  const status = document.getElementById('search-status');
  const empty = document.getElementById('search-empty');
  const dialog = document.getElementById('delete-media-dialog');
  const confirm = dialog?.querySelector('.confirm-delete');
  const cancel = dialog?.querySelector('.delete-cancel');
  const close = dialog?.querySelector('.welcome-close');
  const error = dialog?.querySelector('.welcome-error');
  let opener = null, armed = false, timer = null, pending = false;
  const focusable = () => [...dialog.querySelectorAll('button:not(:disabled), [href], input:not(:disabled), [tabindex]:not([tabindex="-1"])')]
    .filter(element => !element.hidden && element.getClientRects().length);

  function applySearch() {
    const query = search.value.trim().toLocaleLowerCase();
    clear.hidden = !search.value;
    let matches = 0;
    document.querySelectorAll('.media-view section').forEach(section => {
      let sectionMatches = 0;
      const cards = [...section.querySelectorAll('.card')];
      cards.forEach(card => {
        const visible = !query || `${card.dataset.title} ${card.dataset.year}`.toLocaleLowerCase().includes(query);
        card.hidden = !visible; if (visible) sectionMatches++;
      });
      section.hidden = Boolean(query) && sectionMatches === 0;
      section.querySelector('.count').textContent = query ? sectionMatches : cards.length;
      matches += sectionMatches;
    });
    empty.hidden = !query || matches > 0;
    status.textContent = query ? `${matches} ${matches === 1 ? 'title' : 'titles'} found` : '';
  }
  search?.addEventListener('input', applySearch);
  clear?.addEventListener('click', () => { search.value = ''; applySearch(); search.focus(); });

  function resetConfirmation() {
    clearTimeout(timer); armed = false;
    if (confirm) { confirm.textContent = 'Delete'; confirm.disabled = false; }
  }
  function dismiss() { if (!pending) dialog.close(); }
  document.querySelectorAll('.delete-media-button').forEach(button => button.addEventListener('click', () => {
    opener = button; resetConfirmation(); error.hidden = true; error.textContent = '';
    dialog.querySelector('h2').textContent = `Delete ${button.dataset.title}?`;
    dialog.querySelector('[data-delete-library]').textContent = button.dataset.libraryName;
    dialog.showModal(); confirm.focus();
  }));
  confirm?.addEventListener('click', async () => {
    if (!opener || pending) return;
    if (!armed) {
      armed = true; confirm.textContent = 'Delete forever?';
      timer = setTimeout(resetConfirmation, 4000); return;
    }
    clearTimeout(timer); pending = true; confirm.disabled = true; cancel.disabled = true; close.disabled = true;
    confirm.textContent = 'Deleting…'; error.hidden = true;
    try {
      const response = await fetch('/api/library/delete', {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-CSRF-Token':dialog.dataset.csrf},
        body:JSON.stringify({service:opener.dataset.service,itemId:Number(opener.dataset.itemId),libraryKey:opener.dataset.libraryKey})});
      const result = await response.json().catch(() => ({error:'Could not confirm deletion. Reload the library to check its current state.'}));
      if (!response.ok || result.status !== 'deleted') throw new Error(result.error || 'Could not confirm deletion. Reload the library to check its current state.');
      const card = opener.closest('.card'), section = opener.closest('section'), grid = card.closest('.grid');
      const nextFocus = card.nextElementSibling?.querySelector('.delete-media-button') || card.previousElementSibling?.querySelector('.delete-media-button');
      card.remove();
      const remaining = section.querySelectorAll('.card').length;
      section.querySelector('.count').textContent = remaining;
      if (!remaining) {
        grid.replaceWith(Object.assign(document.createElement('div'), {className:'empty', textContent:section.dataset.emptyMessage || 'No downloaded media is present in this library.'}));
      }
      window.showToast?.(`${result.title} deleted`); dialog.close(); applySearch();
      (nextFocus || search)?.focus({preventScroll:true});
    } catch (failure) { error.textContent = failure.message; error.hidden = false; resetConfirmation(); }
    finally { pending = false; cancel.disabled = false; close.disabled = false; }
  });
  cancel?.addEventListener('click', dismiss); close?.addEventListener('click', dismiss);
  dialog?.addEventListener('cancel', event => { if (pending) event.preventDefault(); });
  dialog?.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const controls = focusable();
    if (!controls.length) return;
    if (event.shiftKey && document.activeElement === controls[0]) {
      event.preventDefault(); controls.at(-1).focus();
    } else if (!event.shiftKey && document.activeElement === controls.at(-1)) {
      event.preventDefault(); controls[0].focus();
    }
  });
  dialog?.addEventListener('close', () => {
    resetConfirmation();
    if (opener?.isConnected) opener.focus({preventScroll:true});
  });

})();
