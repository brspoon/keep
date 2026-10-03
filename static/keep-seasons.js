(() => {
  const dialog = document.getElementById('season-dialog');
  if (!dialog) return;
  const find = selector => dialog.querySelector(selector);
  const title = find('h2'), loading = find('.season-loading'), selection = find('.season-selection');
  const options = find('.season-options'), summary = find('.season-summary'), review = find('.season-review');
  const confirmation = find('.season-confirmation'), confirmSummary = find('.season-confirm-summary');
  const remove = find('.season-delete'), back = find('.season-back'), close = find('.season-close');
  const error = find('.season-error'), reload = find('.season-reload');
  let opener = null, generation = 0, plan = null, pending = false;
  const chosen = () => [...options.querySelectorAll('input:checked')].map(input => Number(input.value));
  const label = n => n === 0 ? 'Specials' : `Season ${n}`;
  function update() {
    const count = chosen().length;
    summary.textContent = count ? `${count} ${count === 1 ? 'season' : 'seasons'} selected` : 'No seasons selected';
    review.disabled = !count;
  }
  function failure(message, needsReload = false) {
    error.textContent = message; error.hidden = false; reload.hidden = !needsReload;
    if (needsReload) { remove.disabled = true; back.disabled = true; }
  }
  document.querySelectorAll('.season-manage-button').forEach(button => button.addEventListener('click', async () => {
    opener = button; plan = null; const ticket = ++generation;
    title.textContent = button.dataset.title; options.replaceChildren();
    error.hidden = reload.hidden = selection.hidden = confirmation.hidden = true;
    loading.hidden = false; loading.textContent = 'Loading seasons…'; review.disabled = true;
    remove.disabled = back.disabled = close.disabled = false;
    dialog.showModal(); title.focus();
    try {
      const response = await fetch(`/api/library/sonarr/${Number(button.dataset.itemId)}/seasons`, {credentials:'same-origin', cache:'no-store'});
      const data = await response.json();
      if (ticket !== generation || !dialog.open) return;
      if (!response.ok || !data || !Array.isArray(data.seasons) || typeof data.token !== 'string') {
        throw new Error(data?.error || 'Could not load seasons. Reopen this dialog to try again.');
      }
      plan = data;
      if (!data.seasons.length) { loading.textContent = 'No downloaded seasons are available for you to delete.'; return; }
      data.seasons.forEach(season => {
        const row = document.createElement('label'); row.className = 'season-option';
        const input = document.createElement('input'); input.type = 'checkbox'; input.value = season.number;
        input.setAttribute('role','switch'); input.setAttribute('aria-label',`Select ${label(season.number)} for deletion`);
        input.addEventListener('change', update);
        const toggle = document.createElement('span'); toggle.className = 'season-switch'; toggle.setAttribute('aria-hidden','true');
        const text = document.createElement('span'); text.className = 'season-option-text';
        const name = document.createElement('strong'); name.textContent = label(season.number);
        const info = document.createElement('small'); info.textContent = `${season.episodes} ${season.episodes === 1 ? 'episode' : 'episodes'} · ${season.size}`;
        text.append(name,info); row.append(input,toggle,text); options.append(row);
      });
      loading.hidden = true; selection.hidden = false; update();
    } catch (err) {
      if (ticket !== generation || !dialog.open) return;
      loading.hidden = true;
      failure('Could not load seasons. Close and reopen this dialog to try again.');
    }
  }));
  review.addEventListener('click', () => {
    const seasons = chosen(); if (!seasons.length || !plan || pending) return;
    confirmSummary.textContent = `${seasons.map(label).join(', ')} — ${opener.dataset.title}`;
    remove.textContent = `Delete ${seasons.length} ${seasons.length === 1 ? 'season' : 'seasons'}`;
    selection.hidden = true; confirmation.hidden = false; error.hidden = true;
    back.focus();
  });
  back.addEventListener('click', () => {
    if (pending) return;
    confirmation.hidden = true; selection.hidden = false; error.hidden = true; review.focus();
  });
  remove.addEventListener('click', async () => {
    if (!plan || pending || remove.disabled || !chosen().length) return;
    pending = true; remove.disabled = back.disabled = close.disabled = true;
    remove.textContent = 'Deleting…'; error.hidden = true;
    try {
      const response = await fetch('/api/library/delete', {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-CSRF-Token':dialog.dataset.csrf},
        body:JSON.stringify({service:'sonarr',itemId:Number(opener.dataset.itemId),libraryKey:opener.dataset.libraryKey,
          seasons:chosen(),previewToken:plan.token})});
      const data = await response.json().catch(() => null);
      if (!response.ok || data?.status !== 'seasons-deleted') {
        failure(data?.error || 'Could not confirm deletion. Reload the library to check its current state.', true);
        return;
      }
      window.location.reload();
    } catch (_) { failure('Could not confirm deletion. Reload the library to check its current state.', true); }
    finally { pending = false; close.disabled = false; remove.textContent = 'Delete selected seasons'; }
  });
  close.addEventListener('click', () => { if (!pending) dialog.close(); });
  dialog.addEventListener('cancel', event => { if (pending) event.preventDefault(); });
  dialog.addEventListener('close', () => { generation++; plan = null; opener?.focus({preventScroll:true}); });
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const controls = [...dialog.querySelectorAll('button:not(:disabled), input, a[href]')].filter(el => el.getClientRects().length);
    if (event.shiftKey && document.activeElement === controls[0]) { event.preventDefault(); controls.at(-1)?.focus(); }
    else if (!event.shiftKey && document.activeElement === controls.at(-1)) { event.preventDefault(); controls[0]?.focus(); }
  });
})();
