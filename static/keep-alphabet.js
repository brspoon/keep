/* A desktop title index follows the current section without changing media order. */
(() => {
  const letters = ['#', ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
  const initial = title => {
    const first = String(title || 'Untitled').trim().charAt(0).toUpperCase();
    return /^[A-Z]$/.test(first) ? first : '#';
  };
  const controls = [...document.querySelectorAll('.media-view section[data-alphabet-section]')].map(section => {
    const header = section.querySelector('.section-header');
    if (!header) return null;
    return {section, header, name:section.querySelector('h2')?.textContent.trim() || 'this collection', targets:new Map(), available:[]};
  }).filter(Boolean);
  if (!controls.length) return;

  const mobile = window.matchMedia('(max-width: 700px)');
  const side = document.createElement('aside');
  side.className = 'alphabet-side-navigation'; side.hidden = true;
  const index = document.createElement('nav'); index.className = 'alphabet-side-letters';
  side.append(index); document.body.append(side);
  document.body.classList.add('alphabet-scroller-ready');
  document.documentElement.classList.add('alphabet-scroller-ready');

  let active = null, focusContext = null, indexHadFocus = false, scheduled = false, refreshScheduled = false;
  let renderedControl = null, renderedLetters = '';
  const offset = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--browse-offset')) || 80;
  const viewport = () => ({top:window.visualViewport?.offsetTop || 0, height:window.visualViewport?.height || window.innerHeight});
  const shown = control => !control.section.hidden && control.section.isConnected !== false && control.available.length;
  const needsIndex = control => {
    const usableHeight = Math.max(1, viewport().height - offset() - control.header.getBoundingClientRect().height - 24);
    return shown(control) && control.available.length > 1 && control.section.getBoundingClientRect().height > usableHeight * 2;
  };
  const rebuild = control => {
    control.targets.clear();
    if (!control.section.hidden) control.section.querySelectorAll('.card').forEach(card => {
      if (card.hidden || card.isConnected === false) return;
      const title = card.dataset.title || card.querySelector('.title')?.textContent.trim() || 'Untitled';
      const letter = initial(title);
      if (!control.targets.has(letter)) control.targets.set(letter, card);
    });
    // Follow first appearances in the existing DOM, including the # bucket.
    control.available = [...control.targets.keys()];
  };
  const chooseContext = () => {
    if (focusContext && shown(focusContext)) return focusContext;
    const view = viewport(), probe = view.top + offset() + 8;
    const visible = controls.filter(control => {
      const rect = control.section.getBoundingClientRect();
      return shown(control) && rect.bottom > probe && rect.top < view.top + view.height;
    });
    return [...visible].reverse().find(control => control.section.getBoundingClientRect().top <= probe) || visible[0] || null;
  };
  const hideIndex = previous => {
    // A responsive rule can already have dropped focus to body before its change
    // event runs. Remember index focus until another control receives it.
    if (side.contains(document.activeElement) || indexHadFocus && document.activeElement === document.body) {
      const destination = [previous, active, ...controls].find(control => control
        && !control.section.hidden && control.section.isConnected !== false);
      const target = destination?.header || document.getElementById('media-search');
      if (target) {
        if (destination) { target.tabIndex = -1; target.setAttribute('data-alphabet-target', ''); }
        target.focus({preventScroll:true});
      }
    }
    focusContext = null; indexHadFocus = false; side.hidden = true;
  };
  const jump = (control, letter) => {
    const card = control.targets.get(letter);
    if (!card || card.hidden || control.section.hidden || card.isConnected === false) return;
    card.tabIndex = -1; card.setAttribute('data-alphabet-target', '');
    card.focus({preventScroll:true});
    const top = Math.max(0, window.scrollY + card.getBoundingClientRect().top - offset() - control.header.getBoundingClientRect().height - 8);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({top, behavior:reduced ? 'instant' : 'smooth'});
  };
  const buttons = letters.map(letter => {
    const button = document.createElement('button'); button.type = 'button';
    button.className = 'alphabet-side-letter'; button.dataset.letter = letter; button.textContent = letter;
    button.hidden = true; button.tabIndex = -1;
    button.addEventListener('click', () => {
      refresh();
      if (active && !side.hidden) jump(active, letter);
    });
    button.addEventListener('keydown', event => {
      if (event.metaKey || event.ctrlKey || event.altKey || !['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      if (!active || side.hidden) return;
      const available = active.available.map(value => buttons.find(item => item.dataset.letter === value));
      const position = available.indexOf(button);
      if (position < 0) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? available.length - 1
        : Math.max(0, Math.min(available.length - 1, position + (event.key === 'ArrowUp' ? -1 : 1)));
      buttons.forEach(item => { item.tabIndex = item === available[next] ? 0 : -1; });
      available[next].focus({preventScroll:true});
      available[next].scrollIntoView({block:'nearest', inline:'nearest', behavior:'instant'});
    });
    index.append(button); return button;
  });
  const layout = () => {
    const view = viewport(), browseOffset = offset();
    const safeBottom = parseFloat(getComputedStyle(side).paddingBottom) || 0;
    const start = view.top + browseOffset + 8;
    const space = Math.max(56, view.height - browseOffset - 8 - safeBottom);
    const height = Math.min(active.available.length * 24 + 8, space);
    side.style.left = `${Math.min(window.innerWidth - 44, active.section.getBoundingClientRect().right + 8)}px`;
    side.style.top = `${start + Math.max(0, (space - height) / 2)}px`;
    index.style.maxHeight = `${space}px`;
  };
  const sync = () => {
    scheduled = false;
    const previous = active;
    if (focusContext && !shown(focusContext)) focusContext = null;
    active = chooseContext();
    if (mobile.matches || !active || !needsIndex(active)) { hideIndex(previous); return; }
    side.hidden = false;
    index.setAttribute('aria-label', `Title index in ${active.name}`);
    const focused = document.activeElement;
    const keepRoving = buttons.includes(focused) && active.targets.has(focused.dataset.letter);
    const replaceFocus = index.contains(focused) && !keepRoving;
    const signature = active.available.join('');
    if (renderedControl !== active || renderedLetters !== signature) {
      // Keep reading and keyboard order aligned with the displayed DOM-order buckets.
      index.append(...active.available.map(letter => buttons.find(button => button.dataset.letter === letter)),
        ...buttons.filter(button => !active.targets.has(button.dataset.letter)));
      renderedControl = active; renderedLetters = signature;
    }
    buttons.forEach(button => {
      const position = active.available.indexOf(button.dataset.letter);
      button.hidden = position < 0; button.style.order = String(position);
      button.setAttribute('aria-label', `${button.dataset.letter === '#' ? 'Numbers and other titles' : `Titles starting with ${button.dataset.letter}`} in ${active.name}`);
      if (!keepRoving) button.tabIndex = position === 0 ? 0 : -1;
    });
    layout();
    if (replaceFocus) buttons.find(button => button.dataset.letter === active.available[0])?.focus({preventScroll:true});
    else if (keepRoving && document.activeElement !== focused) focused.focus({preventScroll:true});
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true; requestAnimationFrame(sync);
  };
  const refresh = () => { controls.forEach(rebuild); sync(); };
  side.addEventListener('focusin', () => { focusContext = active; indexHadFocus = true; });
  side.addEventListener('focusout', event => {
    if (event.relatedTarget && !side.contains(event.relatedTarget)) { focusContext = null; indexHadFocus = false; schedule(); }
  });
  document.addEventListener('focusin', event => {
    if (!side.contains(event.target)) { focusContext = null; indexHadFocus = false; schedule(); }
  });
  document.addEventListener('pointerdown', event => {
    if (!side.contains(event.target)) { focusContext = null; indexHadFocus = false; schedule(); }
  });
  document.addEventListener('wheel', event => {
    if (!side.contains(event.target)) focusContext = null;
    schedule();
  }, {passive:true});
  window.addEventListener('scroll', schedule, {passive:true}); window.addEventListener('resize', schedule);
  window.visualViewport?.addEventListener('resize', schedule); window.visualViewport?.addEventListener('scroll', schedule);
  mobile.addEventListener?.('change', sync);
  window.KeepAlphabet = {refresh};
  document.getElementById('media-search')?.addEventListener('input', refresh);
  document.getElementById('search-clear')?.addEventListener('click', refresh);
  document.querySelectorAll('[data-keep-scope]').forEach(button => button.addEventListener('click', refresh));
  window.addEventListener('pageshow', refresh);
  if (window.MutationObserver) {
    const observer = new MutationObserver(records => {
      if (!records.some(record => record.type === 'attributes'
        ? record.target.classList.contains('card') || record.target.tagName === 'SECTION'
        : [...record.addedNodes, ...record.removedNodes].some(node => node.classList?.contains('card') || node.querySelector?.('.card')))) return;
      if (refreshScheduled) return;
      refreshScheduled = true;
      requestAnimationFrame(() => { refreshScheduled = false; refresh(); });
    });
    document.querySelectorAll('.media-view').forEach(view => observer.observe(view, {subtree:true, childList:true, attributes:true, attributeFilter:['hidden']}));
  }
  if (window.ResizeObserver) {
    const observer = new ResizeObserver(schedule);
    controls.forEach(control => observer.observe(control.section));
  }
  refresh();
})();
