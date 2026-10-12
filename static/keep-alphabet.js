/* A shared title index follows the current section without changing media order. */
(() => {
  const letters = ['#', ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
  const initial = title => {
    const first = String(title || 'Untitled').trim().charAt(0).toUpperCase();
    return /^[A-Z]$/.test(first) ? first : '#';
  };
  const controls = [...document.querySelectorAll('.media-view section[data-alphabet-section]')].map(section => {
    const header = section.querySelector('.section-header');
    if (!header) return null;
    return {section, header, name:section.querySelector('h2')?.textContent.trim() || 'this collection', targets:new Map(), available:[], cards:[]};
  }).filter(Boolean);
  if (!controls.length) return;

  const mobile = window.matchMedia('(max-width: 700px)');
  const side = document.createElement('aside');
  side.className = 'alphabet-side-navigation'; side.hidden = true;
  const index = document.createElement('nav'); index.className = 'alphabet-side-letters';
  const track = document.createElement('div'); track.className = 'alphabet-scrub-track';
  const handle = document.createElement('button'); handle.type = 'button'; handle.className = 'alphabet-scrub-handle';
  handle.setAttribute('role', 'slider'); handle.setAttribute('aria-orientation', 'vertical');
  handle.setAttribute('aria-valuemin', '0');
  const bubble = document.createElement('div'); bubble.className = 'alphabet-scrub-bubble';
  bubble.hidden = true; bubble.setAttribute('aria-hidden', 'true');
  track.append(handle, bubble); side.append(index, track); document.body.append(side);
  document.body.classList.add('alphabet-scroller-ready');
  document.documentElement.classList.add('alphabet-scroller-ready');

  let active = null, drag = null, focusContext = null, keyboardSelection = null, scheduled = false, refreshScheduled = false;
  let currentIndex = 0, railTop = 0, railHeight = 0;
  let layoutMetrics = '';
  let renderedControl = null, renderedLetters = '';
  const offset = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--browse-offset')) || 80;
  const viewport = () => ({top:window.visualViewport?.offsetTop || 0, height:window.visualViewport?.height || window.innerHeight});
  const shown = control => !control.section.hidden && control.section.isConnected !== false && control.available.length;
  const rebuild = control => {
    control.targets.clear(); control.cards = [];
    if (!control.section.hidden) control.section.querySelectorAll('.card').forEach(card => {
      if (card.hidden || card.isConnected === false) return;
      const title = card.dataset.title || card.querySelector('.title')?.textContent.trim() || 'Untitled';
      const letter = initial(title);
      control.cards.push({card, letter});
      if (!control.targets.has(letter)) control.targets.set(letter, card);
    });
    // Follow first appearances in the existing DOM, including the # bucket.
    control.available = [...control.targets.keys()];
  };
  const chooseContext = () => {
    if (drag && shown(drag.control)) return drag.control;
    if (focusContext && shown(focusContext)) return focusContext;
    const view = viewport(), probe = view.top + offset() + 8;
    const visible = controls.filter(control => {
      const rect = control.section.getBoundingClientRect();
      return shown(control) && rect.bottom > probe && rect.top < view.top + view.height;
    });
    return [...visible].reverse().find(control => control.section.getBoundingClientRect().top <= probe) || visible[0] || null;
  };
  const atView = control => {
    const probe = viewport().top + offset() + control.header.getBoundingClientRect().height + 8;
    // Existing grids flow in DOM row order. Avoid measuring every card on each scroll.
    let low = 0, high = control.cards.length - 1, position = 0;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      if (control.cards[middle].card.getBoundingClientRect().top <= probe + 1) { position = middle; low = middle + 1; }
      else high = middle - 1;
    }
    const rowTop = control.cards[position]?.card.getBoundingClientRect().top;
    // The first card on the nearest row supplies its initial, even in a wide grid.
    while (position > 0 && Math.abs(control.cards[position - 1].card.getBoundingClientRect().top - rowTop) <= 1) position--;
    return Math.max(0, control.available.indexOf(control.cards[position]?.letter));
  };
  const jump = (control, letter, focus, immediate) => {
    const card = control.targets.get(letter);
    if (!card || card.hidden || control.section.hidden || card.isConnected === false) return;
    if (focus) {
      card.tabIndex = -1; card.setAttribute('data-alphabet-target', '');
      card.focus({preventScroll:true});
    }
    const top = Math.max(0, window.scrollY + card.getBoundingClientRect().top - offset() - control.header.getBoundingClientRect().height - 8);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({top, behavior:immediate || reduced ? 'instant' : 'smooth'});
  };
  const buttons = letters.map(letter => {
    const button = document.createElement('button'); button.type = 'button';
    button.className = 'alphabet-side-letter'; button.dataset.letter = letter; button.textContent = letter;
    button.hidden = true; button.tabIndex = -1;
    button.addEventListener('click', () => {
      refresh();
      if (active) jump(active, letter, true, false);
    });
    button.addEventListener('keydown', event => {
      if (event.metaKey || event.ctrlKey || event.altKey || !['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      if (!active) return;
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
  const positionHandle = () => {
    if (!active) return;
    const height = handle.getBoundingClientRect().height || 56;
    const span = Math.max(0, railHeight - height);
    const fraction = active.available.length > 1 ? currentIndex / (active.available.length - 1) : 0.5;
    handle.style.top = `${span * fraction}px`;
    bubble.style.top = `${span * fraction + height / 2}px`;
    handle.setAttribute('aria-valuemax', String(active.available.length - 1));
    handle.setAttribute('aria-valuenow', String(currentIndex));
    const letter = active.available[currentIndex];
    handle.setAttribute('aria-valuetext', `${active.name}: ${letter === '#' ? 'numbers and other titles' : letter}`);
    handle.setAttribute('aria-label', `Title index in ${active.name}`);
    handle.title = `${active.name}: ${letter}`;
    bubble.textContent = letter;
  };
  const layout = () => {
    if (!active) return;
    const view = viewport(), browseOffset = offset();
    const safeBottom = parseFloat(getComputedStyle(side).paddingBottom) || 0;
    layoutMetrics = [view.top, view.height, window.innerWidth, window.innerHeight, browseOffset, safeBottom].join(':');
    let top, height, space;
    if (drag && drag.layoutMetrics === layoutMetrics) {
      // Title jumps move the heading; the held rail stays fixed to the pointer's viewport.
      top = drag.railTop; height = space = drag.railHeight;
    } else if (mobile.matches) {
      top = Math.max(view.top + browseOffset + 8, active.header.getBoundingClientRect().bottom + 8);
      height = space = view.top + view.height - 88 - safeBottom - top;
      if (height < 56) { keyboardSelection = null; stopDrag(); side.hidden = true; return; }
    } else {
      const start = view.top + browseOffset + 8;
      space = Math.max(56, view.height - browseOffset - 8 - safeBottom);
      height = Math.min(active.available.length * 24 + 8, space);
      top = start + Math.max(0, (space - height) / 2);
    }
    side.style.top = `${top}px`; index.style.maxHeight = `${space}px`;
    track.style.height = `${height}px`;
    const rect = track.getBoundingClientRect();
    const nextTop = rect.top, nextHeight = rect.height || height;
    const changed = nextTop !== railTop || nextHeight !== railHeight;
    railTop = nextTop; railHeight = nextHeight;
    positionHandle();
    if (drag && changed) {
      const handleHeight = handle.getBoundingClientRect().height || 56;
      const fraction = drag.letters.length > 1 ? drag.index / (drag.letters.length - 1) : 0.5;
      drag.grabOffset = drag.lastY - (railTop + handleHeight / 2 + Math.max(0, railHeight - handleHeight) * fraction);
    }
    if (drag) { drag.railTop = railTop; drag.railHeight = railHeight; drag.layoutMetrics = layoutMetrics; }
  };
  const sync = () => {
    scheduled = false;
    if (focusContext && !shown(focusContext)) focusContext = null;
    active = chooseContext(); side.hidden = !active;
    if (keyboardSelection && (active !== keyboardSelection.control || active !== focusContext
      || document.activeElement !== handle || !active.targets.has(keyboardSelection.letter))) keyboardSelection = null;
    if (!active) return;
    currentIndex = drag ? drag.index : keyboardSelection ? active.available.indexOf(keyboardSelection.letter) : atView(active);
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
    let changedCurrent = false;
    buttons.forEach(button => {
      const position = active.available.indexOf(button.dataset.letter);
      button.hidden = position < 0; button.style.order = String(position);
      button.setAttribute('aria-label', `${button.dataset.letter === '#' ? 'Numbers and other titles' : `Titles starting with ${button.dataset.letter}`} in ${active.name}`);
      const current = position === currentIndex;
      if (current && button.getAttribute('aria-current') !== 'location') changedCurrent = true;
      if (current) button.setAttribute('aria-current', 'location'); else button.removeAttribute('aria-current');
      if (!keepRoving) button.tabIndex = current ? 0 : -1;
    });
    layout();
    if (replaceFocus) buttons.find(button => button.dataset.letter === active.available[currentIndex])?.focus({preventScroll:true});
    else if (keepRoving && document.activeElement !== focused) focused.focus({preventScroll:true});
    if (!mobile.matches && changedCurrent && !index.contains(document.activeElement)) {
      buttons.find(button => button.dataset.letter === active.available[currentIndex])?.scrollIntoView({block:'nearest', inline:'nearest', behavior:'instant'});
    }
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true; requestAnimationFrame(sync);
  };
  const stopDrag = (commit = false) => {
    if (!drag) return;
    const session = drag; drag = null; bubble.hidden = true;
    try { handle.releasePointerCapture(session.pointerId); } catch (_) {}
    if (commit) jump(session.control, session.letters[session.index], true, true);
    schedule();
  };
  const refresh = () => {
    controls.forEach(rebuild);
    if (drag && (!shown(drag.control) || drag.letters.join('') !== drag.control.available.join(''))) stopDrag();
    if (focusContext && !shown(focusContext)) focusContext = null;
    sync();
  };
  handle.addEventListener('pointerdown', event => {
    if (!mobile.matches || drag || event.isPrimary === false || (event.button !== undefined && event.button !== 0)) return;
    refresh();
    if (!active || side.hidden) return;
    event.preventDefault(); focusContext = null; keyboardSelection = null;
    const height = handle.getBoundingClientRect().height || 56;
    const fraction = active.available.length > 1 ? currentIndex / (active.available.length - 1) : 0.5;
    drag = {control:active, letters:[...active.available], index:currentIndex, pointerId:event.pointerId,
      railTop, railHeight, layoutMetrics, lastY:event.clientY,
      grabOffset:event.clientY - (railTop + height / 2 + Math.max(0, railHeight - height) * fraction)};
    bubble.hidden = false;
    try { handle.setPointerCapture(event.pointerId); } catch (_) {}
  });
  document.addEventListener('pointermove', event => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    event.preventDefault(); drag.lastY = event.clientY;
    const height = handle.getBoundingClientRect().height || 56;
    const span = Math.max(1, railHeight - height);
    const fraction = Math.max(0, Math.min(1, (event.clientY - drag.grabOffset - railTop - height / 2) / span));
    const next = Math.round(fraction * (drag.letters.length - 1));
    if (next === drag.index) return;
    drag.index = currentIndex = next;
    positionHandle(); jump(drag.control, drag.letters[next], false, true);
  }, {passive:false});
  document.addEventListener('pointerup', event => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    event.preventDefault(); stopDrag(true);
  });
  document.addEventListener('pointercancel', event => { if (drag && event.pointerId === drag.pointerId) stopDrag(); });
  handle.addEventListener('lostpointercapture', event => { if (drag && event.pointerId === drag.pointerId) stopDrag(); });
  handle.addEventListener('keydown', event => {
    if (event.metaKey || event.ctrlKey || event.altKey || !['ArrowUp', 'ArrowDown', 'Home', 'End', 'Enter', ' '].includes(event.key)) return;
    refresh(); if (!active) return;
    event.preventDefault(); focusContext = active;
    if (event.key === 'Enter' || event.key === ' ') {
      jump(active, active.available[currentIndex], true, true); return;
    }
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? active.available.length - 1
      : Math.max(0, Math.min(active.available.length - 1, currentIndex + (event.key === 'ArrowUp' ? -1 : 1)));
    currentIndex = next; keyboardSelection = {control:active, letter:active.available[next]};
    positionHandle(); jump(active, active.available[next], false, true);
  });
  side.addEventListener('focusin', () => { focusContext = active; });
  side.addEventListener('focusout', event => {
    if (event.target === handle && event.relatedTarget !== handle) keyboardSelection = null;
    if (!side.contains(event.relatedTarget)) { focusContext = null; schedule(); }
  });
  document.addEventListener('focusin', event => {
    if (event.target !== handle) keyboardSelection = null;
    if (!side.contains(event.target)) { focusContext = null; schedule(); }
  });
  document.addEventListener('pointerdown', event => {
    if (!side.contains(event.target) && !drag) { focusContext = null; keyboardSelection = null; schedule(); }
  });
  document.addEventListener('wheel', event => {
    if (drag) return;
    keyboardSelection = null;
    if (!side.contains(event.target)) focusContext = null;
    schedule();
  }, {passive:true});
  const cancel = () => { stopDrag(); focusContext = null; keyboardSelection = null; schedule(); };
  window.addEventListener('blur', cancel); window.addEventListener('pagehide', cancel);
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancel(); });
  window.addEventListener('scroll', schedule, {passive:true}); window.addEventListener('resize', schedule);
  window.visualViewport?.addEventListener('resize', schedule); window.visualViewport?.addEventListener('scroll', schedule);
  mobile.addEventListener?.('change', () => { cancel(); focusContext = null; schedule(); });
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
  refresh();
})();
