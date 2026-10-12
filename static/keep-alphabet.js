/* Jump to the first visible title initial in each section; never change media order. */
(() => {
  const sections = [...document.querySelectorAll('.media-view section[data-alphabet-section]')];
  if (!sections.length) return;
  const letters = ['#', ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
  // Use literal title initials, like the existing sort. Numbers and non-ASCII initials share #.
  const initial = title => {
    const first = String(title || 'Untitled').trim().charAt(0).toUpperCase();
    return /^[A-Z]$/.test(first) ? first : '#';
  };
  const controls = sections.map(section => {
    const nav = section.querySelector('[data-alphabet-nav]');
    const strip = nav?.querySelector('.alphabet-letters');
    const header = section.querySelector('.section-header');
    if (!nav || !strip || !header) return null;
    const name = section.querySelector('h2')?.textContent.trim() || 'this collection';
    const targets = new Map(), buttons = [];
    const picker = document.createElement('select');
    picker.className = 'alphabet-picker';
    picker.setAttribute('aria-label', `Jump to letter in ${name}`);
    nav.append(picker);
    let availableLetters = null;
    const refresh = () => {
      targets.clear();
      if (!section.hidden) section.querySelectorAll('.card').forEach(card => {
        if (card.hidden) return;
        const title = card.dataset.title || card.querySelector('.title')?.textContent.trim() || 'Untitled';
        const letter = initial(title);
        if (!targets.has(letter)) targets.set(letter, card);
      });
      buttons.forEach(button => { button.hidden = !targets.has(button.dataset.letter); });
      nav.hidden = !targets.size;
      const available = letters.filter(letter => targets.has(letter));
      const signature = available.join('');
      if (signature !== availableLetters) {
        const prompt = document.createElement('option');
        prompt.value = ''; prompt.textContent = 'Jump to letter';
        const options = available.map(letter => {
          const option = document.createElement('option');
          option.value = letter; option.textContent = letter === '#' ? '# · Numbers and other titles' : letter;
          return option;
        });
        picker.replaceChildren(prompt, ...options);
        picker.value = '';
        availableLetters = signature;
      }
    };
    const jump = letter => {
      // Recheck visibility when activated, including filtering or removal since the last frame.
      refresh();
      const card = targets.get(letter);
      if (!card) return;
      card.tabIndex = -1;
      card.setAttribute('data-alphabet-target', '');
      card.focus({preventScroll:true});
      const offset = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--browse-offset')) || 80;
      const top = Math.max(0, window.scrollY + card.getBoundingClientRect().top - offset - header.getBoundingClientRect().height - 8);
      window.scrollTo({top, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
    };
    picker.addEventListener('change', () => {
      const letter = picker.value;
      if (!letter) return;
      picker.value = '';
      // The shared select restores its trigger focus during commit; jump after it finishes.
      requestAnimationFrame(() => jump(letter));
    });
    letters.forEach(letter => {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'alphabet-letter'; button.dataset.letter = letter;
      button.textContent = letter; button.hidden = true;
      button.setAttribute('aria-label', `${letter === '#' ? 'Numbers and other titles' : `Titles starting with ${letter}`} in ${name}`);
      button.addEventListener('click', () => jump(letter));
      button.addEventListener('keydown', event => {
        if (event.metaKey || event.ctrlKey || event.altKey || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const visible = buttons.filter(item => !item.hidden);
        const index = visible.indexOf(button);
        if (index < 0 || !visible.length) return;
        event.preventDefault();
        const target = event.key === 'Home' ? visible[0] : event.key === 'End' ? visible.at(-1)
          : visible[(index + (event.key === 'ArrowLeft' ? -1 : 1) + visible.length) % visible.length];
        target.focus({preventScroll:true});
        target.scrollIntoView({block:'nearest', inline:'nearest', behavior:'auto'});
      });
      strip.append(button); buttons.push(button);
    });
    return {refresh};
  }).filter(Boolean);
  const refresh = () => controls.forEach(control => control.refresh());
  window.KeepAlphabet = {refresh};
  document.getElementById('media-search')?.addEventListener('input', refresh);
  document.getElementById('search-clear')?.addEventListener('click', refresh);
  document.querySelectorAll('[data-keep-scope]').forEach(button => button.addEventListener('click', refresh));
  window.addEventListener('pageshow', refresh);
  // Manage Library deletion and season/Keep updates can remove or hide cards without input events.
  let scheduled = false;
  const changed = records => {
    // Ignore our own letter/select updates and existing count/action-label updates.
    if (!records.some(record => record.type === 'attributes'
      ? record.target.classList.contains('card') || record.target.tagName === 'SECTION'
      : [...record.addedNodes, ...record.removedNodes].some(node => node.classList?.contains('card') || node.querySelector?.('.card')))) return;
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; refresh(); });
  };
  if (window.MutationObserver) {
    const observer = new MutationObserver(changed);
    document.querySelectorAll('.media-view').forEach(view => observer.observe(view, {subtree:true, childList:true, attributes:true, attributeFilter:['hidden']}));
  }
  refresh();
})();
