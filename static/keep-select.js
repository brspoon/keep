/* Progressive enhancement: native selects remain the form and event contract. */
(() => {
  'use strict';
  let nextId = 0, opened = null;
  const controls = new Set();
  function enhance(select) {
    if (select.multiple || select.size > 1 || select.dataset.keepSelect) return;
    select.dataset.keepSelect = 'true';
    const wrapper = document.createElement('span');
    wrapper.className = 'keep-select';
    select.before(wrapper);
    wrapper.append(select);
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'keep-select-trigger';
    const caption = document.createElement('span');
    caption.className = 'keep-select-caption';
    trigger.append(caption);
    wrapper.append(trigger);
    const panel = document.createElement('div');
    panel.className = 'keep-select-panel';
    panel.hidden = true;
    panel.id = `keep-select-${++nextId}`;
    const search = document.createElement('input');
    search.type = 'search';
    search.className = 'keep-select-search';
    search.placeholder = 'Find an option…';
    search.setAttribute('aria-label', 'Find an option');
    search.autocomplete = 'off';
    const list = document.createElement('div');
    list.className = 'keep-select-list';
    list.id = `${panel.id}-list`;
    list.setAttribute('role', 'listbox');
    panel.append(search, list);
    document.body.append(panel);
    trigger.setAttribute('role', 'combobox');
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-controls', list.id);
    trigger.setAttribute('aria-expanded', 'false');
    let items = [], active = -1, typed = '', typedAt = 0;
    function name() {
      if (select.getAttribute('aria-label')) return select.getAttribute('aria-label');
      if (select.getAttribute('aria-labelledby')) {
        return select.getAttribute('aria-labelledby').split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim();
      }
      return Array.from(select.labels || []).map(label => {
        const copy = label.cloneNode(true);
        copy.querySelectorAll('select,.keep-select').forEach(node => node.remove());
        return copy.textContent.trim();
      }).join(' ') || select.name || 'Choose an option';
    }
    function eligible(item) { return !item.option.disabled && !item.option.parentElement?.disabled && !item.node.hidden; }
    function mark(index) {
      active = index;
      items.forEach((item, i) => item.node.classList.toggle('is-active', i === active));
      if (items[active]) {
        trigger.setAttribute('aria-activedescendant', items[active].node.id);
        search.setAttribute('aria-activedescendant', items[active].node.id);
        items[active].node.scrollIntoView({block: 'nearest'});
      } else {
        trigger.removeAttribute('aria-activedescendant');
        search.removeAttribute('aria-activedescendant');
      }
    }
    function position() {
      const rect = trigger.getBoundingClientRect(), margin = 8;
      if (!rect.width) { close(); return; }
      const width = Math.min(Math.max(rect.width, 240), window.innerWidth - margin * 2);
      panel.style.width = `${width}px`;
      panel.style.left = `${Math.max(margin, Math.min(rect.left, window.innerWidth - width - margin))}px`;
      const below = window.innerHeight - rect.bottom - margin, above = rect.top - margin;
      const upwards = below < 220 && above > below;
      panel.style.maxHeight = `${Math.max(44, Math.min(360, upwards ? above : below))}px`;
      panel.style.top = upwards ? 'auto' : `${rect.bottom + 4}px`;
      panel.style.bottom = upwards ? `${window.innerHeight - rect.top + 4}px` : 'auto';
    }
    function close(focus = false) {
      panel.hidden = true;
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      if (opened === control) opened = null;
      if (focus) trigger.focus();
    }
    let cachedName = name();
    function sync() {
      const value = select.options[select.selectedIndex]?.textContent || 'Choose an option';
      if (caption.textContent !== value) caption.textContent = value;
      trigger.disabled = select.disabled || Boolean(select.closest('fieldset:disabled'));
      trigger.setAttribute('aria-label', `${cachedName}: ${caption.textContent}`);
      list.setAttribute('aria-label', cachedName);
      trigger.setAttribute('aria-required', String(select.required));
      trigger.setAttribute('aria-invalid', String(!select.validity.valid));
      items.forEach(item => item.node.setAttribute('aria-selected', String(item.option.selected)));
      if (trigger.disabled) close();
    }
    function render() {
      list.replaceChildren();
      items = [];
      let previousGroup = null;
      Array.from(select.options).forEach((option, index) => {
        const group = option.parentElement.tagName === 'OPTGROUP' ? option.parentElement : null;
        if (group && group !== previousGroup) {
          const heading = document.createElement('div');
          heading.className = 'keep-select-group';
          heading.textContent = group.label;
          list.append(heading);
        }
        previousGroup = group;
        const node = document.createElement('div');
        node.className = 'keep-select-option';
        node.id = `${panel.id}-option-${index}`;
        node.setAttribute('role', 'option');
        node.setAttribute('aria-disabled', String(option.disabled || Boolean(group?.disabled)));
        node.textContent = option.textContent;
        node.hidden = option.hidden || Boolean(group?.hidden);
        node.addEventListener('click', () => commit(index));
        list.append(node);
        items.push({option, node});
      });
      search.hidden = items.length < 12;
      search.setAttribute('role', 'combobox');
      search.setAttribute('aria-controls', list.id);
      search.setAttribute('aria-expanded', 'true');
      sync();
    }
    function commit(index) {
      if (trigger.disabled || !items[index] || !eligible(items[index])) return;
      const changed = select.selectedIndex !== index;
      select.selectedIndex = index;
      sync();
      close(true);
      if (changed) select.dispatchEvent(new Event('change', {bubbles: true}));
    }
    function open() {
      sync();
      if (trigger.disabled) return;
      if (opened && opened !== control) opened.close();
      render();
      search.value = '';
      panel.hidden = false;
      opened = control;
      trigger.setAttribute('aria-expanded', 'true');
      position();
      mark(items[select.selectedIndex] && eligible(items[select.selectedIndex]) ? select.selectedIndex : items.findIndex(eligible));
      if (!search.hidden) search.focus();
    }
    function move(direction, edge) {
      const indices = items.map((item, i) => eligible(item) ? i : -1).filter(i => i >= 0);
      if (!indices.length) return mark(-1);
      const current = indices.indexOf(active);
      mark(edge === 'first' ? indices[0] : edge === 'last' ? indices[indices.length - 1] : indices[(current + direction + indices.length) % indices.length]);
    }
    function keydown(event) {
      const inSearch = event.target === search;
      if (event.key === 'Escape' && !panel.hidden) { event.preventDefault(); close(true); return; }
      if (event.key === 'Tab') { close(inSearch); return; }
      if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) && !(inSearch && ['Home', 'End'].includes(event.key))) {
        event.preventDefault();
        if (panel.hidden) open();
        else move(event.key === 'ArrowUp' ? -1 : 1, event.key === 'Home' ? 'first' : event.key === 'End' ? 'last' : null);
      } else if (event.key === 'Enter' || (event.key === ' ' && !inSearch)) {
        event.preventDefault();
        if (panel.hidden) open(); else commit(active);
      } else if (!inSearch && event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        if (panel.hidden) open();
        const now = Date.now();
        typed = now - typedAt > 700 ? event.key : typed + event.key;
        typedAt = now;
        const query = typed.toLocaleLowerCase();
        const index = items.findIndex(item => eligible(item) && item.option.textContent.trim().toLocaleLowerCase().startsWith(query));
        if (index >= 0) mark(index);
      }
    }
    const control = {select, trigger, panel, sync, close, position};
    controls.add(control);
    trigger.addEventListener('click', event => { event.preventDefault(); event.stopPropagation(); panel.hidden ? open() : close(); });
    trigger.addEventListener('keydown', keydown);
    search.addEventListener('keydown', keydown);
    search.addEventListener('input', () => {
      const query = search.value.trim().toLocaleLowerCase();
      items.forEach(item => { item.node.hidden = item.option.hidden || !item.option.textContent.toLocaleLowerCase().includes(query); });
      list.querySelectorAll('.keep-select-group').forEach(node => { node.hidden = Boolean(query); });
      mark(items.findIndex(eligible));
    });
    select.addEventListener('change', sync);
    select.addEventListener('focus', () => trigger.focus());
    select.addEventListener('invalid', () => { trigger.setAttribute('aria-invalid', 'true'); trigger.focus(); });
    select.form?.addEventListener('reset', () => setTimeout(() => { close(); sync(); }, 0));
    const observer = new MutationObserver(() => { cachedName = name(); sync(); if (!panel.hidden) { render(); position(); } });
    observer.observe(select, {attributes: true, childList: true, subtree: true, characterData: true});
    Array.from(select.labels || []).forEach(label => label.addEventListener('click', event => {
      if (event.target === label || !event.target.closest('button,input,a,select')) { event.preventDefault(); trigger.focus(); }
    }));
    select.classList.add('keep-select-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');
    sync();
  }
  function scan() { document.querySelectorAll('select').forEach(enhance); }
  document.addEventListener('pointerdown', event => {
    if (opened && !opened.panel.contains(event.target) && !opened.trigger.contains(event.target)) opened.close();
  });
  document.addEventListener('focusin', event => {
    if (opened && !opened.panel.contains(event.target) && event.target !== opened.trigger) opened.close();
  });
  window.addEventListener('resize', () => opened?.position());
  window.addEventListener('scroll', () => opened?.position(), true);
  scan();
  new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
  // Native value/selectedIndex assignments do not emit change or mutation events.
  setInterval(() => {
    controls.forEach(control => {
      if (!control.select.isConnected) { control.close(); control.panel.remove(); controls.delete(control); }
      else control.sync();
    });
  }, 250);
})();
