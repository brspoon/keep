/* Merge the server's user cards without interrupting account edits. */
(() => {
  'use strict';
  const endpoint = '/settings/users';
  let pending = null, controller = null, stopped = false, generation = 0;

  function cards(list) {
    const result = new Map();
    for (const card of list.querySelectorAll('.user-card')) {
      const forms = card.querySelectorAll('form[data-save-key]');
      const key = forms[0]?.dataset.saveKey;
      if (card.parentElement !== list || forms.length !== 1
          || !/^user-[A-Za-z0-9:_-]+$/.test(key || '') || result.has(key)
          || card.querySelectorAll('.user-editor').length !== 1 || card.querySelector('script')) {
        throw new Error('Invalid user list');
      }
      result.set(key, card);
    }
    if (!result.size && !list.querySelector('.empty')) throw new Error('Missing user cards');
    return result;
  }

  function merge(list, incoming) {
    const current = cards(list), next = cards(incoming);
    const active = document.activeElement;
    const anchor = [...current.values()].find(card => card.contains(active));
    const preserve = card => !card.querySelector('.user-editor').hidden || card === anchor;
    const ordered = [...next].map(([key, card]) => {
      const old = current.get(key);
      return old && preserve(old) ? old : document.importNode(card, true);
    });
    for (const [key, card] of current) {
      if (!next.has(key) && preserve(card)) ordered.push(card);
    }
    if (!ordered.length) ordered.push(document.importNode(incoming.querySelector('.empty'), true));
    const left = window.scrollX, top = window.scrollY;
    for (const child of [...list.childNodes]) if (!ordered.includes(child)) child.remove();
    if (anchor && ordered.includes(anchor)) {
      const position = ordered.indexOf(anchor);
      // Keep the focused subtree attached: moving it would blur an input in Safari.
      for (const card of ordered.slice(0, position)) {
        if (card.nextSibling !== anchor) list.insertBefore(card, anchor);
      }
      for (const card of ordered.slice(position + 1).reverse()) {
        if (card !== anchor.nextSibling) list.insertBefore(card, anchor.nextSibling);
      }
    } else {
      let cursor = list.firstChild;
      for (const card of ordered) {
        if (card === cursor) cursor = cursor.nextSibling;
        else list.insertBefore(card, cursor);
      }
    }
    document.dispatchEvent(new CustomEvent('keep-users-updated'));
    window.scrollTo({left, top, behavior:'instant'});
  }

  async function update(list, request, version) {
    let timer;
    const aborted = new Promise((_, reject) => {
      request.signal.addEventListener('abort', () => reject(new Error('User refresh cancelled')), {once:true});
    });
    try {
      timer = setTimeout(() => request.abort(), 15000);
      const response = await Promise.race([fetch(endpoint, {method:'GET', credentials:'same-origin',
        mode:'same-origin', cache:'no-store', redirect:'error', headers:{Accept:'text/html'},
        signal:request.signal}), aborted]);
      if (response.status !== 200 || !response.ok || response.redirected
          || response.type === 'opaqueredirect') return false;
      const url = new URL(response.url);
      if (url.origin !== window.location.origin || url.pathname !== endpoint || url.search || url.hash
          || !/^text\/html(?:\s*;|\s*$)/i.test(response.headers.get('Content-Type') || '')) return false;
      const html = await Promise.race([response.text(), aborted]);
      if (typeof html !== 'string' || stopped || version !== generation || !list.isConnected) return false;
      const parsed = new DOMParser().parseFromString(html, 'text/html');
      const lists = parsed.querySelectorAll('.admin-card-list');
      if (lists.length !== 1) return false;
      merge(list, lists[0]);
      return true;
    } catch (_) {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  function refresh() {
    if (pending) return pending;
    if (stopped || typeof fetch !== 'function' || typeof AbortController !== 'function'
        || typeof DOMParser !== 'function') return Promise.resolve(false);
    const lists = document.querySelectorAll('.admin-card-list');
    if (lists.length !== 1) return Promise.resolve(false);
    controller = new AbortController();
    const task = update(lists[0], controller, generation).finally(() => {
      if (pending === task) { pending = null; controller = null; }
    });
    pending = task;
    return task;
  }

  window.KeepUsers = {refresh};
  window.addEventListener('pagehide', () => { stopped = true; ++generation; controller?.abort(); });
  window.addEventListener('pageshow', () => { stopped = false; });
})();
