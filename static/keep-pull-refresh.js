/* Refresh only a deliberate page pull; leave controls and nested scrolling alone. */
(() => {
  if (document.documentElement.dataset.keepPullRefresh === 'true') return;
  document.documentElement.dataset.keepPullRefresh = 'true';
  const mobile = window.matchMedia('(max-width: 700px)');
  const refreshUrl = document.currentScript?.dataset.refreshUrl;
  const indicator = document.createElement('div');
  indicator.id = 'pull-refresh';
  indicator.className = 'pull-refresh';
  indicator.setAttribute('role', 'status');
  indicator.setAttribute('aria-live', 'polite');
  indicator.setAttribute('aria-atomic', 'true');
  const icon = document.createElement('span');
  icon.className = 'pull-refresh-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = '↓';
  const label = document.createElement('span');
  label.id = 'pull-refresh-text';
  indicator.append(icon, label);
  document.body.append(indicator);

  const threshold = 85;
  let start = null;
  let distance = 0;
  let refreshing = false;
  let hideTimer;
  const reset = () => {
    window.clearTimeout(hideTimer);
    start = null;
    distance = 0;
    refreshing = false;
    indicator.classList.remove('visible', 'ready');
    label.textContent = 'Pull to refresh';
  };
  const atTop = () => window.scrollY <= 1 && (document.scrollingElement?.scrollTop || 0) <= 1;
  const modalOpen = () => !!document.querySelector('dialog[open]');
  const eligibleTarget = target => {
    if (!target?.closest || target.closest('a, button, input, select, textarea, label, summary, [contenteditable]:not([contenteditable="false"]), [role="button"], [role="slider"], [data-no-pull-refresh]')) return false;
    for (let element = target; element && element !== document.body && element !== document.documentElement; element = element.parentElement) {
      const style = window.getComputedStyle(element);
      const canScroll = overflow => /^(auto|scroll|overlay)$/.test(overflow);
      if ((canScroll(style.overflowY) && element.scrollHeight > element.clientHeight + 1) ||
          (canScroll(style.overflowX) && element.scrollWidth > element.clientWidth + 1)) return false;
    }
    return true;
  };
  const fieldChanged = field => {
    if (!field.name || field.disabled || field.readOnly || ['hidden', 'submit', 'button', 'reset', 'image'].includes(field.type) || field.dataset?.revealedSaved === 'true') return false;
    if (['checkbox', 'radio'].includes(field.type)) return field.checked !== field.defaultChecked;
    if (field.options) {
      const defaults = [...field.options].filter(option => option.defaultSelected);
      if (!field.multiple && !defaults.length) {
        const first = [...field.options].find(option => !option.disabled && !option.closest('optgroup[disabled]'));
        if (first) defaults.push(first);
      }
      return [...field.options].some(option => option.selected !== defaults.includes(option));
    }
    return field.value !== field.defaultValue;
  };
  const hasUnsavedChanges = () => {
    if (window.keepHasUnsavedChanges?.()) return true;
    return [...document.forms].some(form => {
      if (form.method.toLowerCase() !== 'post') return false;
      // Protected forms use their saved snapshots, including revealed credentials.
      if (window.keepHasUnsavedChanges && form.matches('[data-save-key], [data-protect-unsaved]')) return false;
      if (form.closest('dialog:not([open])')) return false;
      return [...form.elements].some(fieldChanged);
    });
  };
  const syncMobile = () => {
    document.documentElement.classList.toggle('keep-pull-refresh-enabled', mobile.matches);
    reset();
  };
  mobile.addEventListener('change', syncMobile);
  syncMobile();

  document.addEventListener('touchstart', event => {
    if (refreshing) return;
    reset();
    if (!mobile.matches || modalOpen() || !atTop() || event.touches.length !== 1 || !eligibleTarget(event.target)) return;
    const touch = event.touches[0];
    start = {x:touch.clientX, y:touch.clientY, id:touch.identifier, dragging:false};
  }, {passive:true});

  document.addEventListener('touchmove', event => {
    if (!start) return;
    if (!mobile.matches || modalOpen() || !atTop() || event.touches.length !== 1 || event.touches[0].identifier !== start.id) { reset(); return; }
    const touch = event.touches[0];
    const deltaX = Math.abs(touch.clientX - start.x);
    const deltaY = touch.clientY - start.y;
    if (!start.dragging && Math.max(deltaX, Math.abs(deltaY)) < 10) return;
    if (deltaY <= 0 || deltaX > deltaY * 0.75) { reset(); return; }
    if (!event.cancelable) { reset(); return; }
    event.preventDefault();
    start.dragging = true;
    distance = deltaY;
    indicator.classList.add('visible');
    indicator.classList.toggle('ready', distance >= threshold);
    const message = distance >= threshold ? 'Release to refresh' : 'Pull to refresh';
    if (label.textContent !== message) label.textContent = message;
  }, {passive:false});

  document.addEventListener('touchend', event => {
    if (!start) return;
    if (!mobile.matches || modalOpen() || !atTop() || event.touches.length || distance < threshold) { reset(); return; }
    start = null;
    if (hasUnsavedChanges()) {
      indicator.classList.remove('ready');
      label.textContent = 'Save changes before refreshing';
      hideTimer = window.setTimeout(reset, 2000);
      return;
    }
    refreshing = true;
    indicator.classList.remove('ready');
    label.textContent = 'Refreshing…';
    // A POST-rendered view must navigate with GET rather than repeat its action.
    if (refreshUrl) window.location.replace(refreshUrl);
    else window.location.reload();
    // A cancelled browser navigation must leave the current page usable.
    hideTimer = window.setTimeout(reset, 3000);
  }, {passive:true});
  document.addEventListener('touchcancel', reset, {passive:true});
  document.addEventListener('visibilitychange', () => { if (document.hidden) reset(); });
  window.addEventListener('pageshow', reset);
})();
