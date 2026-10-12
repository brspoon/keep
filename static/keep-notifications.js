/* Native form submissions preserve the ordinary settings redirects and CSRF checks. */
(() => {
  document.querySelectorAll('.subscriptions').forEach(form => {
    const topics = [...form.querySelectorAll('input[name="collection_id"]')];
    const error = form.querySelector('.subscription-error');
    const validate = () => {
      const valid = topics.some(input => !input.disabled && input.checked);
      form.classList.toggle('invalid', !valid);
      return valid;
    };
    topics.forEach(input => input.addEventListener('change', validate));
    // Validate before the shared Save handler records a pending submission.
    form.addEventListener('submit', event => {
      if (validate()) return;
      event.preventDefault();
      const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      error?.scrollIntoView({ behavior: reduced ? 'instant' : 'smooth', block: 'center' });
      topics.find(input => !input.disabled)?.focus({ preventScroll: true });
    }, true);
  });
  document.querySelectorAll('[data-secret-control]').forEach(control => {
    const mode = control.querySelector('[data-secret-mode]');
    const replacement = control.querySelector('[data-secret-replacement]');
    const input = replacement?.querySelector('input');
    if (!mode || !replacement || !input) return;
    const sync = () => {
      replacement.hidden = mode.disabled || mode.value !== 'replace';
      input.disabled = replacement.hidden;
      if (replacement.hidden) input.value = '';
    };
    mode.addEventListener('change', sync);
    window.addEventListener('pageshow', sync);
    sync();
  });
  document.querySelectorAll('[data-delivery-review]').forEach(form => {
    const confirm = form.querySelector('[data-review-confirm]');
    const retry = form.querySelector('[data-review-retry]');
    const error = form.querySelector('.notification-review-error');
    if (!confirm || !retry || !error) return;
    confirm.addEventListener('change', () => { if (confirm.checked) error.hidden = true; });
    form.addEventListener('submit', event => {
      if (event.submitter !== retry || confirm.checked) return;
      event.preventDefault();
      error.hidden = false;
      confirm.focus({ preventScroll: true });
    });
    window.addEventListener('pageshow', () => { error.hidden = true; });
  });
  document.querySelectorAll('[data-notification-test]').forEach(form => {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    const label = button.textContent;
    const disabled = button.disabled;
    let submitting = false;
    form.addEventListener('submit', event => {
      if (submitting || disabled) { event.preventDefault(); return; }
      submitting = true;
      button.disabled = true;
      button.textContent = 'Sending…';
    });
    window.addEventListener('pageshow', () => {
      submitting = false;
      button.disabled = disabled;
      button.textContent = label;
    });
  });
})();
