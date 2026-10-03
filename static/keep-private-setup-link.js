/* Copy only on request; leave a selected URL for manual copying if unavailable. */
(() => {
  const input = document.getElementById('private-setup-url');
  const copy = document.getElementById('copy-setup-url');
  const status = document.getElementById('copy-setup-status');
  if (!input || !copy || !status) return;
  copy.addEventListener('click', async () => {
    if (!input.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      status.textContent = 'Setup URL copied. Share it only with the intended person.';
    } catch (_) {
      input.focus();
      input.select();
      status.textContent = 'Copy the selected setup URL using your device’s copy command.';
    }
  });
})();
