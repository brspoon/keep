/* The full key exists only on its creation response. Clear restored pages too. */
(() => {
  const input = document.getElementById('new-api-key');
  const copy = document.getElementById('copy-api-key');
  const status = document.getElementById('copy-key-status');
  if (!input || !copy || !status) return;
  copy.addEventListener('click', async () => {
    if (!input.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      status.textContent = 'Key copied. Store it in your integration’s secret settings.';
    } catch (_) {
      input.focus();
      input.select();
      status.textContent = 'Copy the selected key using your device’s copy command.';
    }
  });
  const clear = () => {
    input.value = '';
    input.removeAttribute('value');
    copy.disabled = true;
    status.textContent = 'The full key is no longer shown. Replace the key if you did not save it.';
  };
  window.addEventListener('pagehide', clear);
  window.addEventListener('pageshow', event => { if (event.persisted) clear(); });
})();
