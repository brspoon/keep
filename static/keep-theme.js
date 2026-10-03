/* Resolve a saved choice before styles paint; follow system changes live. */
(() => {
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  const valid = ['system', 'light', 'dark'];
  window.keepApplyTheme = choice => {
    const mode = valid.includes(choice) ? choice : 'system';
    const appearance = mode === 'system' ? (system.matches ? 'dark' : 'light') : mode;
    root.dataset.theme = mode;
    root.dataset.appearance = appearance;
    document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', appearance);
  };
  window.keepApplyTheme(root.dataset.theme);
  document.addEventListener('change', event => {
    if (event.target.matches('input[type="radio"][name="theme_mode"]')) {
      window.keepApplyTheme(event.target.value);
    }
  });
  system.addEventListener('change', () => {
    if (root.dataset.theme === 'system') window.keepApplyTheme('system');
  });
})();
