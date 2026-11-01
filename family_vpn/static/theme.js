/* Apply before styles load to avoid flashing the wrong theme. */
(() => {
  'use strict';
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { preference = localStorage.getItem('family-vpn-theme') || 'system'; } catch (_) { /* Storage may be disabled. */ }
  if (!['system', 'light', 'dark'].includes(preference)) preference = 'system';
  const apply = () => {
    root.dataset.theme = preference === 'system' ? (system.matches ? 'dark' : 'light') : preference;
  };
  apply();
  system.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-control]').forEach(control => { control.hidden = false; });
    document.querySelectorAll('[data-theme-choice]').forEach(choice => {
      choice.value = preference;
      choice.addEventListener('change', () => {
        preference = choice.value;
        try { localStorage.setItem('family-vpn-theme', preference); } catch (_) { /* Keep this session's choice. */ }
        apply();
      });
    });
  });
})();
