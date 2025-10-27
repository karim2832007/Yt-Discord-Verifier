document.addEventListener("DOMContentLoaded", () => {
  const didInput = document.getElementById('did');
  const copyBtn = document.getElementById('copy');
  const contBtn = document.getElementById('continue');
  const scriptTag = document.currentScript || document.querySelector('script[src$="id.js"]');
  const TARGET = scriptTag ? scriptTag.getAttribute('data-target') : "";

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(didInput.value);
      copyBtn.textContent = 'Copied!';
    } catch (e) {
      // fallback for browsers without Clipboard API
      didInput.select();
      document.execCommand('copy');
      copyBtn.textContent = 'Copied (fallback)!';
    }
    contBtn.disabled = false;
  });

  contBtn.addEventListener('click', () => {
    const sep = TARGET.includes('?') ? '&' : '?';
    location.href = TARGET + sep + 'discord_id=' + encodeURIComponent(didInput.value);
  });
});