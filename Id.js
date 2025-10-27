// id.js — place beside app.py
const didInput = document.getElementById('did');
const copyBtn = document.getElementById('copy');
const contBtn = document.getElementById('continue');
const TARGET = document.currentScript.getAttribute('data-target') || "";

copyBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(didInput.value);
    copyBtn.textContent = 'Copied!';
    contBtn.disabled = false;
  } catch (e) {
    didInput.select();
    copyBtn.textContent = 'Select & copy';
    contBtn.disabled = false;
  }
});

contBtn.addEventListener('click', () => {
  const sep = TARGET.includes('?') ? '&' : '?';
  location.href = TARGET + sep + 'discord_id=' + encodeURIComponent(didInput.value);
});
