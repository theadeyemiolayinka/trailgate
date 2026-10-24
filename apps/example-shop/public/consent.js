(() => {
  const form = document.querySelector('.consent-form');
  if (!form) return;
  const permEcho = form.querySelector('[data-perm-echo]');
  const durationEcho = form.querySelector('[data-duration-echo]');
  const expiryEcho = form.querySelector('[data-expiry-echo]');
  const approve = form.querySelector('[data-approve-btn]');
  const select = form.querySelector('select[name="lifetime_seconds"]');
  function sync() {
    // Each permission is a radio group named `mode_<permission>` with
    // values allow / approval / deny; granted means not denied.
    const picked = form.querySelectorAll('input[name^="mode_"]:checked');
    const granted = [];
    const asked = [];
    for (let i = 0; i < picked.length; i++) {
      const group = picked[i].closest('[data-label]');
      const label = group ? group.getAttribute('data-label') : picked[i].name.slice(5);
      if (picked[i].value === 'approval') {
        granted.push(label);
        asked.push(label);
      } else if (picked[i].value === 'allow') {
        granted.push(label);
      }
    }
    if (permEcho) {
      let text =
        granted.length > 0 ? granted.join(', ').toLowerCase() : 'nothing (approve is disabled)';
      if (asked.length > 0) {
        text += `; asks you first for: ${asked.join(', ').toLowerCase()}`;
      }
      permEcho.textContent = text;
    }
    const seconds = Number(select.value);
    if (durationEcho) durationEcho.textContent = select.options[select.selectedIndex].textContent;
    if (expiryEcho) expiryEcho.textContent = new Date(Date.now() + seconds * 1000).toLocaleString();
    if (approve) approve.disabled = granted.length === 0;
  }
  form.addEventListener('change', sync);
  sync();
})();
