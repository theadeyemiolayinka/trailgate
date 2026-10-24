(function () {
  const form = document.querySelector('.consent-form');
  if (!form) return;
  const permEcho = form.querySelector('[data-perm-echo]');
  const durationEcho = form.querySelector('[data-duration-echo]');
  const expiryEcho = form.querySelector('[data-expiry-echo]');
  const approve = form.querySelector('[data-approve-btn]');
  const select = form.querySelector('select[name="lifetime_seconds"]');
  function sync() {
    const labels = [];
    const boxes = form.querySelectorAll('input[name="perm"]');
    for (let i = 0; i < boxes.length; i++) {
      if (boxes[i].checked) labels.push(boxes[i].getAttribute('data-label'));
    }
    if (permEcho)
      permEcho.textContent =
        labels.length > 0 ? labels.join(', ').toLowerCase() : 'nothing (approve is disabled)';
    const seconds = Number(select.value);
    if (durationEcho) durationEcho.textContent = select.options[select.selectedIndex].textContent;
    if (expiryEcho) expiryEcho.textContent = new Date(Date.now() + seconds * 1000).toLocaleString();
    if (approve) approve.disabled = labels.length === 0;
  }
  form.addEventListener('change', sync);
  sync();
})();
