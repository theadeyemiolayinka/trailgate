import type { Invoice } from '../../domain/orders.ts';
import { esc, formatDate, formatTime } from '../html.ts';
import { price, productThumb, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

/** Print-friendly invoice view. */
export function renderInvoice(_ctx: RenderCtx, invoice: Invoice): string {
  const { order, lines, address, userName, userEmail } = invoice;
  const rows = lines
    .map(
      (line) => `<div class="cart-line">
        <div class="cart-line-media">${productThumb(line.sku, line.name)}</div>
        <div class="cart-line-info">
          <span class="cart-line-name">${esc(line.name)}</span>
          <span class="cart-line-unit">${price(line.unitPrice)} x ${line.qty}</span>
        </div>
        <div class="cart-line-price">${price(line.lineTotal)}</div>
      </div>`,
    )
    .join('');
  const shipTo =
    address !== undefined
      ? `<p>${esc(address.line1)}${address.line2 !== undefined ? `<br>${esc(address.line2)}` : ''}<br>
        ${esc(address.city)}${address.region !== undefined ? `, ${esc(address.region)}` : ''} ${esc(address.postcode)}<br>
        ${esc(address.country)}</p>`
      : '<p class="muted">No address on file.</p>';
  return `
<div class="page-head">
  <div>
    <span class="eyebrow">Invoice ${esc(order.id)}</span>
    <h1>Invoice</h1>
    <p class="lede">Issued ${esc(formatDate(order.createdAt))} · ${statusBadge(order.status)}</p>
  </div>
  <button class="button button-secondary no-print" onclick="window.print()">Print</button>
</div>
<div class="cart-layout">
  <div>
    <div class="cart-lines">${rows}</div>
    <div class="summary-line summary-total"><span>Total due</span>${price(order.total)}</div>
  </div>
  <aside class="summary-card">
    <h2>Billing</h2>
    <dl class="dl" style="grid-template-columns:1fr">
      <dt>Billed to</dt><dd>${esc(userName)}<br><span class="muted">${esc(userEmail)}</span></dd>
      <dt>Ship to</dt><dd>${shipTo}</dd>
      <dt>Order</dt><dd><span class="mono-id">${esc(order.id)}</span></dd>
      <dt>Paid</dt><dd>${order.paidAt !== undefined ? esc(formatTime(order.paidAt)) : 'Unpaid'}</dd>
    </dl>
    <p class="faint" style="margin:var(--space-3) 0 0">ExampleShop is a demonstration storefront. This invoice documents a simulated transaction; no real funds moved.</p>
  </aside>
</div>`;
}
