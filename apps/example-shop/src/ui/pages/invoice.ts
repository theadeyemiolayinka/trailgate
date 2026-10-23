import type { Invoice } from '../../domain/orders.ts';
import { esc, formatDate, formatTime } from '../html.ts';
import { price, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

/** Print-friendly invoice view. */
export function renderInvoice(_ctx: RenderCtx, invoice: Invoice): string {
  const { order, lines, address, userName, userEmail } = invoice;
  const rows = lines
    .map(
      (line) => `<tr>
        <td>${esc(line.name)}</td>
        <td class="num">${line.qty}</td>
        <td class="num">${price(line.unitPrice)}</td>
        <td class="num">${price(line.lineTotal)}</td>
      </tr>`,
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
    <table class="table">
      <thead><tr><th>Item</th><th class="num">Qty</th><th class="num">Unit price</th><th class="num">Amount</th></tr></thead>
      <tbody>${rows}</tbody>
      <tfoot><tr><td colspan="3" class="total-row">Total due</td><td class="num total-row">${price(order.total)}</td></tr></tfoot>
    </table>
  </div>
  <aside class="panel">
    <dl class="dl">
      <dt>Billed to</dt><dd>${esc(userName)}<br><span class="muted">${esc(userEmail)}</span></dd>
      <dt>Ship to</dt><dd>${shipTo}</dd>
      <dt>Order</dt><dd><span class="mono-id">${esc(order.id)}</span></dd>
      <dt>Paid</dt><dd>${order.paidAt !== undefined ? esc(formatTime(order.paidAt)) : 'Unpaid'}</dd>
    </dl>
    <p class="faint">ExampleShop is a demonstration storefront. This invoice documents a simulated transaction; no real funds moved.</p>
  </aside>
</div>`;
}
