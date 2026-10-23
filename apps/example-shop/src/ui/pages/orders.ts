import { formatMoney } from '../../domain/money.ts';
import type { Order, OrderLine } from '../../domain/orders.ts';
import type { Address } from '../../domain/users.ts';
import type { Wallet } from '../../domain/wallet.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, emptyState, price, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderOrderList(_ctx: RenderCtx, orders: Order[]): string {
  const body =
    orders.length === 0
      ? emptyState(
          'No orders yet',
          'Orders you place appear here.',
          '/products',
          'Shop the catalog',
        )
      : `<table class="table">
        <thead><tr><th>Order</th><th>Placed</th><th>By</th><th class="num">Total</th><th>Status</th></tr></thead>
        <tbody>${orders
          .map(
            (order) => `<tr>
              <td><a href="/orders/${esc(order.id)}">${esc(order.id)}</a></td>
              <td>${esc(formatTime(order.createdAt))}</td>
              <td>${order.placedVia === 'agent' ? 'Agent' : 'You'}</td>
              <td class="num">${price(order.total)}</td>
              <td>${statusBadge(order.status)}</td>
            </tr>`,
          )
          .join('')}</tbody>
      </table>`;
  return `
<div class="page-head"><div><span class="eyebrow">Orders</span><h1>Your orders</h1></div></div>
${body}`;
}

export function renderOrderDetail(
  ctx: RenderCtx,
  order: Order,
  lines: OrderLine[],
  wallet: Wallet,
  address: Address | undefined,
): string {
  const rows = lines
    .map(
      (line) => `<tr>
        <td>${esc(line.name)} <span class="row-sub">${esc(line.sku)}</span></td>
        <td class="num">${line.qty}</td>
        <td class="num">${price(line.unitPrice)}</td>
        <td class="num">${price(line.lineTotal)}</td>
      </tr>`,
    )
    .join('');
  const canPay = order.status === 'awaiting_payment' && wallet.balance.amount >= order.total.amount;
  const payBlock =
    order.status === 'awaiting_payment'
      ? `<div class="panel">
          <p class="muted">This order is unpaid. Paying debits your simulated wallet.</p>
          ${
            canPay
              ? `<form method="post" action="/orders/${esc(order.id)}/pay">
                  ${csrfField(ctx.session?.csrfToken)}
                  <button class="button" type="submit">Pay ${esc(formatMoney(order.total))} ${esc(order.total.currency)}</button>
                  <button class="button button-secondary" type="submit" formaction="/orders/${esc(order.id)}/cancel" formnovalidate>Cancel order</button>
                </form>`
              : `<p class="flash flash-error">Insufficient wallet balance (${esc(formatMoney(wallet.balance))} ${esc(wallet.currency)}).</p>
                 <form method="post" action="/orders/${esc(order.id)}/cancel">
                  ${csrfField(ctx.session?.csrfToken)}
                  <button class="button button-secondary" type="submit">Cancel order</button>
                 </form>`
          }
        </div>`
      : order.status === 'paid'
        ? `<div class="panel">
            <p class="muted">Paid ${order.paidAt !== undefined ? esc(formatTime(order.paidAt)) : ''} from the simulated wallet.</p>
            <form method="post" action="/orders/${esc(order.id)}/refund">
              ${csrfField(ctx.session?.csrfToken)}
              <button class="button button-danger" type="submit">Refund this order</button>
            </form>
          </div>`
        : '';
  const meta: string[] = [
    `<dt>Status</dt><dd>${statusBadge(order.status)}</dd>`,
    `<dt>Placed</dt><dd>${esc(formatTime(order.createdAt))}</dd>`,
    `<dt>Placed by</dt><dd>${order.placedVia === 'agent' ? 'Agent (TrailGate grant)' : 'You'}</dd>`,
  ];
  if (order.grantJti !== undefined) {
    meta.push(`<dt>Grant</dt><dd><span class="mono-id">${esc(order.grantJti)}</span></dd>`);
  }
  if (address !== undefined) {
    meta.push(
      `<dt>Ship to</dt><dd>${esc(address.label)} — ${esc(address.line1)}${address.line2 !== undefined ? `, ${esc(address.line2)}` : ''}, ${esc(address.city)}${address.region !== undefined ? `, ${esc(address.region)}` : ''} ${esc(address.postcode)}, ${esc(address.country)}</dd>`,
    );
  }
  if (order.refundedAt !== undefined) {
    meta.push(`<dt>Refunded</dt><dd>${esc(formatTime(order.refundedAt))}</dd>`);
  }
  return `
<div class="page-head">
  <div>
    <span class="eyebrow"><a href="/orders">Orders</a> / ${esc(order.id)}</span>
    <h1>Order ${esc(order.id)}</h1>
  </div>
  <a href="/orders/${esc(order.id)}/invoice">View invoice</a>
</div>
<div class="cart-layout">
  <div>
    <table class="table">
      <thead><tr><th>Item</th><th class="num">Qty</th><th class="num">Price</th><th class="num">Total</th></tr></thead>
      <tbody>${rows}</tbody>
      <tfoot><tr><td colspan="3" class="total-row">Total</td><td class="num total-row">${price(order.total)}</td></tr></tfoot>
    </table>
    <div class="panel panel-sunken"><dl class="dl">${meta.join('')}</dl></div>
  </div>
  <div>${payBlock}</div>
</div>`;
}
