import { formatMoney } from '../../domain/money.ts';
import type { Order, OrderLine } from '../../domain/orders.ts';
import type { Address } from '../../domain/users.ts';
import type { Wallet } from '../../domain/wallet.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, emptyState, pageHead, price, productThumb, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';

export function renderOrderList(_ctx: RenderCtx, orders: Order[]): string {
  const body =
    orders.length === 0
      ? emptyState(
          'No orders yet',
          'Orders you place appear here.',
          '/products',
          'Shop the catalogue',
        )
      : `<table class="table table-cards">
        <thead><tr><th>Order</th><th>Placed</th><th>By</th><th class="num">Total</th><th>Status</th></tr></thead>
        <tbody>${orders
          .map(
            (order) => `<tr>
              <td data-label="Order"><a href="/orders/${esc(order.id)}">${esc(order.id)}</a></td>
              <td data-label="Placed">${esc(formatTime(order.createdAt))}</td>
              <td data-label="By">${order.placedVia === 'agent' ? 'Agent' : 'You'}</td>
              <td data-label="Total" class="num">${price(order.total)}</td>
              <td data-label="Status">${statusBadge(order.status)}</td>
            </tr>`,
          )
          .join('')}</tbody>
      </table>`;
  return `
${pageHead('Account', 'Your orders')}
<div class="account-grid">
  ${accountNav('orders')}
  <div>${body}</div>
</div>`;
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
      (line) => `<div class="cart-line">
        <a class="cart-line-media" href="/products/${esc(line.sku)}">${productThumb(line.sku, line.name)}</a>
        <div class="cart-line-info">
          <span class="cart-line-name"><a href="/products/${esc(line.sku)}">${esc(line.name)}</a></span>
          <span class="cart-line-sku">${esc(line.sku)}</span>
          <span class="cart-line-unit">${price(line.unitPrice)} x ${line.qty}</span>
        </div>
        <div class="cart-line-price">${price(line.lineTotal)}</div>
      </div>`,
    )
    .join('');
  const canPay = order.status === 'awaiting_payment' && wallet.balance.amount >= order.total.amount;
  const payBlock =
    order.status === 'awaiting_payment'
      ? `<div class="summary-card">
          <h2>Awaiting payment</h2>
          <div class="summary-line"><span class="muted">Wallet balance</span>${price(wallet.balance)}</div>
          <div class="summary-line summary-total"><span>Due</span>${price(order.total)}</div>
          ${
            canPay
              ? `<form method="post" action="/orders/${esc(order.id)}/pay">
                  ${csrfField(ctx.session?.csrfToken)}
                  <button class="button button-block" type="submit">Pay ${esc(formatMoney(order.total))} ${esc(order.total.currency)}</button>
                  <button class="button button-secondary button-block" type="submit" formaction="/orders/${esc(order.id)}/cancel" formnovalidate>Cancel order</button>
                </form>`
              : `<div class="flash flash-error" role="alert">Insufficient wallet balance (${esc(formatMoney(wallet.balance))} ${esc(wallet.currency)}).</div>
                 <a class="button button-secondary button-block" href="/account/wallet">Top up wallet</a>
                 <form method="post" action="/orders/${esc(order.id)}/cancel">
                  ${csrfField(ctx.session?.csrfToken)}
                  <button class="button button-secondary button-block" type="submit">Cancel order</button>
                 </form>`
          }
          <p class="summary-note">Paying debits your simulated wallet immediately.</p>
        </div>`
      : order.status === 'paid'
        ? `<div class="summary-card">
            <h2>Paid</h2>
            <p class="muted">Paid ${order.paidAt !== undefined ? esc(formatTime(order.paidAt)) : ''} from the simulated wallet.</p>
            <form method="post" action="/orders/${esc(order.id)}/refund">
              ${csrfField(ctx.session?.csrfToken)}
              <button class="button button-danger button-block" type="submit">Refund this order</button>
            </form>
          </div>`
        : '';
  const meta: string[] = [
    `<dt>Status</dt><dd>${statusBadge(order.status)}</dd>`,
    `<dt>Placed</dt><dd>${esc(formatTime(order.createdAt))}</dd>`,
    `<dt>Placed by</dt><dd>${order.placedVia === 'agent' ? 'Agent (TrailGate grant)' : 'You'}</dd>`,
  ];
  if (order.grantJti !== undefined) {
    meta.push(
      `<dt>Grant</dt><dd><a class="mono-id" href="/account/connections/${esc(order.grantJti)}">${esc(order.grantJti)}</a></dd>`,
    );
  }
  if (address !== undefined) {
    meta.push(
      `<dt>Ship to</dt><dd>${esc(address.label)} - ${esc(address.line1)}${address.line2 !== undefined ? `, ${esc(address.line2)}` : ''}, ${esc(address.city)}${address.region !== undefined ? `, ${esc(address.region)}` : ''} ${esc(address.postcode)}, ${esc(address.country)}</dd>`,
    );
  }
  if (order.refundedAt !== undefined) {
    meta.push(`<dt>Refunded</dt><dd>${esc(formatTime(order.refundedAt))}</dd>`);
  }
  return `
<nav class="crumbs" aria-label="Breadcrumb"><a href="/orders">Orders</a><span class="crumb-sep">/</span>${esc(order.id)}</nav>
<div class="page-head">
  <h1>Order ${esc(order.id)}</h1>
  <a class="button button-secondary button-small" href="/orders/${esc(order.id)}/invoice">View invoice</a>
</div>
<div class="cart-layout">
  <div>
    <div class="cart-lines">${rows}</div>
    <div class="summary-line summary-total"><span>Total</span>${price(order.total)}</div>
    <div class="panel panel-sunken" style="margin-top:var(--space-5)"><dl class="dl">${meta.join('')}</dl></div>
  </div>
  <div>${payBlock}</div>
</div>`;
}
