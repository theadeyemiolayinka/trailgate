import type { Cart } from '../../domain/cart.ts';
import { formatMoney, formatMoneyWithCurrency } from '../../domain/money.ts';
import type { Address } from '../../domain/users.ts';
import type { Wallet } from '../../domain/wallet.ts';
import { esc } from '../html.ts';
import { csrfField, emptyState, pageHead, price, productThumb } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

function addressOption(address: Address, selectedId: string | undefined): string {
  const selected = address.id === selectedId || (selectedId === undefined && address.isDefault);
  return `<option value="${esc(address.id)}"${selected ? ' selected' : ''}>${esc(
    `${address.label} — ${address.line1}, ${address.city}`,
  )}</option>`;
}

export function renderCheckout(
  ctx: RenderCtx,
  cart: Cart,
  wallet: Wallet,
  addresses: Address[],
  error?: string,
): string {
  if (cart.lines.length === 0) {
    return `
${pageHead('Checkout', 'Checkout')}
${emptyState('Nothing to check out', 'Your cart is empty.', '/products', 'Shop the catalogue')}`;
  }
  const summaryItems = cart.lines
    .map(
      (line) => `<div class="summary-item">
        <a class="thumb" href="/products/${esc(line.sku)}">${productThumb(line.sku, line.name)}</a>
        <span class="summary-item-name">${esc(line.name)}<span class="row-sub">x ${line.qty}</span></span>
        <span class="num">${price(line.lineTotal)}</span>
      </div>`,
    )
    .join('');
  const canPay = wallet.balance.amount >= cart.total.amount;
  const errorBlock =
    error !== undefined ? `<div class="flash flash-error" role="alert">${esc(error)}</div>` : '';
  const paymentBlock = canPay
    ? `<button class="button button-block" type="submit">Place order and pay ${esc(formatMoneyWithCurrency(cart.total))}</button>`
    : `<div class="flash flash-error" role="alert">Insufficient wallet balance: ${esc(formatMoneyWithCurrency(wallet.balance))} available, ${esc(formatMoneyWithCurrency(cart.total))} needed.</div>
       <p><a class="button button-secondary button-block" href="/account/wallet">Top up the simulated wallet</a></p>
       <button class="button button-block" type="submit" disabled>Place order and pay</button>`;
  return `
${pageHead('Checkout', 'Checkout', 'Review your order and pay with your simulated wallet.')}
${errorBlock}
<div class="cart-layout">
  <form method="post" action="/checkout" class="checkout-form">
    ${csrfField(ctx.session?.csrfToken)}
    <div class="panel checkout-section">
      <div class="section-head"><h3>Shipping address</h3><a href="/account/addresses">Manage addresses</a></div>
      ${
        addresses.length === 0
          ? '<p class="muted">No saved addresses. Add one on your account page, or leave this blank.</p>'
          : `<div class="field">
              <label for="address_id">Deliver to</label>
              <select id="address_id" name="address_id">
                <option value="">No address</option>
                ${addresses.map((a) => addressOption(a, undefined)).join('')}
              </select>
            </div>`
      }
    </div>
    <div class="panel checkout-section">
      <div class="section-head"><h3>Payment</h3></div>
      <dl class="dl">
        <dt>Method</dt><dd>Simulated wallet</dd>
        <dt>Wallet balance</dt><dd>${esc(formatMoney(wallet.balance))} ${esc(wallet.currency)}</dd>
        <dt>Order total</dt><dd>${price(cart.total)}</dd>
      </dl>
      ${paymentBlock}
      <p class="consent-note">Paying debits your wallet balance immediately. The wallet is simulated: no real funds move.</p>
    </div>
  </form>
  <aside class="summary-card">
    <h2>Order summary</h2>
    <div class="summary-items" style="border:0;margin:0;padding:0">${summaryItems}</div>
    <div class="summary-line summary-total"><span>Total</span>${price(cart.total)}</div>
  </aside>
</div>`;
}
