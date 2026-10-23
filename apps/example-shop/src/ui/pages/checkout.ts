import type { Cart } from '../../domain/cart.ts';
import { formatMoney } from '../../domain/money.ts';
import type { Address } from '../../domain/users.ts';
import type { Wallet } from '../../domain/wallet.ts';
import { esc } from '../html.ts';
import { csrfField, emptyState, price } from '../layout.ts';
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
<div class="page-head"><div><span class="eyebrow">Checkout</span><h1>Checkout</h1></div></div>
${emptyState('Nothing to check out', 'Your cart is empty.', '/products', 'Shop the catalog')}`;
  }
  const rows = cart.lines
    .map(
      (line) =>
        `<tr><td>${esc(line.name)} <span class="row-sub">x ${line.qty}</span></td><td class="num">${price(line.lineTotal)}</td></tr>`,
    )
    .join('');
  const canPay = wallet.balance.amount >= cart.total.amount;
  const errorBlock =
    error !== undefined ? `<div class="flash flash-error" role="alert">${esc(error)}</div>` : '';
  return `
<div class="page-head"><div><span class="eyebrow">Checkout</span><h1>Checkout</h1></div></div>
${errorBlock}
<div class="cart-layout">
  <form method="post" action="/checkout">
    ${csrfField(ctx.session?.csrfToken)}
    <div class="section">
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
    <div class="section">
      <div class="section-head"><h3>Payment</h3></div>
      <dl class="dl">
        <dt>Method</dt><dd>Simulated wallet</dd>
        <dt>Wallet balance</dt><dd>${esc(formatMoney(wallet.balance))} ${esc(wallet.currency)}</dd>
        <dt>Order total</dt><dd>${price(cart.total)}</dd>
      </dl>
      ${
        canPay
          ? '<button class="button" type="submit">Place order and pay</button>'
          : `<p class="flash flash-error">Insufficient wallet balance for this order. <a href="/account/wallet">Top up the simulated wallet</a> or remove items.</p>
             <button class="button" type="submit" disabled>Place order and pay</button>`
      }
      <p class="consent-note">Paying debits your wallet balance immediately. The wallet is simulated: no real funds move.</p>
    </div>
  </form>
  <aside class="panel">
    <div class="section-head"><h3>Order summary</h3></div>
    <table class="table"><tbody>${rows}</tbody>
    <tfoot><tr><td class="total-row">Total</td><td class="num total-row">${price(cart.total)}</td></tr></tfoot></table>
  </aside>
</div>`;
}
