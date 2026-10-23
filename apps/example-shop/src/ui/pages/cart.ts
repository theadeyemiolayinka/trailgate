import type { Cart } from '../../domain/cart.ts';
import { esc } from '../html.ts';
import { csrfField, emptyState, price } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderCart(ctx: RenderCtx, cart: Cart): string {
  if (cart.lines.length === 0) {
    return `
<div class="page-head"><div><span class="eyebrow">Cart</span><h1>Your cart</h1></div></div>
${emptyState('Your cart is empty', 'Browse the catalog to find something worth keeping.', '/products', 'Shop the catalog')}`;
  }
  const rows = cart.lines
    .map(
      (line) => `<tr>
        <td>
          <a href="/products/${esc(line.sku)}">${esc(line.name)}</a>
          <div class="row-sub">${esc(line.sku)}${line.qty > line.stock ? ` · only ${line.stock} in stock` : ''}</div>
        </td>
        <td class="num">${price(line.unitPrice)}</td>
        <td class="num">
          <form method="post" action="/cart/update" class="qty-form">
            ${csrfField(ctx.session?.csrfToken)}
            <input type="hidden" name="sku" value="${esc(line.sku)}">
            <input name="qty" type="number" min="0" max="${line.stock}" value="${line.qty}" aria-label="Quantity for ${esc(line.name)}">
            <button class="button-secondary button-small button" type="submit">Set</button>
          </form>
        </td>
        <td class="num">${price(line.lineTotal)}</td>
        <td class="num">
          <form method="post" action="/cart/remove" class="inline-form">
            ${csrfField(ctx.session?.csrfToken)}
            <input type="hidden" name="sku" value="${esc(line.sku)}">
            <button class="link-button" type="submit">Remove</button>
          </form>
        </td>
      </tr>`,
    )
    .join('');
  return `
<div class="page-head"><div><span class="eyebrow">Cart</span><h1>Your cart</h1></div></div>
<div class="cart-layout">
  <table class="table">
    <thead><tr><th>Item</th><th class="num">Price</th><th class="num">Qty</th><th class="num">Total</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <aside class="panel">
    <div class="split"><span class="muted">Subtotal</span><span class="total-row">${price(cart.total)}</span></div>
    <p class="faint">Charged to your simulated wallet at checkout.</p>
    <p><a class="button" href="/checkout">Checkout</a></p>
  </aside>
</div>`;
}
