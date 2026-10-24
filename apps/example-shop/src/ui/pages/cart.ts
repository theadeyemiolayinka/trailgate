import type { Cart } from '../../domain/cart.ts';
import { esc } from '../html.ts';
import { csrfField, emptyState, pageHead, price, productThumb } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderCart(ctx: RenderCtx, cart: Cart): string {
  if (cart.lines.length === 0) {
    return `
${pageHead('Cart', 'Your cart')}
${emptyState('Your cart is empty', 'Browse the catalogue to find something worth keeping.', '/products', 'Shop the catalogue')}`;
  }
  const lines = cart.lines
    .map(
      (line) => `<div class="cart-line">
        <a class="cart-line-media" href="/products/${esc(line.sku)}">${productThumb(line.sku, line.name)}</a>
        <div class="cart-line-info">
          <span class="cart-line-name"><a href="/products/${esc(line.sku)}">${esc(line.name)}</a></span>
          <span class="cart-line-sku">${esc(line.sku)}</span>
          <span class="cart-line-unit">${price(line.unitPrice)} each${line.qty > line.stock ? ` · only ${line.stock} in stock` : ''}</span>
          <div class="cart-line-controls">
            <form method="post" action="/cart/update" class="qty-form">
              ${csrfField(ctx.session?.csrfToken)}
              <input type="hidden" name="sku" value="${esc(line.sku)}">
              <input name="qty" type="number" min="0" max="${line.stock}" value="${line.qty}" aria-label="Quantity for ${esc(line.name)}">
              <button class="button button-secondary button-small" type="submit">Update</button>
            </form>
            <form method="post" action="/cart/remove" class="inline-form">
              ${csrfField(ctx.session?.csrfToken)}
              <input type="hidden" name="sku" value="${esc(line.sku)}">
              <button class="link-button" type="submit">Remove</button>
            </form>
          </div>
        </div>
        <div class="cart-line-price">${price(line.lineTotal)}</div>
      </div>`,
    )
    .join('');
  return `
${pageHead('Cart', 'Your cart')}
<div class="cart-layout">
  <div class="cart-lines">${lines}</div>
  <aside class="summary-card">
    <h2>Order summary</h2>
    <div class="summary-line"><span class="muted">Subtotal</span>${price(cart.total)}</div>
    <div class="summary-line summary-total"><span>Total</span>${price(cart.total)}</div>
    <a class="button" href="/checkout">Proceed to checkout</a>
    <p class="summary-note">Charged to your simulated wallet at checkout.</p>
  </aside>
</div>`;
}
