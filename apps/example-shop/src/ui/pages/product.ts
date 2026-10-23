import type { Product } from '../../domain/catalog.ts';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { esc } from '../html.ts';
import { csrfField, productMark } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderProduct(ctx: RenderCtx, product: Product): string {
  const stockNote =
    product.stock === 0
      ? '<p class="stock-note stock-out">Out of stock</p>'
      : product.stock <= 10
        ? `<p class="stock-note stock-low">Only ${product.stock} left</p>`
        : `<p class="stock-note">${product.stock} in stock</p>`;
  const addForm =
    ctx.user === undefined
      ? `<p class="faint"><a href="/login?next=${encodeURIComponent(`/products/${product.sku}`)}">Sign in</a> to add this to your cart.</p>`
      : product.stock === 0
        ? '<button class="button" disabled>Add to cart</button>'
        : `<form method="post" action="/cart/add" class="qty-form">
            ${csrfField(ctx.session?.csrfToken)}
            <input type="hidden" name="sku" value="${esc(product.sku)}">
            <label for="qty">Qty</label>
            <input id="qty" name="qty" type="number" min="1" max="${product.stock}" value="1">
            <button class="button" type="submit">Add to cart</button>
          </form>`;
  return `
<div class="page-head">
  <div>
    <span class="eyebrow"><a href="/products">Catalog</a> / ${esc(product.category)}</span>
    <h1>${esc(product.name)}</h1>
  </div>
</div>
<div class="product-detail">
  <div>${productMark(product.sku, product.name)}</div>
  <div>
    <p class="price">${esc(formatMoneyWithCurrency(product.price))}</p>
    <p>${esc(product.description)}</p>
    ${stockNote}
    ${addForm}
    <hr class="rule">
    <p class="detail-text">${esc(product.detail)}</p>
    <p class="faint mono-id">SKU ${esc(product.sku)}</p>
  </div>
</div>`;
}
