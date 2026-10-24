import type { Product } from '../../domain/catalog.ts';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { esc } from '../html.ts';
import { csrfField, productCard, productFigure } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderProduct(ctx: RenderCtx, product: Product, related: Product[]): string {
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
            <div class="qty-field">
              <label for="qty">Quantity</label>
              <input id="qty" name="qty" type="number" min="1" max="${product.stock}" value="1">
            </div>
            <button class="button" type="submit">Add to cart</button>
          </form>`;
  const relatedSection =
    related.length === 0
      ? ''
      : `<section class="section">
          <div class="section-head"><h2>You may also like</h2><a href="/products?category=${encodeURIComponent(product.category)}">More ${esc(product.category)}</a></div>
          <ul class="product-grid">${related.map((p) => `<li>${productCard(p)}</li>`).join('')}</ul>
        </section>`;
  return `
<nav class="crumbs" aria-label="Breadcrumb">
  <a href="/">Home</a><span class="crumb-sep">/</span><a href="/products">Catalogue</a><span class="crumb-sep">/</span><a href="/products?category=${encodeURIComponent(product.category)}">${esc(product.category)}</a><span class="crumb-sep">/</span>${esc(product.name)}
</nav>
<div class="product-detail">
  <div class="product-media">${productFigure(product, { loading: 'eager' })}</div>
  <div class="product-info">
    <p class="product-card-category">${esc(product.category)}</p>
    <h1>${esc(product.name)}</h1>
    <p class="price">${esc(formatMoneyWithCurrency(product.price))}</p>
    <p class="product-desc">${esc(product.description)}</p>
    ${stockNote}
    ${addForm}
    <hr class="rule">
    <p class="detail-text">${esc(product.detail)}</p>
    <ul class="spec-list">
      <li><span>SKU</span><span class="mono-id">${esc(product.sku)}</span></li>
      <li><span>Category</span><span>${esc(product.category)}</span></li>
    </ul>
  </div>
</div>
${relatedSection}`;
}
