import type { Product } from '../../domain/catalog.ts';
import { esc } from '../html.ts';
import { emptyState, price, productMark } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderCatalog(
  _ctx: RenderCtx,
  products: Product[],
  categories: string[],
  activeCategory: string | undefined,
  query?: string,
): string {
  const nav = ['', ...categories]
    .map((category) => {
      const label = category === '' ? 'All' : category;
      const href =
        category === '' ? '/products' : `/products?category=${encodeURIComponent(category)}`;
      const current = (activeCategory ?? '') === category;
      return `<a href="${href}"${current ? ' aria-current="true"' : ''}>${esc(label)}</a>`;
    })
    .join('');
  const searchForm = `<form method="get" action="/products" class="search-form" role="search">
    ${
      activeCategory !== undefined
        ? `<input type="hidden" name="category" value="${esc(activeCategory)}">`
        : ''
    }
    <input type="search" name="q" value="${esc(query ?? '')}" placeholder="Search the catalog" aria-label="Search products">
    <button class="button" type="submit">Search</button>
  </form>`;
  const grid =
    products.length === 0
      ? emptyState(
          'Nothing here',
          query !== undefined && query !== ''
            ? `No products match "${esc(query)}".`
            : 'No products in this category yet.',
        )
      : `<ul class="product-grid">${products
          .map(
            (p) => `<li>
              <a class="product-card" href="/products/${esc(p.sku)}">
                ${productMark(p.sku, p.name)}
                <div class="product-card-body">
                  <p class="product-card-name">${esc(p.name)}</p>
                  <p class="product-card-meta">${esc(p.category)}${p.stock === 0 ? ' · Out of stock' : ''}</p>
                  ${price(p.price)}
                </div>
              </a>
            </li>`,
          )
          .join('')}</ul>`;
  return `
<div class="page-head">
  <div>
    <span class="eyebrow">Catalog</span>
    <h1>All products</h1>
  </div>
</div>
<nav class="category-nav" aria-label="Categories">${nav}</nav>
${searchForm}
${query !== undefined && query !== '' ? `<p class="muted">${products.length} result${products.length === 1 ? '' : 's'} for "${esc(query)}"</p>` : ''}
${grid}`;
}
