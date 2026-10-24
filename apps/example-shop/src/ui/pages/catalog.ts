import type { Product } from '../../domain/catalog.ts';
import { esc } from '../html.ts';
import { emptyState, pageHead, productCard } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

const SORTS: [string, string][] = [
  ['featured', 'Featured'],
  ['name', 'Name'],
  ['price_asc', 'Price: low to high'],
  ['price_desc', 'Price: high to low'],
];

export function renderCatalog(
  _ctx: RenderCtx,
  products: Product[],
  categories: string[],
  activeCategory: string | undefined,
  query: string | undefined,
  sort: string | undefined,
): string {
  const activeSort = sort === undefined ? 'featured' : sort;
  const nav = ['', ...categories]
    .map((category) => {
      const label = category === '' ? 'All' : category;
      const href =
        category === '' ? '/products' : `/products?category=${encodeURIComponent(category)}`;
      const current = (activeCategory ?? '') === category;
      return `<a href="${href}"${current ? ' aria-current="true"' : ''}>${esc(label)}</a>`;
    })
    .join('');
  const sortOptions = SORTS.map(
    ([key, label]) =>
      `<option value="${key}"${key === activeSort ? ' selected' : ''}>${esc(label)}</option>`,
  ).join('');
  const sortForm = `<form method="get" action="/products" class="sort-form">
    ${
      activeCategory !== undefined
        ? `<input type="hidden" name="category" value="${esc(activeCategory)}">`
        : ''
    }
    ${query !== undefined && query !== '' ? `<input type="hidden" name="q" value="${esc(query)}">` : ''}
    <label for="sort">Sort</label>
    <select id="sort" name="sort">${sortOptions}</select>
    <button class="button button-secondary button-small" type="submit">Apply</button>
  </form>`;
  const grid =
    products.length === 0
      ? emptyState(
          'Nothing here',
          query !== undefined && query !== ''
            ? `No products match "${esc(query)}".`
            : 'No products in this category yet.',
        )
      : `<ul class="product-grid">${products.map((p) => `<li>${productCard(p)}</li>`).join('')}</ul>`;
  const resultLine =
    query !== undefined && query !== ''
      ? `<p class="result-count">${products.length} result${products.length === 1 ? '' : 's'} for "${esc(query)}"</p>`
      : '';
  return `
${pageHead('Catalogue', activeCategory !== undefined ? activeCategory : 'All products')}
<div class="catalog-toolbar">
  <nav class="category-nav" aria-label="Categories">${nav}</nav>
  ${sortForm}
</div>
${resultLine}
${grid}`;
}
