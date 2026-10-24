import type { Product } from '../../domain/catalog.ts';
import { esc } from '../html.ts';
import { productCard } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

const CATEGORY_IMAGES: Record<string, string> = {
  Drinkware: '/static/products/drk-carafe-02.jpg',
  Desk: '/static/products/dsk-mat-02.jpg',
  Stationery: '/static/products/stn-book-01.jpg',
  Kitchen: '/static/products/kit-pour-01.jpg',
  Home: '/static/products/hm-throw-01.jpg',
};

function categoryTile(category: string, count: number): string {
  const img = CATEGORY_IMAGES[category];
  const media =
    img === undefined ? '' : `<img src="${esc(img)}" alt="" loading="lazy" decoding="async">`;
  return `<a class="cat-tile" href="/products?category=${encodeURIComponent(category)}">
  <span class="cat-tile-media">${media}</span>
  <span class="cat-tile-name">${esc(category)}</span>
  <span class="cat-tile-count">${count} ${count === 1 ? 'item' : 'items'}</span>
</a>`;
}

export function renderHome(ctx: RenderCtx, products: Product[]): string {
  const counts = new Map<string, number>();
  for (const p of products) {
    counts.set(p.category, (counts.get(p.category) ?? 0) + 1);
  }
  const categories = [...counts.keys()].sort();
  const featured = products.slice(0, 8);
  const greeting =
    ctx.user !== undefined
      ? `<p class="hero-kicker">Welcome back, ${esc(ctx.user.name)}</p>`
      : '<p class="hero-kicker">Desk, kitchen and home goods</p>';
  const agentCta =
    ctx.user === undefined
      ? '<a href="/login">Sign in to connect an agent</a>'
      : '<a href="/account/connections">Manage your agent connections</a>';
  return `
<section class="hero">
  <div class="hero-copy">
    ${greeting}
    <h1>Goods for a considered desk</h1>
    <p class="lede">Stoneware, paper, wood, and wool. A small catalogue of things made to be used daily.</p>
    <div class="cta-row">
      <a class="button" href="/products">Browse the catalogue</a>
    </div>
  </div>
  <div class="hero-media">
    <img src="/static/products/hero-desk.jpg" alt="A walnut desk arranged with a notebook, brass pen, and stoneware mug" loading="eager" decoding="async">
  </div>
</section>

<section class="section">
  <div class="section-head"><h2>Shop by category</h2><a href="/products">All products</a></div>
  <div class="cat-grid">${categories.map((c) => categoryTile(c, counts.get(c) ?? 0)).join('')}</div>
</section>

<section class="section">
  <div class="section-head"><h2>New this season</h2><a href="/products">All products</a></div>
  <ul class="product-grid">${featured.map((p) => `<li>${productCard(p)}</li>`).join('')}</ul>
</section>

<section class="section agent-section" id="agent-shopping">
  <div class="section-head"><h2>Shop with an agent</h2>${agentCta}</div>
  <div class="agent-grid">
    <div class="agent-step">
      <h3>You approve the scope</h3>
      <p>An agent can shop here, but only inside a grant you approve: named permissions, named resources, spending caps, and a fixed lifetime.</p>
    </div>
    <div class="agent-step">
      <h3>The shop enforces it</h3>
      <p>Every signed request is checked against the grant and this site's own policy before it touches your cart, orders, or wallet.</p>
    </div>
    <div class="agent-step">
      <h3>You keep the evidence</h3>
      <p>Signed receipts and an append-only audit log record what the agent tried and what was allowed. Revoking stops it at the next request.</p>
    </div>
  </div>
</section>`;
}
