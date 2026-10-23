import type { Product } from '../../domain/catalog.ts';
import { esc } from '../html.ts';
import { price, productMark } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function renderHome(ctx: RenderCtx, featured: Product[]): string {
  const cards = featured
    .map(
      (p) => `<li>
        <a class="product-card" href="/products/${esc(p.sku)}">
          ${productMark(p.sku, p.name)}
          <div class="product-card-body">
            <p class="product-card-name">${esc(p.name)}</p>
            <p class="product-card-meta">${esc(p.category)}</p>
            ${price(p.price)}
          </div>
        </a>
      </li>`,
    )
    .join('');
  const greeting =
    ctx.user !== undefined ? `<p class="lede">Welcome back, ${esc(ctx.user.name)}.</p>` : '';
  return `
<div class="page-head">
  <div>
    <span class="eyebrow">The example storefront</span>
    <h1>Goods for a considered desk</h1>
    <p class="lede">ExampleShop is the reference storefront for TrailGate: a small catalog, a simulated wallet, and real delegated-authority enforcement for agents.</p>
    ${greeting}
  </div>
  <a class="button" href="/products">Browse the catalog</a>
</div>
<section class="section">
  <div class="section-head"><h2>Featured</h2><a href="/products">All products</a></div>
  <ul class="product-grid">${cards}</ul>
</section>
<section class="section">
  <div class="panel">
    <h3>Shopping with an agent</h3>
    <p class="muted">An AI agent can shop here with your explicit approval: you grant it scoped permissions, resource access, and spending limits; the shop enforces them on every request. Connect an agent from your account, or read the <a href="/.well-known/trailgate">discovery document</a>.</p>
    ${ctx.user === undefined ? '<p class="faint">Sign in to approve agent access to your cart, orders, and wallet.</p>' : '<p><a href="/account/connections">Manage agent connections</a></p>'}
  </div>
</section>`;
}
