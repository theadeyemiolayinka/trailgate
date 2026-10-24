import type { Money } from '@trailgate/core';
import type { Product } from '../domain/catalog.ts';
import { formatMoneyWithCurrency } from '../domain/money.ts';
import type { User } from '../domain/users.ts';
import { esc } from './html.ts';

export interface PageOptions {
  title: string;
  user?: User;
  /** Item count for the cart link badge. */
  cartCount?: number;
  /** Current nav section, for example 'products' or 'account'. */
  section?: string;
  flash?: { kind: 'info' | 'error' | 'ok'; text: string };
  body: string;
}

function icon(name: 'bag' | 'search' | 'user' | 'menu' | 'shield' | 'arrow'): string {
  const paths: Record<string, string> = {
    bag: '<path d="M6.5 8.5h11l1 11.5a1 1 0 0 1-1 1h-11a1 1 0 0 1-1-1l1-11.5Z"/><path d="M9 8.5V7a3 3 0 0 1 6 0v1.5"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 4.5 4.5"/>',
    user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c.8-3.4 3.6-5 7-5s6.2 1.6 7 5"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    shield:
      '<path d="M12 3 5 5.6v5.2c0 4.5 3 7.6 7 9.2 4-1.6 7-4.7 7-9.2V5.6L12 3Z"/><path d="m9 11.8 2.1 2.1 3.9-4"/>',
    arrow: '<path d="M4 12h15m0 0-5.5-5.5M19 12l-5.5 5.5"/>',
  };
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths[name]}</svg>`;
}

function navLink(href: string, label: string, section: string | undefined, key: string): string {
  const current = section === key ? ' aria-current="page"' : '';
  return `<a href="${href}"${current}>${esc(label)}</a>`;
}

function searchForm(query = '', extraClass = ''): string {
  return `<form class="site-search ${extraClass}" role="search" action="/products" method="get">
  <label class="visually-hidden" for="site-search-input">Search the catalogue</label>
  ${icon('search')}
  <input id="site-search-input" type="search" name="q" value="${esc(query)}" placeholder="Search the catalogue" autocomplete="off">
</form>`;
}

export function page(options: PageOptions): string {
  const user = options.user;
  const cartCount = options.cartCount ?? 0;
  const flash =
    options.flash !== undefined
      ? `<div class="flash flash-${options.flash.kind}" role="status">${esc(options.flash.text)}</div>`
      : '';
  const accountLinks =
    user === undefined
      ? `<a class="header-link" href="/login"${options.section === 'login' ? ' aria-current="page"' : ''}>${icon('user')}<span class="header-link-label">Sign in</span></a>`
      : `<a class="header-link" href="/account"${options.section === 'account' ? ' aria-current="page"' : ''}>${icon('user')}<span class="header-link-label">Account</span></a>`;
  const cartBadge =
    cartCount > 0
      ? `<span class="cart-count" aria-label="${cartCount} items">${cartCount}</span>`
      : '';
  const cartLabel = cartCount === 1 ? '1 item in cart' : `${cartCount} items in cart`;
  const mobileAccountLinks =
    user === undefined
      ? `${navLink('/login', 'Sign in', options.section, 'login')}${navLink('/register', 'Create account', options.section, 'register')}`
      : `${navLink('/account', 'Account', options.section, 'account')}${navLink('/orders', 'Orders', options.section, 'orders')}${navLink('/account/wallet', 'Wallet', options.section, 'wallet')}${navLink('/account/connections', 'Connections', options.section, 'connections')}
         <form method="post" action="/logout"><button class="mobile-signout" type="submit">Sign out</button></form>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(options.title)} · ExampleShop</title>
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<div class="site-announce">Free shipping on all orders</div>
<header class="site-header">
  <div class="site-header-inner">
    <a class="brand" href="/" aria-label="ExampleShop home">
      <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="5" fill="var(--accent)"/><text x="16" y="22" text-anchor="middle" font-family="Iowan Old Style, Palatino, Georgia, serif" font-size="17" fill="#f7f4ec">E</text></svg>
      <span class="brand-name">ExampleShop</span>
    </a>
    <nav class="site-nav" aria-label="Primary">
      ${navLink('/products', 'Catalogue', options.section, 'products')}
      ${user !== undefined ? navLink('/orders', 'Orders', options.section, 'orders') : ''}
    </nav>
    <div class="site-header-spacer"></div>
    ${searchForm()}
    ${accountLinks}
    <a class="header-link" href="/cart"${options.section === 'cart' ? ' aria-current="page"' : ''} aria-label="Cart, ${cartLabel}">
      ${icon('bag')}<span class="header-link-label">Cart</span>${cartBadge}
    </a>
    <details class="mobile-menu">
      <summary aria-label="Open menu">${icon('menu')}</summary>
      <div class="mobile-menu-panel">
        ${searchForm()}
        <nav aria-label="Mobile">
          ${navLink('/products', 'Catalogue', options.section, 'products')}
          ${mobileAccountLinks}
        </nav>
      </div>
    </details>
  </div>
</header>
<main class="page" id="main">
  ${flash}
  ${options.body}
</main>
<footer class="site-footer">
  <div class="site-footer-inner">
    <div class="footer-grid">
      <section class="footer-col footer-about">
        <a class="brand brand-footer" href="/"><svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="5" fill="var(--accent)"/><text x="16" y="22" text-anchor="middle" font-family="Iowan Old Style, Palatino, Georgia, serif" font-size="17" fill="#f7f4ec">E</text></svg><span class="brand-name">ExampleShop</span></a>
        <p>Considered goods for the desk and the home.</p>
      </section>
      <nav class="footer-col" aria-label="Shop">
        <h2>Shop</h2>
        <a href="/products">All products</a>
        <a href="/products?category=Desk">Desk</a>
        <a href="/products?category=Drinkware">Drinkware</a>
        <a href="/products?category=Stationery">Stationery</a>
        <a href="/products?category=Kitchen">Kitchen</a>
        <a href="/products?category=Home">Home</a>
      </nav>
      <nav class="footer-col" aria-label="Account">
        <h2>Your account</h2>
        <a href="/account">Account overview</a>
        <a href="/orders">Order history</a>
        <a href="/account/wallet">Wallet</a>
        <a href="/account/connections">Agent connections</a>
        <a href="/account/activity">Authorization activity</a>
      </nav>
    </div>
    <div class="footer-base">
      <p>ExampleShop is a demo storefront for the <a href="/.well-known/trailgate">TrailGate</a> delegated-authorization protocol. Wallet funds are simulated.</p>
    </div>
  </div>
</footer>
</body>
</html>`;
}

/** Eyebrow + title + lede used at the top of interior pages. */
export function pageHead(eyebrow: string, title: string, lede?: string): string {
  return `<header class="page-head">
  <div>
    <p class="eyebrow">${esc(eyebrow)}</p>
    <h1>${esc(title)}</h1>
    ${lede === undefined ? '' : `<p class="lede">${esc(lede)}</p>`}
  </div>
</header>`;
}

/** Price in small-caps style with the currency code. */
export function price(value: Money): string {
  return `<span class="price">${esc(formatMoneyWithCurrency(value))}</span>`;
}

export function statusBadge(status: string): string {
  const map: Record<string, string> = {
    awaiting_payment: 'Awaiting payment',
    paid: 'Paid',
    refunded: 'Refunded',
    cancelled: 'Cancelled',
    pending: 'Pending',
    approved: 'Approved',
    denied: 'Denied',
    expired: 'Expired',
    issued: 'Issued',
    active: 'Active',
    revoked: 'Revoked',
    allow: 'Allowed',
    deny: 'Denied',
  };
  const tone =
    status === 'paid' || status === 'active' || status === 'approved' || status === 'allow'
      ? 'ok'
      : status === 'awaiting_payment' || status === 'pending' || status === 'issued'
        ? 'warn'
        : status === 'denied' || status === 'deny' || status === 'revoked'
          ? 'bad'
          : 'muted';
  return `<span class="badge badge-${tone}">${esc(map[status] ?? status)}</span>`;
}

export function emptyState(
  title: string,
  detail: string,
  ctaHref?: string,
  ctaLabel?: string,
): string {
  const cta =
    ctaHref !== undefined && ctaLabel !== undefined
      ? `<p class="empty-cta"><a class="button" href="${ctaHref}">${esc(ctaLabel)}</a></p>`
      : '';
  return `<section class="empty-state">
  <h2>${esc(title)}</h2>
  <p>${esc(detail)}</p>
  ${cta}
</section>`;
}

/** Local product photography, keyed by the seeded SKU. */
const PRODUCT_IMAGES: Record<string, string> = {
  'drk-mug-01': '/static/products/drk-mug-01.jpg',
  'drk-carafe-02': '/static/products/drk-carafe-02.jpg',
  'dsk-tray-01': '/static/products/dsk-tray-01.jpg',
  'dsk-mat-02': '/static/products/dsk-mat-02.jpg',
  'dsk-lamp-03': '/static/products/dsk-lamp-03.jpg',
  'stn-book-01': '/static/products/stn-book-01.jpg',
  'stn-pen-02': '/static/products/stn-pen-02.jpg',
  'stn-cards-03': '/static/products/stn-cards-03.jpg',
  'kit-pour-01': '/static/products/kit-pour-01.jpg',
  'kit-board-02': '/static/products/kit-board-02.jpg',
  'hm-throw-01': '/static/products/hm-throw-01.jpg',
  'hm-candle-02': '/static/products/hm-candle-02.jpg',
};

export function productImageUrl(product: Product): string | undefined {
  return PRODUCT_IMAGES[product.sku];
}

export function productImageForSku(sku: string): string | undefined {
  return PRODUCT_IMAGES[sku];
}

/** Small 4:5 product thumbnail for line items; falls back to the SVG mark. */
export function productThumb(sku: string, name: string): string {
  const url = PRODUCT_IMAGES[sku];
  return url === undefined
    ? productMark(sku, name)
    : `<img src="${esc(url)}" alt="" loading="lazy" decoding="async">`;
}

/**
 * Product photograph when a local asset exists, otherwise the deterministic
 * SVG mark. Consistent 4:5 crop everywhere via CSS object-fit.
 */
export function productFigure(
  product: Product,
  options: { loading?: 'lazy' | 'eager'; className?: string } = {},
): string {
  const url = productImageUrl(product);
  if (url === undefined) {
    return productMark(product.sku, product.name);
  }
  return `<img src="${esc(url)}" alt="${esc(product.name)}" loading="${options.loading ?? 'lazy'}" decoding="async" class="product-photo ${esc(options.className ?? '')}">`;
}

/** Storefront product card: image, category, name, price, stock cue. */
export function productCard(
  product: Product,
  options: { loading?: 'lazy' | 'eager' } = {},
): string {
  const stock =
    product.stock === 0
      ? '<span class="stock-note stock-out">Out of stock</span>'
      : product.stock <= 5
        ? `<span class="stock-note stock-low">Only ${product.stock} left</span>`
        : '';
  return `<article class="product-card">
  <a class="product-card-media" href="/products/${esc(product.sku)}">${productFigure(product, options)}</a>
  <div class="product-card-body">
    <p class="product-card-category">${esc(product.category)}</p>
    <h3 class="product-card-name"><a href="/products/${esc(product.sku)}">${esc(product.name)}</a></h3>
    <div class="product-card-foot">
      ${price(product.price)}
      ${stock}
    </div>
  </div>
</article>`;
}

/**
 * Deterministic product mark: a restrained geometric stamp derived from the
 * SKU. Fallback for products without a local photograph.
 */
export function productMark(sku: string, name: string): string {
  let hash = 0;
  for (const ch of sku) {
    hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  }
  const palette = ['#e7e0d3', '#dfe4dc', '#e3d7d7', '#d9dfe6', '#e6ddc8', '#dcd8e4'];
  const bg = palette[Math.abs(hash) % palette.length];
  const fg = '#3d3a34';
  const variant = Math.abs(hash >> 3) % 4;
  const initial = esc(name.slice(0, 1).toUpperCase());
  const shapes = [
    `<circle cx="60" cy="54" r="30" fill="none" stroke="${fg}" stroke-width="2.5"/>
     <line x1="20" y1="108" x2="100" y2="108" stroke="${fg}" stroke-width="2.5"/>`,
    `<rect x="34" y="30" width="52" height="52" fill="none" stroke="${fg}" stroke-width="2.5" transform="rotate(45 60 56)"/>
     <line x1="20" y1="108" x2="100" y2="108" stroke="${fg}" stroke-width="2.5"/>`,
    `<path d="M 30 84 A 30 30 0 0 1 90 84" fill="none" stroke="${fg}" stroke-width="2.5"/>
     <line x1="60" y1="24" x2="60" y2="84" stroke="${fg}" stroke-width="2.5"/>
     <line x1="20" y1="108" x2="100" y2="108" stroke="${fg}" stroke-width="2.5"/>`,
    `<circle cx="60" cy="54" r="30" fill="none" stroke="${fg}" stroke-width="2.5"/>
     <circle cx="60" cy="54" r="12" fill="${fg}"/>
     <line x1="20" y1="108" x2="100" y2="108" stroke="${fg}" stroke-width="2.5"/>`,
  ];
  return `<svg viewBox="0 0 120 130" role="img" aria-label="${esc(name)}" class="product-mark" preserveAspectRatio="xMidYMid slice">
  <rect width="120" height="130" fill="${bg}"/>
  ${shapes[variant]}
  <text x="60" y="121" text-anchor="middle" font-family="Georgia, serif" font-size="10" fill="${fg}" letter-spacing="1">${initial}</text>
</svg>`;
}

export function csrfField(token: string | undefined): string {
  return token === undefined ? '' : `<input type="hidden" name="_csrf" value="${esc(token)}">`;
}
