import type { Money } from '@trailgate/core';
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

function navLink(href: string, label: string, section: string | undefined, key: string): string {
  const current = section === key ? ' aria-current="page"' : '';
  return `<a href="${href}"${current}>${esc(label)}</a>`;
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
      ? `${navLink('/login', 'Sign in', options.section, 'login')}
         <a class="button button-small" href="/register">Create account</a>`
      : `${navLink('/account', 'Account', options.section, 'account')}
         ${navLink('/account/wallet', 'Wallet', options.section, 'wallet')}
         <form method="post" action="/logout" class="inline-form"><button class="link-button" type="submit">Sign out</button></form>`;
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
<header class="site-header">
  <div class="site-header-inner">
    <a class="brand" href="/">
      <span class="brand-mark" aria-hidden="true">E</span>
      <span class="brand-name">Example<span class="brand-accent">Shop</span></span>
    </a>
    <nav class="site-nav" aria-label="Primary">
      ${navLink('/products', 'Catalog', options.section, 'products')}
      ${navLink('/orders', 'Orders', options.section, 'orders')}
      <a href="/cart"${options.section === 'cart' ? ' aria-current="page"' : ''}>Cart${cartCount > 0 ? ` <span class="cart-count">${cartCount}</span>` : ''}</a>
      ${accountLinks}
    </nav>
  </div>
</header>
<main class="page">
  ${flash}
  ${options.body}
</main>
<footer class="site-footer">
  <div class="site-footer-inner">
    <p>ExampleShop is a reference storefront for the TrailGate delegation protocol. Prices and balances are simulated; the enforcement and accounting are real.</p>
    <p class="footer-meta"><a href="/.well-known/trailgate">Discovery document</a> · <a href="/account/connections">Agent connections</a></p>
  </div>
</footer>
</body>
</html>`;
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
  };
  const tone =
    status === 'paid' || status === 'active' || status === 'approved'
      ? 'ok'
      : status === 'awaiting_payment' || status === 'pending' || status === 'issued'
        ? 'warn'
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
      ? `<p><a class="button" href="${ctaHref}">${esc(ctaLabel)}</a></p>`
      : '';
  return `<section class="empty-state">
  <h2>${esc(title)}</h2>
  <p>${esc(detail)}</p>
  ${cta}
</section>`;
}

/**
 * Deterministic product mark: a restrained geometric stamp derived from the
 * SKU. It stands in for photography so the demo needs no image assets; it
 * is decoration, not recorded activity.
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
