/**
 * ExampleShop's TrailGate vocabulary. These are site-level choices: the
 * spec defines formats and semantics, the site defines the concrete
 * permission identifiers and resource selector types it advertises
 * (docs/handoff.md, D3 section).
 */

export const PERMISSIONS = [
  'tg.catalog.read',
  'tg.cart.read',
  'tg.cart.write',
  'tg.order.create',
  'tg.order.read',
  'tg.wallet.read',
  'tg.wallet.charge',
] as const;

/** Resource selector types this site accepts inside a grant scope. */
export const RESOURCE_TYPES = ['cart', 'order', 'wallet'] as const;

export function cartSelector(userId: string): string {
  return `cart:cart_${userId}`;
}

export function walletSelector(userId: string): string {
  return `wallet:wlt_${userId}`;
}

export function orderSelector(orderId: string): string {
  return `order:${orderId}`;
}

const SELECTOR_RE = /^(cart|order|wallet):[A-Za-z0-9_-]+$/;

export function isShopSelector(selector: string): boolean {
  return SELECTOR_RE.test(selector);
}
