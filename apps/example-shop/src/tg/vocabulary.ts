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
/**
 * Subject-template form accepted in grant requests (`cart:{user}`,
 * `wallet:{user}`, `order:{user}`): bound to the approving subject's own
 * resources at consent time via `bindSubjectResources`, so an agent can
 * ask for "the user's cart" without knowing the concrete selector.
 */
const TEMPLATE_RE = /^(cart|order|wallet):\{user\}$/;

export function isShopSelector(selector: string): boolean {
  return SELECTOR_RE.test(selector) || TEMPLATE_RE.test(selector);
}

/**
 * Consent-time binding for `{user}` templates (spec section 8). `cart` and
 * `wallet` expand to the subject's own resources; `order:{user}` cannot
 * map to one order and is dropped (consent may narrow, never widen).
 * Concrete selectors pass through unchanged.
 */
export function bindShopSelectors(resources: readonly string[], subject: string): string[] {
  return resources
    .map((selector) => {
      if (selector === 'cart:{user}') {
        return cartSelector(subject);
      }
      if (selector === 'wallet:{user}') {
        return walletSelector(subject);
      }
      if (selector === 'order:{user}') {
        return undefined;
      }
      return selector;
    })
    .filter((s): s is string => s !== undefined);
}
