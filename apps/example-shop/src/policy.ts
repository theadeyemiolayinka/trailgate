import type { Money } from '@trailgate/core';
import type { ShopConfig } from './config.ts';

/**
 * Server-authoritative spending policy. Values come from ShopConfig; the
 * UI reads them from `tg.spendingPolicy` for display only - enforcement
 * happens server-side (refineScope at intake, charge-time cap).
 */
export interface ShopPolicy {
  /** Largest single wallet charge the shop executes for any caller. */
  maxCharge: Money;
  /** Largest cumulative_budget a grant may carry after refinement. */
  maxGrantBudget: Money;
  currency: string;
}

export function shopPolicy(config: ShopConfig): ShopPolicy {
  return {
    maxCharge: { amount: config.maxChargeMinor, currency: config.policyCurrency },
    maxGrantBudget: { amount: config.maxGrantBudgetMinor, currency: config.policyCurrency },
    currency: config.policyCurrency,
  };
}

export const SHOP_POLICY = shopPolicy;
