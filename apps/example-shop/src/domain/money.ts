import type { Money } from '@trailgate/core';

/** The shop's only supported currency in this reference implementation. */
export const SHOP_CURRENCY = 'USD';

export function money(amount: number, currency = SHOP_CURRENCY): Money {
  if (!Number.isInteger(amount) || amount < 0) {
    throw new RangeError('money amount must be a non-negative integer of minor units');
  }
  if (!/^[A-Z]{3}$/.test(currency)) {
    throw new RangeError('currency must be an ISO 4217 alpha code');
  }
  return { amount, currency };
}

/** Renders minor units as a display string, for example 1299 -> "12.99". */
export function formatMoney(value: Money): string {
  const sign = value.amount < 0 ? '-' : '';
  const abs = Math.abs(value.amount);
  const major = Math.floor(abs / 100);
  const minor = String(abs % 100).padStart(2, '0');
  return `${sign}${major}.${minor}`;
}

/** Renders with the currency code, for example "USD 12.99". */
export function formatMoneyWithCurrency(value: Money): string {
  return `${value.currency} ${formatMoney(value)}`;
}
