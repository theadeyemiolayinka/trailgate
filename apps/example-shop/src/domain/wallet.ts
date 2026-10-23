import type { Money } from '@trailgate/core';
import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';
import { SHOP_CURRENCY } from './money.ts';

/**
 * Simulated wallet. The balance is authoritative database state: every
 * change is an append-only entry in `wallet_entries` plus a balance update
 * in the same transaction, so the ledger and the cached balance can never
 * disagree after a commit. Debits refuse to run when headroom is absent
 * rather than going negative.
 */

export type WalletEntryKind = 'topup' | 'order_debit' | 'order_refund' | 'adjustment';

export interface Wallet {
  userId: string;
  currency: string;
  balance: Money;
  createdAt: number;
}

export interface WalletEntry {
  id: string;
  kind: WalletEntryKind;
  /** Signed minor units: credits positive, debits negative. */
  amount: Money;
  ref?: string;
  balanceAfter: number;
  createdAt: number;
}

export function walletIdFor(userId: string): string {
  return `wlt_${userId}`;
}

export function getWallet(db: Db, userId: string): Wallet {
  const row = db
    .prepare('SELECT user_id, currency, balance_minor, created_at FROM wallets WHERE user_id = ?')
    .get(userId) as
    | { user_id: string; currency: string; balance_minor: number; created_at: number }
    | undefined;
  if (row === undefined) {
    throw new WalletError('wallet is missing');
  }
  return {
    userId: row.user_id,
    currency: row.currency,
    balance: { amount: row.balance_minor, currency: row.currency },
    createdAt: row.created_at,
  };
}

export function listWalletEntries(db: Db, userId: string, limit = 100): WalletEntry[] {
  const rows = db
    .prepare(
      `SELECT id, kind, amount_minor, ref, balance_after, created_at
       FROM wallet_entries WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
    )
    .all(userId, limit) as {
    id: string;
    kind: WalletEntryKind;
    amount_minor: number;
    ref: string | null;
    balance_after: number;
    created_at: number;
  }[];
  return rows.map((row) => ({
    id: row.id,
    kind: row.kind,
    amount: { amount: row.amount_minor, currency: SHOP_CURRENCY },
    ...(row.ref !== null ? { ref: row.ref } : {}),
    balanceAfter: row.balance_after,
    createdAt: row.created_at,
  }));
}

/**
 * Runs `fn` inside a SAVEPOINT. SAVEPOINTs compose inside an outer
 * transaction (payOrder's) and behave as a standalone transaction
 * otherwise, so wallet writes are always atomic without nested BEGIN.
 */
function walletTx<T>(db: Db, fn: () => T): T {
  db.exec('SAVEPOINT wallet_op');
  try {
    const out = fn();
    db.exec('RELEASE wallet_op');
    return out;
  } catch (err) {
    db.exec('ROLLBACK TO wallet_op');
    db.exec('RELEASE wallet_op');
    throw err;
  }
}

function postEntry(
  db: Db,
  userId: string,
  kind: WalletEntryKind,
  amountMinor: number,
  ref: string | undefined,
  now: number,
): WalletEntry {
  const balanceRow = db
    .prepare('SELECT balance_minor FROM wallets WHERE user_id = ?')
    .get(userId) as { balance_minor: number } | undefined;
  if (balanceRow === undefined) {
    throw new WalletError('wallet is missing');
  }
  const balanceAfter = balanceRow.balance_minor + amountMinor;
  const id = newId('wev');
  db.prepare(
    `INSERT INTO wallet_entries (id, user_id, kind, amount_minor, ref, balance_after, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, userId, kind, amountMinor, ref ?? null, balanceAfter, now);
  db.prepare('UPDATE wallets SET balance_minor = ? WHERE user_id = ?').run(balanceAfter, userId);
  return {
    id,
    kind,
    amount: { amount: amountMinor, currency: SHOP_CURRENCY },
    ...(ref !== undefined ? { ref } : {}),
    balanceAfter,
    createdAt: now,
  };
}

/**
 * Adds funds to the wallet. This is the simulated top-up: ExampleShop has
 * no payment processor, so crediting the wallet is a development affordance
 * and is labeled as such in the UI.
 */
export function topUp(
  db: Db,
  userId: string,
  amount: Money,
  now = Math.floor(Date.now() / 1000),
): WalletEntry {
  if (amount.currency !== SHOP_CURRENCY || amount.amount <= 0) {
    throw new WalletError('top-up amount must be positive minor units of the wallet currency');
  }
  if (amount.amount > 1_000_000) {
    throw new WalletError('top-up exceeds the simulated limit');
  }
  return walletTx(db, () => postEntry(db, userId, 'topup', amount.amount, undefined, now));
}

/**
 * Debits the wallet for an order. Atomic: the balance guard, the balance
 * update, and the ledger entry commit together. Throws
 * `InsufficientFundsError` when the wallet cannot cover `amount`.
 */
export function debitForOrder(
  db: Db,
  userId: string,
  amount: Money,
  orderId: string,
  now = Math.floor(Date.now() / 1000),
): WalletEntry {
  if (amount.currency !== SHOP_CURRENCY || amount.amount <= 0) {
    throw new WalletError('debit amount must be positive minor units of the wallet currency');
  }
  return walletTx(db, () => {
    const row = db.prepare('SELECT balance_minor FROM wallets WHERE user_id = ?').get(userId) as
      | { balance_minor: number }
      | undefined;
    if (row === undefined) {
      throw new WalletError('wallet is missing');
    }
    if (row.balance_minor < amount.amount) {
      throw new InsufficientFundsError(amount, {
        amount: row.balance_minor,
        currency: SHOP_CURRENCY,
      });
    }
    return postEntry(db, userId, 'order_debit', -amount.amount, orderId, now);
  });
}

/** Credits a refund for an order. */
export function refundForOrder(
  db: Db,
  userId: string,
  amount: Money,
  orderId: string,
  now = Math.floor(Date.now() / 1000),
): WalletEntry {
  if (amount.amount <= 0) {
    throw new WalletError('refund amount must be positive');
  }
  return walletTx(db, () => postEntry(db, userId, 'order_refund', amount.amount, orderId, now));
}

export class WalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WalletError';
  }
}

export class InsufficientFundsError extends WalletError {
  readonly requested: Money;
  readonly balance: Money;
  constructor(requested: Money, balance: Money) {
    super('insufficient wallet balance');
    this.name = 'InsufficientFundsError';
    this.requested = requested;
    this.balance = balance;
  }
}
