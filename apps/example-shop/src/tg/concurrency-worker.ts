import { openDatabase } from '../db/database.ts';
import { createSpendingLedger } from './stores.ts';

/**
 * Worker for the cross-process overspend test. Each spawned process opens
 * the same SQLite file and tries to reserve `amount` minor units under the
 * shared grant and budget. Prints one JSON result line for the parent.
 */
const [dbPath, grantId, amountArg, budgetArg] = process.argv.slice(2);
if (dbPath === undefined || grantId === undefined || amountArg === undefined) {
  console.error('usage: concurrency-worker <db> <grant> <amount> [budget]');
  process.exit(2);
}
const amount = Number.parseInt(amountArg, 10);
const budget = Number.parseInt(budgetArg ?? '0', 10);
const db = openDatabase(dbPath);
const ledger = createSpendingLedger(db, () => Math.floor(Date.now() / 1000));
const now = Math.floor(Date.now() / 1000);
try {
  const r = await ledger.reserve({
    reservationId: `rsv_${process.pid}`,
    grantId,
    amount: { amount, currency: 'USD' },
    budgets: budget > 0 ? [{ amount: budget, currency: 'USD' }] : [],
    spendWindows: [],
    now,
    ttlSeconds: 300,
  });
  console.log(JSON.stringify({ state: r.state }));
} catch (err) {
  const code = (err as { code?: string }).code ?? 'error';
  console.log(JSON.stringify({ state: 'denied', code }));
}
