import type { Money } from '@trailgate/core';
import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';
import { clearCart, getCart } from './cart.ts';
import { decrementStock, restoreStock } from './catalog.ts';
import { SHOP_CURRENCY } from './money.ts';
import type { Address } from './users.ts';
import { getAddress } from './users.ts';
import { debitForOrder, refundForOrder } from './wallet.ts';

export type OrderStatus = 'awaiting_payment' | 'paid' | 'refunded' | 'cancelled';
export type PlacedVia = 'user' | 'agent';

export interface OrderLine {
  sku: string;
  name: string;
  qty: number;
  unitPrice: Money;
  lineTotal: Money;
}

export interface Order {
  id: string;
  userId: string;
  status: OrderStatus;
  total: Money;
  addressId?: string;
  placedVia: PlacedVia;
  grantJti?: string;
  createdAt: number;
  paidAt?: number;
  refundedAt?: number;
}

interface OrderRow {
  id: string;
  user_id: string;
  status: OrderStatus;
  total_minor: number;
  currency: string;
  address_id: string | null;
  placed_via: PlacedVia;
  grant_jti: string | null;
  created_at: number;
  paid_at: number | null;
  refunded_at: number | null;
}

function toOrder(row: OrderRow): Order {
  return {
    id: row.id,
    userId: row.user_id,
    status: row.status,
    total: { amount: row.total_minor, currency: row.currency },
    ...(row.address_id !== null ? { addressId: row.address_id } : {}),
    placedVia: row.placed_via,
    ...(row.grant_jti !== null ? { grantJti: row.grant_jti } : {}),
    createdAt: row.created_at,
    ...(row.paid_at !== null ? { paidAt: row.paid_at } : {}),
    ...(row.refunded_at !== null ? { refundedAt: row.refunded_at } : {}),
  };
}

export class OrderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OrderError';
  }
}

/**
 * Snapshots the user's cart into a pending order and empties the cart.
 * Stock is reserved immediately (decremented) and restored if the order is
 * cancelled or refunded before fulfillment, which this demo treats as the
 * end of the lifecycle.
 */
export function createOrderFromCart(
  db: Db,
  userId: string,
  options: { addressId?: string; placedVia: PlacedVia; grantJti?: string },
  now = Math.floor(Date.now() / 1000),
): Order {
  const cart = getCart(db, userId);
  if (cart.lines.length === 0) {
    throw new OrderError('the cart is empty');
  }
  if (options.addressId !== undefined && getAddress(db, options.addressId, userId) === undefined) {
    throw new OrderError('unknown shipping address');
  }
  const orderId = newId('ord');
  db.exec('BEGIN');
  try {
    for (const line of cart.lines) {
      decrementStock(db, line.sku, line.qty);
    }
    db.prepare(
      `INSERT INTO orders (id, user_id, status, total_minor, currency, address_id, placed_via, grant_jti, created_at)
       VALUES (?, ?, 'awaiting_payment', ?, ?, ?, ?, ?, ?)`,
    ).run(
      orderId,
      userId,
      cart.total.amount,
      cart.total.currency,
      options.addressId ?? null,
      options.placedVia,
      options.grantJti ?? null,
      now,
    );
    for (const line of cart.lines) {
      db.prepare(
        `INSERT INTO order_items (order_id, sku, name, qty, unit_price_minor) VALUES (?, ?, ?, ?, ?)`,
      ).run(orderId, line.sku, line.name, line.qty, line.unitPrice.amount);
    }
    clearCart(db, userId);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return getOrder(db, orderId, userId) as Order;
}

/**
 * Pays an awaiting order from the wallet: balance guard, ledger entry,
 * status transition in one transaction. Throws OrderError when the order is
 * not payable; the caller maps InsufficientFundsError to a denial.
 */
export function payOrder(
  db: Db,
  orderId: string,
  userId: string,
  now = Math.floor(Date.now() / 1000),
): Order {
  const order = getOrder(db, orderId, userId);
  if (order === undefined) {
    throw new OrderError('unknown order');
  }
  if (order.status !== 'awaiting_payment') {
    throw new OrderError(`order is not payable (status ${order.status})`);
  }
  db.exec('BEGIN');
  try {
    debitForOrder(db, userId, order.total, orderId, now);
    db.prepare("UPDATE orders SET status = 'paid', paid_at = ? WHERE id = ?").run(now, orderId);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return getOrder(db, orderId, userId) as Order;
}

/**
 * Refunds a paid order: wallet credit and status transition in one
 * transaction, plus stock restoration. Returns the refund amount so callers
 * can post the offsetting grant-ledger entry (spec section 12).
 */
export function refundOrder(
  db: Db,
  orderId: string,
  userId: string,
  now = Math.floor(Date.now() / 1000),
): { order: Order; refund: Money } {
  const order = getOrder(db, orderId, userId);
  if (order === undefined) {
    throw new OrderError('unknown order');
  }
  if (order.status !== 'paid') {
    throw new OrderError(`order is not refundable (status ${order.status})`);
  }
  db.exec('BEGIN');
  try {
    refundForOrder(db, userId, order.total, orderId, now);
    db.prepare("UPDATE orders SET status = 'refunded', refunded_at = ? WHERE id = ?").run(
      now,
      orderId,
    );
    for (const line of listOrderItems(db, orderId)) {
      restoreStock(db, line.sku, line.qty);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { order: getOrder(db, orderId, userId) as Order, refund: order.total };
}

/** Cancels an unpaid order and restores stock. */
export function cancelOrder(db: Db, orderId: string, userId: string): Order {
  const order = getOrder(db, orderId, userId);
  if (order === undefined) {
    throw new OrderError('unknown order');
  }
  if (order.status !== 'awaiting_payment') {
    throw new OrderError(`order cannot be cancelled (status ${order.status})`);
  }
  db.exec('BEGIN');
  try {
    db.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ?").run(orderId);
    for (const line of listOrderItems(db, orderId)) {
      restoreStock(db, line.sku, line.qty);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return getOrder(db, orderId, userId) as Order;
}

export function getOrder(db: Db, id: string, userId?: string): Order | undefined {
  const row = (
    userId === undefined
      ? db.prepare('SELECT * FROM orders WHERE id = ?').get(id)
      : db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(id, userId)
  ) as OrderRow | undefined;
  return row === undefined ? undefined : toOrder(row);
}

export function listOrders(db: Db, userId: string): Order[] {
  return (
    db
      .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC')
      .all(userId) as unknown as OrderRow[]
  ).map(toOrder);
}

export function listOrderItems(db: Db, orderId: string): OrderLine[] {
  const rows = db
    .prepare(
      `SELECT sku, name, qty, unit_price_minor FROM order_items WHERE order_id = ? ORDER BY name`,
    )
    .all(orderId) as { sku: string; name: string; qty: number; unit_price_minor: number }[];
  return rows.map((row) => ({
    sku: row.sku,
    name: row.name,
    qty: row.qty,
    unitPrice: { amount: row.unit_price_minor, currency: SHOP_CURRENCY },
    lineTotal: { amount: row.unit_price_minor * row.qty, currency: SHOP_CURRENCY },
  }));
}

export interface Invoice {
  order: Order;
  lines: OrderLine[];
  address?: Address;
  userName: string;
  userEmail: string;
}

export function getInvoice(db: Db, orderId: string, userId: string): Invoice | undefined {
  const order = getOrder(db, orderId, userId);
  if (order === undefined) {
    return undefined;
  }
  const user = db.prepare('SELECT name, email FROM users WHERE id = ?').get(userId) as
    | { name: string; email: string }
    | undefined;
  const address =
    order.addressId !== undefined ? getAddress(db, order.addressId, userId) : undefined;
  return {
    order,
    lines: listOrderItems(db, orderId),
    ...(address !== undefined ? { address } : {}),
    userName: user?.name ?? '',
    userEmail: user?.email ?? '',
  };
}
