import type { Money } from '@trailgate/core';
import type { Db } from '../db/database.ts';
import { getProduct, type Product } from './catalog.ts';
import { SHOP_CURRENCY } from './money.ts';

export interface CartLine {
  sku: string;
  name: string;
  qty: number;
  unitPrice: Money;
  lineTotal: Money;
  stock: number;
}

export interface Cart {
  id: string;
  userId: string;
  lines: CartLine[];
  total: Money;
  itemCount: number;
}

export function cartIdFor(userId: string): string {
  return `cart_${userId}`;
}

function loadCart(db: Db, userId: string): Cart {
  const cartId = cartIdFor(userId);
  const rows = db
    .prepare(
      `SELECT ci.sku, ci.qty, p.name, p.price_minor, p.currency, p.stock
       FROM cart_items ci JOIN products p ON p.sku = ci.sku
       WHERE ci.cart_id = ? ORDER BY p.name`,
    )
    .all(cartId) as {
    sku: string;
    qty: number;
    name: string;
    price_minor: number;
    currency: string;
    stock: number;
  }[];
  const lines = rows.map((row) => ({
    sku: row.sku,
    name: row.name,
    qty: row.qty,
    unitPrice: { amount: row.price_minor, currency: row.currency },
    lineTotal: { amount: row.price_minor * row.qty, currency: row.currency },
    stock: row.stock,
  }));
  const total = lines.reduce((sum, line) => sum + line.lineTotal.amount, 0);
  return {
    id: cartId,
    userId,
    lines,
    total: { amount: total, currency: SHOP_CURRENCY },
    itemCount: lines.reduce((sum, line) => sum + line.qty, 0),
  };
}

export function getCart(db: Db, userId: string): Cart {
  return loadCart(db, userId);
}

export function setCartQty(db: Db, userId: string, sku: string, qty: number): void {
  const cartId = cartIdFor(userId);
  if (!Number.isInteger(qty) || qty < 0 || qty > 99) {
    throw new CartError('Quantity must be between 0 and 99.');
  }
  const product = getProduct(db, sku);
  if (product === undefined) {
    throw new CartError('Unknown product.');
  }
  if (qty === 0) {
    db.prepare('DELETE FROM cart_items WHERE cart_id = ? AND sku = ?').run(cartId, sku);
    return;
  }
  if (qty > product.stock) {
    throw new CartError(`Only ${product.stock} of ${product.name} in stock.`);
  }
  db.prepare(
    `INSERT INTO cart_items (cart_id, sku, qty) VALUES (?, ?, ?)
     ON CONFLICT (cart_id, sku) DO UPDATE SET qty = excluded.qty`,
  ).run(cartId, sku, qty);
}

export function clearCart(db: Db, userId: string): void {
  db.prepare('DELETE FROM cart_items WHERE cart_id = ?').run(cartIdFor(userId));
}

export class CartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CartError';
  }
}

export type { Product };
