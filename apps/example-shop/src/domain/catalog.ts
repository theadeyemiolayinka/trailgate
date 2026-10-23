import type { Money } from '@trailgate/core';
import type { Db } from '../db/database.ts';
import { money } from './money.ts';

export interface Product {
  sku: string;
  name: string;
  category: string;
  description: string;
  detail: string;
  price: Money;
  stock: number;
}

interface ProductRow {
  sku: string;
  name: string;
  category: string;
  description: string;
  detail: string;
  price_minor: number;
  currency: string;
  stock: number;
}

function toProduct(row: ProductRow): Product {
  return {
    sku: row.sku,
    name: row.name,
    category: row.category,
    description: row.description,
    detail: row.detail,
    price: { amount: row.price_minor, currency: row.currency },
    stock: row.stock,
  };
}

export function listProducts(db: Db, category?: string): Product[] {
  const rows = (category === undefined
    ? db.prepare('SELECT * FROM products ORDER BY category, name').all()
    : db
        .prepare('SELECT * FROM products WHERE category = ? ORDER BY name')
        .all(category)) as unknown as ProductRow[];
  return rows.map(toProduct);
}

export function getProduct(db: Db, sku: string): Product | undefined {
  const row = db.prepare('SELECT * FROM products WHERE sku = ?').get(sku) as ProductRow | undefined;
  return row === undefined ? undefined : toProduct(row);
}

export function listCategories(db: Db): string[] {
  return (
    db.prepare('SELECT DISTINCT category FROM products ORDER BY category').all() as {
      category: string;
    }[]
  ).map((r) => r.category);
}

export function productCount(db: Db): number {
  const row = db.prepare('SELECT COUNT(*) AS n FROM products').get() as { n: number };
  return row.n;
}

/** Decrements stock inside the caller's transaction. Throws when out of stock. */
export function decrementStock(db: Db, sku: string, qty: number): void {
  const result = db
    .prepare('UPDATE products SET stock = stock - ? WHERE sku = ? AND stock >= ?')
    .run(qty, sku, qty);
  if (result.changes === 0) {
    throw new InsufficientStockError(sku);
  }
}

export function restoreStock(db: Db, sku: string, qty: number): void {
  db.prepare('UPDATE products SET stock = stock + ? WHERE sku = ?').run(qty, sku);
}

export class InsufficientStockError extends Error {
  readonly sku: string;
  constructor(sku: string) {
    super(`insufficient stock for ${sku}`);
    this.name = 'InsufficientStockError';
    this.sku = sku;
  }
}
