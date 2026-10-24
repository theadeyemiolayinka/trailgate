import assert from 'node:assert/strict';
import { test } from 'node:test';
import { type Db, openDatabase } from '../db/database.ts';
import { seedIfEmpty } from '../db/seed.ts';
import { CartError, getCart, setCartQty } from './cart.ts';
import { getProduct, InsufficientStockError, listCategories, listProducts } from './catalog.ts';
import { formatMoney, formatMoneyWithCurrency, money } from './money.ts';
import {
  cancelOrder,
  createOrderFromCart,
  getInvoice,
  getOrder,
  OrderError,
  payOrder,
  refundOrder,
} from './orders.ts';
import {
  AuthError,
  authenticate,
  createSession,
  createUser,
  getSession,
  ValidationError,
} from './users.ts';
import {
  getWallet,
  InsufficientFundsError,
  listWalletEntries,
  refundForOrder,
  topUp,
} from './wallet.ts';

function testDb(): Db {
  const db = openDatabase(':memory:');
  seedIfEmpty(db);
  return db;
}

test('money formats integer minor units', () => {
  assert.equal(formatMoney(money(0)), '0.00');
  assert.equal(formatMoney(money(5)), '0.05');
  assert.equal(formatMoney(money(1299)), '12.99');
  assert.equal(formatMoneyWithCurrency(money(1299, 'USD')), 'USD 12.99');
  assert.equal(formatMoney({ amount: -250, currency: 'USD' }), '-2.50');
  assert.throws(() => money(1.5), RangeError);
  assert.throws(() => money(-1), RangeError);
});

test('seed produces deterministic catalog and demo user', () => {
  const db = testDb();
  const products = listProducts(db);
  assert.equal(products.length, 12);
  assert.ok(listCategories(db).length > 0);
  const user = authenticate(db, 'ada@example.com', 'demo-pass-1234');
  assert.equal(user.id, 'usr_demo');
  assert.equal(getWallet(db, user.id).balance.amount, 25000);
});

test('registration validates and rejects duplicates', () => {
  const db = testDb();
  assert.throws(
    () => createUser(db, { email: 'not-an-email', name: 'X', password: 'long-enough-1' }),
    ValidationError,
  );
  assert.throws(
    () => createUser(db, { email: 'x@y.com', name: 'X', password: 'short' }),
    ValidationError,
  );
  const user = createUser(db, { email: 'jo@example.com', name: 'Jo', password: 'long-enough-1' });
  assert.equal(user.email, 'jo@example.com');
  assert.throws(
    () => createUser(db, { email: 'JO@example.com', name: 'Jo2', password: 'long-enough-1' }),
    ValidationError,
  );
  assert.throws(() => authenticate(db, 'jo@example.com', 'wrong-password'), AuthError);
});

test('sessions expire', () => {
  const db = testDb();
  const session = createSession(db, 'usr_demo');
  assert.ok(getSession(db, session.id) !== undefined);
  const future = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30;
  assert.equal(getSession(db, session.id, future), undefined);
});

test('cart enforces stock and quantity', () => {
  const db = testDb();
  setCartQty(db, 'usr_demo', 'drk-mug-01', 2);
  const cart = getCart(db, 'usr_demo');
  assert.equal(cart.lines[0]?.qty, 2);
  assert.equal(cart.total.amount, 4800);
  assert.throws(() => setCartQty(db, 'usr_demo', 'hm-throw-01', 10), CartError); // only 9 in stock
  assert.throws(() => setCartQty(db, 'usr_demo', 'nope', 1), CartError);
  setCartQty(db, 'usr_demo', 'drk-mug-01', 0);
  assert.equal(getCart(db, 'usr_demo').lines.length, 0);
});

test('wallet: topup, debit, insufficient funds, refund', () => {
  const db = testDb();
  const before = getWallet(db, 'usr_demo').balance.amount;
  topUp(db, 'usr_demo', money(500));
  assert.equal(getWallet(db, 'usr_demo').balance.amount, before + 500);

  // debitForOrder is exercised through payOrder in the orders suite; test guard here
  assert.throws(
    () => refundForOrder(db, 'usr_demo', { amount: 0, currency: 'USD' }, 'ord_x'),
    /positive/,
  );
  assert.throws(() => topUp(db, 'usr_demo', { amount: 0, currency: 'USD' }), /positive/);

  const entries = listWalletEntries(db, 'usr_demo');
  assert.ok(entries.length >= 2);
  // Invariant: sum of entries equals balance.
  const sum = db
    .prepare('SELECT SUM(amount_minor) AS s FROM wallet_entries WHERE user_id = ?')
    .get('usr_demo') as { s: number };
  assert.equal(sum.s, getWallet(db, 'usr_demo').balance.amount);
});

test('orders: create snapshots cart, pay debits wallet, refund restores', () => {
  const db = testDb();
  const startBalance = getWallet(db, 'usr_demo').balance.amount;
  const mug = getProduct(db, 'drk-mug-01');
  const startStock = mug?.stock;

  setCartQty(db, 'usr_demo', 'drk-mug-01', 2);
  const order = createOrderFromCart(db, 'usr_demo', { placedVia: 'user' });
  assert.equal(order.status, 'awaiting_payment');
  assert.equal(order.total.amount, 4800);
  assert.equal(getCart(db, 'usr_demo').lines.length, 0);
  assert.equal(getProduct(db, 'drk-mug-01')?.stock, startStock - 2);

  assert.throws(() => payOrder(db, 'ord_missing', 'usr_demo'), OrderError);
  const paid = payOrder(db, order.id, 'usr_demo');
  assert.equal(paid.status, 'paid');
  assert.equal(getWallet(db, 'usr_demo').balance.amount, startBalance - 4800);

  assert.throws(() => payOrder(db, order.id, 'usr_demo'), OrderError);
  const { refund } = refundOrder(db, order.id, 'usr_demo');
  assert.equal(refund.amount, 4800);
  assert.equal(getWallet(db, 'usr_demo').balance.amount, startBalance);
  assert.equal(getProduct(db, 'drk-mug-01')?.stock, startStock);
});

test('orders: cross-user isolation and cancel', () => {
  const db = testDb();
  const other = createUser(db, { email: 'bo@example.com', name: 'Bo', password: 'long-enough-1' });
  setCartQty(db, 'usr_demo', 'stn-book-01', 1);
  const order = createOrderFromCart(db, 'usr_demo', { placedVia: 'user' });
  assert.equal(getOrder(db, order.id, other.id), undefined);
  assert.throws(() => payOrder(db, order.id, other.id), OrderError);
  const cancelled = cancelOrder(db, order.id, 'usr_demo');
  assert.equal(cancelled.status, 'cancelled');
});

test('orders: insufficient wallet balance keeps order unpaid', () => {
  const db = testDb();
  const poor = createUser(db, { email: 'po@example.com', name: 'Po', password: 'long-enough-1' });
  setCartQty(db, poor.id, 'hm-throw-01', 1); // 8900 > 0 balance
  const order = createOrderFromCart(db, poor.id, { placedVia: 'user' });
  assert.throws(() => payOrder(db, order.id, poor.id), InsufficientFundsError);
  assert.equal(getOrder(db, order.id, poor.id)?.status, 'awaiting_payment');
});

test('invoice returns order with bill-to', () => {
  const db = testDb();
  setCartQty(db, 'usr_demo', 'stn-pen-02', 1);
  const order = createOrderFromCart(db, 'usr_demo', { placedVia: 'user' });
  const invoice = getInvoice(db, order.id, 'usr_demo');
  assert.equal(invoice?.order.id, order.id);
  assert.equal(invoice?.userEmail, 'ada@example.com');
  assert.equal(invoice?.lines.length, 1);
});

test('orders respect stock', () => {
  const db = testDb();
  setCartQty(db, 'usr_demo', 'hm-candle-02', 1);
  db.prepare("UPDATE products SET stock = 0 WHERE sku = 'hm-candle-02'").run();
  assert.throws(
    () => createOrderFromCart(db, 'usr_demo', { placedVia: 'user' }),
    InsufficientStockError,
  );
});
