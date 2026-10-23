import { getProduct, productCount } from '../domain/catalog.ts';
import { SHOP_CURRENCY } from '../domain/money.ts';
import { createUser, saveAddress } from '../domain/users.ts';
import { topUp } from '../domain/wallet.ts';
import type { Db } from './database.ts';

/**
 * Deterministic seed data. Product rows are sample catalog data; they are
 * not recorded activity. The demo user, wallet balance, and address exist
 * so the walkthrough in the README works out of the box. Real activity
 * (orders, wallet entries, audit events) is only ever written by real
 * operations against the running app.
 */

const DEMO_USER = {
  id: 'usr_demo',
  email: 'ada@example.com',
  name: 'Ada Osei',
  password: 'demo-pass-1234',
};

interface SeedProduct {
  sku: string;
  name: string;
  category: string;
  description: string;
  detail: string;
  priceMinor: number;
  stock: number;
}

const PRODUCTS: SeedProduct[] = [
  {
    sku: 'drk-mug-01',
    name: 'Stoneware Mug',
    category: 'Drinkware',
    description: 'A hand-glazed 350 ml mug with a matte exterior and a gloss interior.',
    detail:
      'Thrown and finished in small batches. Dishwasher and microwave safe. The matte glaze keeps its texture through daily use; the interior glaze resists staining.',
    priceMinor: 2400,
    stock: 40,
  },
  {
    sku: 'drk-carafe-02',
    name: 'Glass Carafe',
    category: 'Drinkware',
    description: 'A one-litre borosilicate carafe with a lid that doubles as a cup.',
    detail:
      'Heat resistant to 150 degrees. The lid seals with a silicone ring and seats as a tumbler. Fits the pour-over dripper SKU kit-pour-01.',
    priceMinor: 3800,
    stock: 25,
  },
  {
    sku: 'dsk-tray-01',
    name: 'Walnut Desk Tray',
    category: 'Desk',
    description: 'A solid walnut catch-all for keys, pens, and pocket contents.',
    detail:
      'Finished with hardwax oil. Cork-lined base. Dimensions 24 x 16 x 3 cm. Grain varies per piece.',
    priceMinor: 4600,
    stock: 18,
  },
  {
    sku: 'dsk-mat-02',
    name: 'Wool Desk Mat',
    category: 'Desk',
    description: 'A 90 x 40 cm merino felt mat that anchors a keyboard and notebook.',
    detail:
      'Four millimetre felted merino with a natural rubber grip layer. Cut edges, no stitching. Spot clean.',
    priceMinor: 5200,
    stock: 22,
  },
  {
    sku: 'dsk-lamp-03',
    name: 'Task Lamp',
    category: 'Desk',
    description: 'A clamp lamp with a warm-to-neutral LED head and a long reach arm.',
    detail:
      'Aluminium arm, steel clamp, 2700K to 5000K continuous adjustment, 800 lumen maximum. Powered over USB-C.',
    priceMinor: 9800,
    stock: 12,
  },
  {
    sku: 'stn-book-01',
    name: 'Linen Notebook',
    category: 'Stationery',
    description: 'A lay-flat A5 notebook bound in book linen with dot grid pages.',
    detail:
      '192 pages of 100 gsm paper, thread-sewn binding, two ribbon markers. The dot grid is printed in cool grey.',
    priceMinor: 1800,
    stock: 60,
  },
  {
    sku: 'stn-pen-02',
    name: 'Brass Pen',
    category: 'Stationery',
    description: 'A machined brass pen that takes a standard gel refill and ages to a patina.',
    detail:
      '12 grams, knurled grip section, ships with a black 0.5 mm refill. The brass darkens with handling.',
    priceMinor: 3400,
    stock: 35,
  },
  {
    sku: 'stn-cards-03',
    name: 'Correspondence Cards',
    category: 'Stationery',
    description: 'A box of 25 heavyweight flat cards with matching envelopes.',
    detail: '600 gsm cotton card stock, blind-debossed rule border, unprinted envelopes.',
    priceMinor: 2200,
    stock: 30,
  },
  {
    sku: 'kit-pour-01',
    name: 'Pour-Over Set',
    category: 'Kitchen',
    description: 'A ceramic dripper, server, and filter pack for one to two cups.',
    detail:
      'Glazed stoneware dripper with spiral ribs, 600 ml server, 40 paper filters. Sized for the glass carafe.',
    priceMinor: 6200,
    stock: 15,
  },
  {
    sku: 'kit-board-02',
    name: 'Oak Serving Board',
    category: 'Kitchen',
    description: 'A 38 cm white oak board with a leather hanging loop.',
    detail: 'Oiled finish, food safe. Hand wash and re-oil monthly. End-grain inlay stripe.',
    priceMinor: 4400,
    stock: 20,
  },
  {
    sku: 'hm-throw-01',
    name: 'Wool Throw',
    category: 'Home',
    description: 'A 130 x 180 cm lambswool throw in a plain oat weave.',
    detail: 'Undyed lambswool, whipped edges, woven in a small mill. Dry clean only.',
    priceMinor: 8900,
    stock: 9,
  },
  {
    sku: 'hm-candle-02',
    name: 'Cedar Candle',
    category: 'Home',
    description: 'A cedar and vetiver candle in a reusable glass tumbler.',
    detail: '200 grams, roughly 45 hours of burn time, cotton wick, no dye.',
    priceMinor: 1900,
    stock: 50,
  },
];

export function seedIfEmpty(db: Db, now = Math.floor(Date.now() / 1000)): void {
  if (productCount(db) > 0) {
    return;
  }
  db.exec('BEGIN');
  try {
    for (const product of PRODUCTS) {
      db.prepare(
        `INSERT INTO products (sku, name, category, description, detail, price_minor, currency, stock)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        product.sku,
        product.name,
        product.category,
        product.description,
        product.detail,
        product.priceMinor,
        SHOP_CURRENCY,
        product.stock,
      );
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  const user = createUser(db, DEMO_USER, { now, id: DEMO_USER.id });
  saveAddress(db, user.id, {
    label: 'Home',
    line1: '14 Marsh Lane',
    city: 'Portland',
    region: 'OR',
    postcode: '97205',
    country: 'United States',
    isDefault: true,
  });
  // Simulated opening balance for the demo wallet.
  topUp(db, user.id, { amount: 25000, currency: SHOP_CURRENCY }, now);

  // Second user with one paid order, so cross-user resource denial can be
  // demonstrated deterministically (resource order:ord_bill_seed01).
  const bill = createUser(
    db,
    { email: 'bill@example.com', name: 'Bill Hart', password: 'demo-pass-1234' },
    { now, id: 'usr_bill' },
  );
  topUp(db, bill.id, { amount: 5000, currency: SHOP_CURRENCY }, now);
  const billMug = getProduct(db, 'drk-mug-01');
  db.prepare(
    `INSERT INTO orders (id, user_id, status, total_minor, currency, address_id, placed_via, created_at, paid_at)
     VALUES ('ord_bill_seed01', ?, 'paid', ?, 'USD', NULL, 'user', ?, ?)`,
  ).run(bill.id, billMug?.price.amount ?? 2400, now, now);
  db.prepare(
    `INSERT INTO order_items (order_id, sku, name, qty, unit_price_minor)
     VALUES ('ord_bill_seed01', 'drk-mug-01', ?, 1, ?)`,
  ).run(billMug?.name ?? 'Stoneware Mug', billMug?.price.amount ?? 2400);
}

export { DEMO_USER };
