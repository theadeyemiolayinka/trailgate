/**
 * Reproducible agent walkthrough against a live ExampleShop over real HTTP.
 * Exercises discovery, consent, redemption, signed requests, spending
 * constraints, and receipts, printing each step the way a runtime would.
 *
 * Usage:
 *   pnpm dev            (terminal 1: the shop)
 *   pnpm demo           (terminal 2: this script)
 *
 * The script submits a grant request, then waits for you to approve it in
 * the browser (it prints the consent URL translated to the local origin).
 * Optional flags:
 *   --budget <minor>    cumulative_budget constraint in minor units (default 10000)
 *   --max <minor>       max_amount constraint in minor units (default 5000)
 *   --origin <url>      http origin the shop listens on (default http://127.0.0.1:3300)
 */
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';
import { loopbackTransport } from './loopback.ts';

const flag = (name: string): string | undefined => {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 && idx + 1 < process.argv.length ? process.argv[idx + 1] : undefined;
};

const ISSUER = process.env['SHOP_ISSUER'] ?? 'https://localhost:3443';
const ORIGIN = flag('origin') ?? 'http://127.0.0.1:3300';
const BUDGET_MINOR = Number.parseInt(flag('budget') ?? '10000', 10);
const MAX_MINOR = Number.parseInt(flag('max') ?? '5000', 10);
const DEMO_USER_ID = 'usr_demo';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const transport = loopbackTransport(ISSUER, ORIGIN);
const client = createAgentClient({ transport });
client.useKey(SoftwareKeyProvider.generate());

const decode = (body: Uint8Array) => JSON.parse(new TextDecoder().decode(body)) as unknown;

console.log('1. discover');
const site = await client.discover(ISSUER);
console.log(`   issuer: ${site.issuer}  protocol: ${site.protocolVersion}`);
console.log(`   permissions: ${site.document.permissions.join(', ')}`);

console.log('2. request grant');
const session = await client.requestGrant(site, {
  permissions: [
    'tg.catalog.read',
    'tg.cart.read',
    'tg.cart.write',
    'tg.order.create',
    'tg.order.read',
    'tg.wallet.read',
    'tg.wallet.charge',
  ],
  resources: [`cart:cart_${DEMO_USER_ID}`, `wallet:wlt_${DEMO_USER_ID}`],
  constraints: [
    { type: 'max_amount', params: { amount: MAX_MINOR, currency: 'USD' } },
    { type: 'cumulative_budget', params: { amount: BUDGET_MINOR, currency: 'USD' } },
  ],
  requestedSeconds: 3600,
});
console.log(`   request_id: ${session.requestId}`);
console.log(`   approve in the browser: ${transport.mapUrl(session.consentUrl)}`);
console.log('   (sign in as ada@example.com / demo-pass-1234, then Approve)');

console.log('3. awaiting consent decision...');
const grant = await client.awaitApproval(session.requestId, { intervalMs: 1500 });
console.log(`   grant issued: ${grant.jti}`);

console.log('4. read catalog');
const catalog = await client.fetchProtected(site, { method: 'GET', target: '/api/products' });
console.log(
  `   status ${catalog.status}: ${(decode(catalog.body) as { products: unknown[] }).products.length} products`,
);

console.log('5. add an item to the cart');
const added = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/cart/items',
  body: JSON.stringify({ sku: 'drk-mug-01', qty: 1 }),
});
console.log(`   status ${added.status}`);

console.log('6. place the order');
const orderRes = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
});
const order = decode(orderRes.body) as { id: string; total: { amount: number } };
console.log(`   status ${orderRes.status}: order ${order.id} total ${order.total.amount}`);

console.log('7. pay for the order (tg.wallet.charge)');
const paid = await client.fetchProtected(site, {
  method: 'POST',
  target: `/api/orders/${order.id}/pay`,
  body: '{}',
});
const receiptNote =
  paid.receipt === undefined
    ? 'no receipt'
    : paid.receipt.verified
      ? `receipt decision=${paid.receipt.payload.tg.decision}`
      : 'receipt unverified';
console.log(`   status ${paid.status} ${receiptNote}`);
if (paid.error !== undefined) {
  console.log(`   denied: ${paid.error.code} ${paid.error.message}`);
}

console.log('8. attempt an over-budget charge (expected denial)');
const order2 = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
});
if (order2.status === 201) {
  const id2 = (decode(order2.body) as { id: string }).id;
  const denied = await client.fetchProtected(site, {
    method: 'POST',
    target: `/api/orders/${id2}/pay`,
    body: '{}',
  });
  console.log(
    `   status ${denied.status}${denied.error !== undefined ? `: ${denied.error.code}` : ''}`,
  );
} else {
  console.log(`   order creation failed (${order2.status}); nothing to charge`);
}

console.log('9. read wallet state');
const wallet = await client.fetchProtected(site, { method: 'GET', target: '/api/wallet' });
if (wallet.status === 200) {
  const view = decode(wallet.body) as {
    wallet: { balance: { amount: number; currency: string } };
    grant: { consumed_under_grant: { amount: number }; reserved_under_grant: { amount: number } };
  };
  console.log(`   balance ${view.wallet.balance.amount} ${view.wallet.balance.currency}`);
  console.log(
    `   grant ledger: consumed=${view.grant.consumed_under_grant.amount} reserved=${view.grant.reserved_under_grant.amount}`,
  );
} else {
  console.log(
    `   status ${wallet.status}${wallet.error !== undefined ? `: ${wallet.error.code}` : ''}`,
  );
}

await sleep(0);
console.log('done.');
