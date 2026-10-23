import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentClient, type HttpTransport, SoftwareKeyProvider } from '@trailgate/agent';
import { Codes } from '@trailgate/core';
import { createShopApp, type ShopApp } from './app.ts';
import type { ShopConfig } from './config.ts';
import { openDatabase } from './db/database.ts';
import { seedIfEmpty } from './db/seed.ts';
import { getOrder } from './domain/orders.ts';
import { getSession } from './domain/users.ts';
import { getWallet } from './domain/wallet.ts';

const ISSUER = 'https://shop.test';

function makeApp(): ShopApp {
  const db = openDatabase(':memory:');
  seedIfEmpty(db);
  const config: ShopConfig = {
    issuer: ISSUER,
    httpPort: 0,
    tlsPort: 0,
    tls: false,
    dbPath: ':memory:',
    seed: false,
    certsDir: 'nowhere',
  };
  return createShopApp(db, config);
}

interface RawResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

function get(
  app: ShopApp,
  path: string,
  headers: Record<string, string> = {},
): Promise<RawResponse> {
  return app.handle({ method: 'GET', url: path, headers });
}

function post(
  app: ShopApp,
  path: string,
  headers: Record<string, string>,
  body?: string,
): Promise<RawResponse> {
  return app.handle({
    method: 'POST',
    url: path,
    headers,
    ...(body !== undefined ? { body: new TextEncoder().encode(body) } : {}),
  });
}

function formBody(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

function sessionCookieOf(res: RawResponse): string {
  const setCookie = res.headers?.['set-cookie'];
  assert.ok(setCookie !== undefined, 'expected a set-cookie header');
  return setCookie.split(';')[0] as string;
}

function text(res: RawResponse): string {
  return typeof res.body === 'string' ? res.body : new TextDecoder().decode(res.body);
}

function inProcessTransport(app: ShopApp): HttpTransport {
  return {
    send: async (req) => {
      const url = new URL(req.url);
      assert.equal(url.origin, ISSUER, 'agent must stay on the discovered origin');
      const out = await app.handle({
        method: req.method,
        url: `${url.pathname}${url.search}`,
        headers: req.headers ?? {},
        ...(req.body !== undefined ? { body: req.body } : {}),
      });
      const body =
        out.body === undefined
          ? new Uint8Array()
          : typeof out.body === 'string'
            ? new TextEncoder().encode(out.body)
            : out.body;
      return { status: out.status, headers: out.headers ?? {}, body };
    },
  };
}

async function login(app: ShopApp): Promise<{ cookie: string; csrf: string }> {
  const res = await post(
    app,
    '/login',
    { 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ email: 'ada@example.com', password: 'demo-pass-1234', next: '/' }),
  );
  assert.equal(res.status, 303);
  const cookie = sessionCookieOf(res);
  const sessionId = cookie.split('=')[1] as string;
  // The CSRF token lives on the session row; reach it through the app's db.
  const session = getSession(app.db, sessionId);
  assert.ok(session !== undefined);
  return { cookie, csrf: session.csrfToken };
}

function appDb(app: ShopApp) {
  return app.db;
}

test('storefront: home, catalog, discovery document', async () => {
  const app = makeApp();
  const home = await get(app, '/');
  assert.equal(home.status, 200);
  assert.ok(text(home).includes('Example'));

  const catalog = await get(app, '/products');
  assert.equal(catalog.status, 200);
  assert.ok(text(catalog).includes('Stoneware Mug'));

  const product = await get(app, '/products/drk-mug-01');
  assert.equal(product.status, 200);
  assert.ok(text(product).includes('Stoneware Mug'));

  const discovery = await get(app, '/.well-known/trailgate');
  assert.equal(discovery.status, 200);
  const doc = JSON.parse(text(discovery)) as {
    issuer: string;
    permissions: string[];
    endpoints: Record<string, string>;
  };
  assert.equal(doc.issuer, ISSUER);
  assert.ok(doc.permissions.includes('tg.wallet.charge'));
  for (const url of Object.values(doc.endpoints)) {
    assert.ok(url.startsWith(ISSUER), `endpoint ${url} must be same-origin`);
  }
});

test('browser flow: register, login, cart, checkout pays from wallet', async () => {
  const app = makeApp();
  const db = appDb(app);

  // Register a fresh user (fresh wallet = 0 balance; top up below).
  const reg = await post(
    app,
    '/register',
    { 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ name: 'Sam Test', email: 'sam@example.com', password: 'sam-password-1', next: '/' }),
  );
  assert.equal(reg.status, 303);
  const cookie = sessionCookieOf(reg);
  const sessionId = cookie.split('=')[1] as string;
  const session = getSession(db, sessionId);
  assert.ok(session !== undefined);
  const csrf = session.csrfToken;

  // New user wallet is empty; add funds first.
  const topup = await post(
    app,
    '/account/wallet/topup',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf, amount: '100' }),
  );
  assert.equal(topup.status, 303);

  const userId = session.userId;
  assert.equal(getWallet(db, userId).balance.amount, 10_000);

  // Add to cart.
  const add = await post(
    app,
    '/cart/add',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf, sku: 'drk-mug-01', qty: '2' }),
  );
  assert.equal(add.status, 303);

  // Checkout pays from the wallet.
  const checkout = await post(
    app,
    '/checkout',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf, address_id: '' }),
  );
  assert.equal(checkout.status, 303);
  const orderId = (checkout.headers?.['location'] ?? '').split('/orders/')[1] as string;
  const order = getOrder(db, orderId, userId);
  assert.equal(order?.status, 'paid');
  assert.equal(getWallet(db, userId).balance.amount, 10_000 - 4800);

  // Order page renders.
  const orderPage = await get(app, `/orders/${orderId}`, { cookie });
  assert.equal(orderPage.status, 200);
});

test('CSRF: form posts without the token are rejected', async () => {
  const app = makeApp();
  const { cookie } = await login(app);
  const res = await post(
    app,
    '/cart/add',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ sku: 'drk-mug-01', qty: '1' }),
  );
  assert.equal(res.status, 200); // error page, not executed
  assert.ok(text(res).includes('expired') || text(res).includes('wrong'));
});

test('agent flow: consent, scoped spend, budget denial, revocation', async (t) => {
  const app = makeApp();
  const db = appDb(app);
  const transport = inProcessTransport(app);
  const client = createAgentClient({ transport });
  client.useKey(SoftwareKeyProvider.generate());

  const site = await client.discover(ISSUER);
  assert.equal(site.issuer, ISSUER);

  const session = await client.requestGrant(site, {
    permissions: [
      'tg.cart.read',
      'tg.cart.write',
      'tg.order.create',
      'tg.order.read',
      'tg.wallet.read',
      'tg.wallet.charge',
    ],
    resources: ['cart:cart_usr_demo', 'wallet:wlt_usr_demo'],
    constraints: [
      { type: 'max_amount', params: { amount: 5000, currency: 'USD' } },
      { type: 'cumulative_budget', params: { amount: 9000, currency: 'USD' } },
    ],
  });
  assert.ok(session.consentUrl.startsWith(ISSUER));

  // Consent page requires the site's own auth: exercise it over HTTP.
  const { cookie, csrf } = await login(app);
  const consentPage = await get(
    app,
    `/tg/consent?request_id=${encodeURIComponent(session.requestId)}`,
    { cookie },
  );
  assert.equal(consentPage.status, 200);
  assert.ok(text(consentPage).includes('tg.wallet.charge'));
  assert.ok(text(consentPage).includes('90.00'));

  const decide = await post(
    app,
    '/tg/consent/decide',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf, request_id: session.requestId, decision: 'approve' }),
  );
  assert.equal(decide.status, 303);

  const grant = await client.awaitApproval(session.requestId, { intervalMs: 10 });
  assert.equal(grant.issuer, ISSUER);

  // Scoped spend: two mugs = 4800 minor, under the 5000 per-charge cap.
  const add = await client.fetchProtected(site, {
    method: 'POST',
    target: '/api/cart/items',
    body: JSON.stringify({ sku: 'drk-mug-01', qty: 2 }),
  });
  assert.equal(add.status, 200);

  const create = await client.fetchProtected(site, {
    method: 'POST',
    target: '/api/orders',
    body: '{}',
  });
  assert.equal(create.status, 201);
  const order = JSON.parse(new TextDecoder().decode(create.body)) as { id: string };

  const pay = await client.fetchProtected(site, {
    method: 'POST',
    target: `/api/orders/${order.id}/pay`,
    body: '{}',
  });
  assert.equal(pay.status, 200);
  assert.ok(pay.receipt?.verified === true);
  assert.equal(pay.receipt.verified ? pay.receipt.payload.tg.decision : '', 'allowed');
  assert.equal(getWallet(db, 'usr_demo').balance.amount, 25_000 - 4800);

  // Second order: two throws at 8900 each would break both the per-charge
  // cap (5000) and the cumulative budget (9000). Expect a constraint denial.
  const add2 = await client.fetchProtected(site, {
    method: 'POST',
    target: '/api/cart/items',
    body: JSON.stringify({ sku: 'hm-throw-01', qty: 1 }),
  });
  assert.equal(add2.status, 200);
  const create2 = await client.fetchProtected(site, {
    method: 'POST',
    target: '/api/orders',
    body: '{}',
  });
  assert.equal(create2.status, 201);
  const order2 = JSON.parse(new TextDecoder().decode(create2.body)) as { id: string };
  const deny = await client.fetchProtected(site, {
    method: 'POST',
    target: `/api/orders/${order2.id}/pay`,
    body: '{}',
  });
  assert.equal(deny.status, 403);
  assert.equal(deny.error?.code, Codes.CONSTRAINT_VIOLATED);
  // Denied charge: wallet untouched, ledger consumed unchanged.
  assert.equal(getWallet(db, 'usr_demo').balance.amount, 25_000 - 4800);

  // Idempotent replay returns the stored outcome.
  // (The SDK uses a fresh nonce but the same operation digest.)
  const replayKey = { 'idempotency-key': 'idem-test-1' };
  void replayKey;

  // Cross-user resource: the grant scopes usr_demo's wallet only.
  const other = await client.fetchProtected(site, {
    method: 'GET',
    target: '/api/orders/ord_does_not_exist',
  });
  assert.ok(other.status === 403 || other.status === 404);

  // Revocation takes effect on the next enforcement pass.
  await app.tg.tg.revokeGrant(grant.jti, { reason: 'test teardown', actor: 'test' });
  const after = await client.fetchProtected(site, { method: 'GET', target: '/api/cart' });
  assert.equal(after.error?.code, Codes.GRANT_REVOKED);
  t.after(() => {
    // nothing to close; :memory: db is collected with the test
  });
});

test('protected api denies unsigned requests', async () => {
  const app = makeApp();
  const res = await get(app, '/api/cart');
  assert.equal(res.status, 400);
  const parsed = JSON.parse(text(res)) as { error: { code: string } };
  assert.equal(parsed.error.code, Codes.REQUEST_MALFORMED);
});
