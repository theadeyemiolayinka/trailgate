import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createAgentClient,
  type HttpTransport,
  SoftwareKeyProvider,
  type StoredGrantRecord,
} from '@trailgate/agent';
import { Codes, TrailGateError } from '@trailgate/core';
import { createShopApp, type ShopApp } from './app.ts';
import type { ShopConfig } from './config.ts';
import { openDatabase } from './db/database.ts';
import { seedIfEmpty } from './db/seed.ts';
import { getOrder } from './domain/orders.ts';
import { getSession } from './domain/users.ts';
import { getWallet } from './domain/wallet.ts';

const ISSUER = 'https://shop.test';
const CART = 'cart:cart_usr_demo';
const WALLET = 'wallet:wlt_usr_demo';
const AGENT_SCOPE = {
  permissions: [
    'tg.cart.read',
    'tg.cart.write',
    'tg.order.create',
    'tg.order.read',
    'tg.wallet.read',
    'tg.wallet.charge',
  ],
  resources: [CART, WALLET],
};

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
    maxChargeMinor: 10_000,
    maxGrantBudgetMinor: 50_000,
    policyCurrency: 'USD',
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
  const session = getSession(app.db, cookie.split('=')[1] as string);
  assert.ok(session !== undefined);
  return { cookie, csrf: session.csrfToken };
}

type AgentClient = ReturnType<typeof createAgentClient>;

interface ApprovedAgent {
  client: AgentClient;
  grant: StoredGrantRecord;
}

async function approveAgent(
  app: ShopApp,
  scope: {
    permissions: string[];
    resources: string[];
    constraints?: { type: string; params: Record<string, unknown> }[];
  },
): Promise<ApprovedAgent> {
  const client = createAgentClient({ transport: inProcessTransport(app) });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);
  const session = await client.requestGrant(site, scope);
  // Approval stands in for the human's consent decision; the human-in-the-loop
  // requirements themselves are asserted over HTTP in the consent test below.
  await app.tg.tg.decideConsent(session.requestId, 'approve', 'usr_demo');
  const grant = await client.awaitApproval(session.requestId, { intervalMs: 5 });
  return { client, grant };
}

function consumedUsd(app: ShopApp, grantId: string): number {
  const row = app.db
    .prepare(
      'SELECT COALESCE(SUM(amount_minor), 0) AS total FROM tg_ledger_consumed WHERE grant_id = ?',
    )
    .get(grantId) as { total: number };
  return row.total;
}

function activeReservations(app: ShopApp, grantId: string): number {
  const row = app.db
    .prepare(
      "SELECT COUNT(*) AS n FROM tg_ledger_reservations WHERE grant_id = ? AND state = 'reserved'",
    )
    .get(grantId) as { n: number };
  return row.n;
}

function auditEvents(app: ShopApp, event: string): { payload: string }[] {
  return app.db.prepare('SELECT payload FROM tg_audit WHERE event = ? ORDER BY at').all(event) as {
    payload: string;
  }[];
}

async function createOrderFromCart(client: AgentClient, sku: string, qty: number): Promise<string> {
  const add = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: '/api/cart/items',
    body: JSON.stringify({ sku, qty }),
  });
  assert.equal(add.status, 200, `cart add for ${sku}: ${text(add)}`);
  const create = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: '/api/orders',
    body: '{}',
  });
  assert.equal(create.status, 201, `order create: ${text(create)}`);
  return (JSON.parse(text(create)) as { id: string }).id;
}

test('grant-request intake: unknown permission and unsupported constraint types are rejected', async () => {
  const app = makeApp();
  const client = createAgentClient({ transport: inProcessTransport(app) });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);

  await assert.rejects(
    client.requestGrant(site, {
      permissions: ['tg.nukes.launch'],
      resources: [],
      constraints: [],
    }),
    (err: unknown) => err instanceof TrailGateError && err.code === Codes.GRANT_UNKNOWN_PERMISSION,
    'an identifier outside the site vocabulary must not reach consent',
  );

  // Threshold-based re-approval is not a draft 0.1 constraint type. The site
  // must reject it at intake rather than silently accepting and ignoring it.
  await assert.rejects(
    client.requestGrant(site, {
      permissions: ['tg.catalog.read'],
      resources: [],
      constraints: [{ type: 'approval_threshold', params: { amount: 100, currency: 'USD' } }],
    }),
    (err: unknown) => err instanceof TrailGateError && err.code === Codes.GRANT_SCOPE_REJECTED,
    'unsupported constraint types fail closed at request time',
  );

  // Nothing was persisted for the rejected requests.
  const rows = app.db.prepare('SELECT COUNT(*) AS n FROM tg_grant_requests').get() as { n: number };
  assert.equal(rows.n, 0);
});

test('human approval: consent requires site auth and redemption before approval is denied', async () => {
  const app = makeApp();
  const client = createAgentClient({ transport: inProcessTransport(app) });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);
  const session = await client.requestGrant(site, {
    permissions: ['tg.catalog.read'],
    resources: [],
    constraints: [],
  });

  // The consent surface is part of the site's own auth: unauthenticated
  // visitors are pushed to login, not shown a decision form.
  const anonPage = await get(app, `/tg/consent?request_id=${session.requestId}`);
  assert.equal(anonPage.status, 303);
  assert.ok((anonPage.headers?.location ?? '').startsWith('/login'));

  const anonDecide = await post(
    app,
    '/tg/consent/decide',
    { 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ request_id: session.requestId, decision: 'approve' }),
  );
  assert.equal(anonDecide.status, 303);

  // No agent path can redeem a grant the user has not approved.
  await assert.rejects(
    client.redeemGrant(session.requestId),
    (err: unknown) => err instanceof TrailGateError && err.code === Codes.AUTHORIZATION_DENIED,
    'redemption before approval must deny',
  );

  // An approval decision without an authenticated user is refused too.
  await assert.rejects(
    app.tg.tg.decideConsent(session.requestId, 'approve'),
    (err: unknown) => err instanceof TrailGateError && err.code === Codes.AUTHORIZATION_DENIED,
  );

  // A real login plus the site's CSRF-protected decision completes the loop.
  const { cookie, csrf } = await login(app);
  const decide = await post(
    app,
    '/tg/consent/decide',
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf, request_id: session.requestId, decision: 'approve' }),
  );
  assert.equal(decide.status, 303);
  const grant = await client.redeemGrant(session.requestId);
  assert.equal(grant.subject, 'usr_demo');
});

test('currency: a request in a different currency than max_amount fails closed', async () => {
  const app = makeApp();
  const { client } = await approveAgent(app, {
    ...AGENT_SCOPE,
    constraints: [{ type: 'max_amount', params: { amount: 999_999, currency: 'EUR' } }],
  });

  const orderId = await createOrderFromCart(client, 'drk-mug-01', 2);
  const pay = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${orderId}/pay`,
    body: '{}',
  });
  // A USD charge against an EUR cap cannot be evaluated safely, so it denies
  // rather than ignoring the currency and comparing raw numbers.
  assert.equal(pay.status, 403);
  assert.equal(pay.error?.code, Codes.CONSTRAINT_VIOLATED);
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 25_000);
});

test('rate_limit denies past the window and the denial is audited', async () => {
  const app = makeApp();
  const { client } = await approveAgent(app, {
    permissions: ['tg.catalog.read'],
    resources: [],
    constraints: [{ type: 'rate_limit', params: { max_requests: 2, window_seconds: 3600 } }],
  });

  for (let i = 0; i < 2; i++) {
    const ok = await client.fetchProtected(ISSUER, { method: 'GET', target: '/api/products' });
    assert.equal(ok.status, 200);
  }
  const denied = await client.fetchProtected(ISSUER, {
    method: 'GET',
    target: '/api/products',
  });
  assert.equal(denied.status, 403);
  assert.equal(denied.error?.code, Codes.CONSTRAINT_VIOLATED);
  const deniedPayloads = auditEvents(app, 'request.denied').map(
    (row) => JSON.parse(row.payload) as { code?: string },
  );
  assert.ok(
    deniedPayloads.some((p) => p.code === Codes.CONSTRAINT_VIOLATED),
    'rate-limit denial must appear in the audit sink',
  );
  assert.ok(auditEvents(app, 'request.authenticated').length >= 2);
});

test('concurrency: two requests competing for the remaining budget cannot both spend', async () => {
  const app = makeApp();
  const { client, grant } = await approveAgent(app, {
    ...AGENT_SCOPE,
    constraints: [{ type: 'cumulative_budget', params: { amount: 6_000, currency: 'USD' } }],
  });

  const order1 = await createOrderFromCart(client, 'drk-mug-01', 2); // 4800
  const order2 = await createOrderFromCart(client, 'drk-mug-01', 2); // 4800

  const [pay1, pay2] = await Promise.all([
    client.fetchProtected(ISSUER, {
      method: 'POST',
      target: `/api/orders/${order1}/pay`,
      body: '{}',
    }),
    client.fetchProtected(ISSUER, {
      method: 'POST',
      target: `/api/orders/${order2}/pay`,
      body: '{}',
    }),
  ]);
  const statuses = [pay1.status, pay2.status].sort();
  assert.deepEqual(statuses, [200, 403], 'exactly one concurrent charge may land');
  const loser = pay1.status === 403 ? pay1 : pay2;
  assert.equal(loser.error?.code, Codes.CONSTRAINT_VIOLATED);

  // The losing reservation was released; only the winning charge consumed budget.
  assert.equal(consumedUsd(app, grant.jti), 4_800);
  assert.equal(activeReservations(app, grant.jti), 0);
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 25_000 - 4_800);
});

test('failed charge: handler failure releases the reservation and touches nothing', async () => {
  const app = makeApp();
  const { client, grant } = await approveAgent(app, {
    ...AGENT_SCOPE,
    constraints: [
      { type: 'max_amount', params: { amount: 9_500, currency: 'USD' } },
      { type: 'cumulative_budget', params: { amount: 40_000, currency: 'USD' } },
    ],
  });

  // Drain the wallet below a throw's price: two 8900 pays leave 7200.
  const first = await createOrderFromCart(client, 'hm-throw-01', 1);
  const second = await createOrderFromCart(client, 'hm-throw-01', 1);
  for (const id of [first, second]) {
    const pay = await client.fetchProtected(ISSUER, {
      method: 'POST',
      target: `/api/orders/${id}/pay`,
      body: '{}',
    });
    assert.equal(pay.status, 200);
  }
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 25_000 - 17_800);

  // A third 8900 charge passes the budget and max_amount gates but the wallet
  // cannot cover it. The reservation must roll back with the business failure.
  const third = await createOrderFromCart(client, 'hm-throw-01', 1);
  const failed = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${third}/pay`,
    body: '{}',
  });
  assert.equal(failed.status, 402);
  // Application errors use the site's own surface, not the tg.* envelope
  // (spec/errors.md), so the code arrives in the body rather than res.error.
  const failedBody = JSON.parse(text(failed)) as { error: { code: string } };
  assert.equal(failedBody.error.code, 'shop.wallet.insufficient');

  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 7_200);
  assert.equal(consumedUsd(app, grant.jti), 17_800);
  assert.equal(activeReservations(app, grant.jti), 0);
  assert.equal(getOrder(app.db, third, 'usr_demo')?.status, 'awaiting_payment');

  // Headroom is intact: a charge the wallet can cover still lands afterwards.
  const cheap = await createOrderFromCart(client, 'drk-mug-01', 2);
  const recovered = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${cheap}/pay`,
    body: '{}',
  });
  assert.equal(recovered.status, 200);
});

test('refund: a web-side refund reconciles the ledger and restores grant headroom', async () => {
  const app = makeApp();
  const { client, grant } = await approveAgent(app, {
    ...AGENT_SCOPE,
    constraints: [{ type: 'cumulative_budget', params: { amount: 14_000, currency: 'USD' } }],
  });

  const order1 = await createOrderFromCart(client, 'hm-throw-01', 1); // 8900
  const pay1 = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${order1}/pay`,
    body: '{}',
  });
  assert.equal(pay1.status, 200);
  assert.equal(consumedUsd(app, grant.jti), 8_900);

  // A second 8900 would exceed the 14000 budget.
  const order2 = await createOrderFromCart(client, 'hm-throw-01', 1);
  const blocked = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${order2}/pay`,
    body: '{}',
  });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.error?.code, Codes.CONSTRAINT_VIOLATED);

  // The user refunds order1 through the ordinary site flow; the order carries
  // the grant jti, so the app posts an offsetting ledger entry.
  const { cookie, csrf } = await login(app);
  const refund = await post(
    app,
    `/orders/${order1}/refund`,
    { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    formBody({ _csrf: csrf }),
  );
  assert.equal(refund.status, 303);
  assert.equal(getOrder(app.db, order1, 'usr_demo')?.status, 'refunded');
  assert.equal(consumedUsd(app, grant.jti), 0);
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 25_000);

  // With headroom restored, the previously denied charge succeeds.
  const retry = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${order2}/pay`,
    body: '{}',
  });
  assert.equal(retry.status, 200);
  assert.equal(consumedUsd(app, grant.jti), 8_900);
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, 25_000 - 8_900);
});

test('idempotency: replayed key returns the stored outcome; reused key on a different operation conflicts', async () => {
  const app = makeApp();
  const { client } = await approveAgent(app, {
    ...AGENT_SCOPE,
    constraints: [],
  });

  const orderId = await createOrderFromCart(client, 'drk-mug-01', 1);
  const first = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${orderId}/pay`,
    body: '{}',
    idempotencyKey: 'pay-replay-1',
  });
  assert.equal(first.status, 200);
  const walletAfterFirst = getWallet(app.db, 'usr_demo').balance.amount;

  // Same key, same operation: stored outcome replays, no second debit.
  const replay = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: `/api/orders/${orderId}/pay`,
    body: '{}',
    idempotencyKey: 'pay-replay-1',
  });
  assert.equal(replay.status, 200);
  assert.equal(getWallet(app.db, 'usr_demo').balance.amount, walletAfterFirst);

  // Same key, different operation: conflict, not silent acceptance.
  const conflict = await client.fetchProtected(ISSUER, {
    method: 'POST',
    target: '/api/cart/items',
    body: JSON.stringify({ sku: 'drk-mug-01', qty: 1 }),
    idempotencyKey: 'pay-replay-1',
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.error?.code, Codes.REQUEST_IDEMPOTENCY_CONFLICT);
});

test('cross-user resource access is denied even with the right permission', async () => {
  const app = makeApp();
  const { client } = await approveAgent(app, {
    permissions: ['tg.order.read'],
    resources: [CART],
    constraints: [],
  });

  // ord_bill_seed01 is a real paid order belonging to another user. Holding
  // tg.order.read is not enough; the order: selector is outside this grant.
  const res = await client.fetchProtected(ISSUER, {
    method: 'GET',
    target: '/api/orders/ord_bill_seed01',
  });
  assert.equal(res.status, 403);
  assert.equal(res.error?.code, Codes.REQUEST_RESOURCE_DENIED);
});

test('revoked grant denies immediately even when earlier requests were allowed', async () => {
  const app = makeApp();
  const { client, grant } = await approveAgent(app, {
    permissions: ['tg.cart.read'],
    resources: [CART],
    constraints: [],
  });

  const before = await client.fetchProtected(ISSUER, { method: 'GET', target: '/api/cart' });
  assert.equal(before.status, 200);

  await app.tg.tg.revokeGrant(grant.jti, { reason: 'user-initiated', actor: 'test' });
  const after = await client.fetchProtected(ISSUER, { method: 'GET', target: '/api/cart' });
  assert.equal(after.error?.code, Codes.GRANT_REVOKED);
});
