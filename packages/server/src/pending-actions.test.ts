import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import type { Jwk } from '@trailgate/core';
import { Codes, signRequest, TrailGateError, verifyReceipt } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import type { TrailGateServerOptions } from './config.ts';
import { RECEIPT_HEADER } from './enforcement.ts';
import type { TrailGateServer } from './server.ts';
import { createTrailGateServer } from './server.ts';
import type { HostRequest, HostResponse } from './types.ts';

const ISSUER = 'https://shop.example.com';
const NOW = 1_700_000_000;

const site = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();

let clockNow = NOW;

function makeServer(overrides: Partial<TrailGateServerOptions> = {}) {
  return createTrailGateServer({
    issuer: ISSUER,
    signingKeys: [{ privateJwk: site.privateJwk }],
    permissions: ['tg.cart.read', 'tg.order.create', 'tg.posts.publish'],
    clock: { now: () => clockNow },
    ...overrides,
  });
}

interface IssuedGrant {
  token: string;
  jti: string;
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  return { verifier, challenge };
}

async function issueGrant(
  server: TrailGateServer,
  options: {
    permissions?: string[];
    resources?: string[];
    constraints?: Record<string, unknown>[];
    subject?: string;
    /** Consent-time tri-state marks: permissions to gate behind approval. */
    approvalPermissions?: string[];
  } = {},
): Promise<IssuedGrant> {
  const { verifier, challenge } = pkce();
  const created = await server.handleGrantRequest({
    method: 'POST',
    url: `${ISSUER}/tg/grant-request`,
    headers: {},
    body: JSON.stringify({
      version: '0.1',
      permissions: options.permissions ?? ['tg.order.create'],
      resources: options.resources ?? [],
      constraints: options.constraints ?? [],
      agent_key: agent.publicJwk,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }),
  });
  assert.equal(created.status, 201);
  const requestId = (created.body as { request_id: string }).request_id;
  const narrow =
    options.approvalPermissions !== undefined
      ? {
          permissions: options.permissions ?? ['tg.order.create'],
          approvalPermissions: options.approvalPermissions,
        }
      : undefined;
  await server.decideConsent(requestId, 'approve', options.subject ?? 'user_1', narrow);
  const redeemed = await server.handleRedemption({
    method: 'POST',
    url: `${ISSUER}/tg/grant-redemption`,
    headers: {},
    body: JSON.stringify({ request_id: requestId, code_verifier: verifier }),
  });
  assert.equal(redeemed.status, 200);
  const token = (redeemed.body as { grant: string }).grant;
  const jti = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8'))
    .jti as string;
  return { token, jti };
}

async function signedRequest(
  grant: string,
  options: {
    method?: string;
    url?: string;
    body?: string;
    idempotencyKey?: string;
    privateJwk?: Jwk;
  } = {},
): Promise<HostRequest> {
  const body = options.body ?? '';
  const headers = await signRequest(
    {
      method: options.method ?? 'POST',
      url: options.url ?? `${ISSUER}/orders`,
      body: new TextEncoder().encode(body),
    },
    {
      privateJwk: options.privateJwk ?? agent.privateJwk,
      keyid: agent.jkt,
      nonce: randomBytes(16).toString('base64url'),
      created: clockNow,
      expires: clockNow + 60,
      grant,
      idempotencyKey: options.idempotencyKey ?? `idem_${randomBytes(12).toString('base64url')}`,
    },
  );
  return {
    method: options.method ?? 'POST',
    url: options.url ?? `${ISSUER}/orders`,
    headers,
    body,
  };
}

const CHECKOUT_ROUTE = {
  permission: 'tg.order.create',
  approval: 'required',
  action: {
    id: 'orders.checkout',
    method: 'POST',
    path: '/orders',
    description: 'check out the cart',
    approval_required: true,
  },
  describe: () => ({ summary: 'check out the cart' }),
} as const;

function pendingBody(res: HostResponse): { id: string; status: string; review_url: string } {
  return (res.body as { pending_action: { id: string; status: string; review_url: string } })
    .pending_action;
}

describe('approval-gated routes (spec section 12.5)', () => {
  it('queues a verified submission as a pending action instead of executing', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200, body: { ok: true } };
    });
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token, { body: '{"cart":"c1"}' }));
    assert.equal(res.status, 202);
    const view = pendingBody(res);
    assert.equal(view.status, 'pending');
    assert.ok(view.id.startsWith('pact_'));
    assert.ok(view.review_url.endsWith(`/account/approvals/${view.id}`));
    assert.equal(ran, 0, 'the handler must not run before approval');
    const receipt = res.headers?.[RECEIPT_HEADER];
    assert.ok(typeof receipt === 'string', 'queued responses carry a pending receipt');
    const payload = await verifyReceipt(receipt, {
      resolveSiteKey: { resolve: async () => site.publicJwk },
      issuer: ISSUER,
      audience: ISSUER,
      expectedGrantId: grant.jti,
    });
    assert.equal(payload.tg.decision, 'pending');
  });

  it('a byte-identical resubmission returns the same open action', async () => {
    clockNow = NOW;
    const server = makeServer();
    const handler = server.protect(CHECKOUT_ROUTE, () => ({ status: 200 }));
    const grant = await issueGrant(server);
    // Same operation digest: identical method, url, body, grant (fresh nonce).
    const req = () => signedRequest(grant.token, { body: '{"cart":"c1"}' });
    const first = await handler(await req());
    const second = await handler(await req());
    assert.equal(first.status, 202);
    assert.equal(second.status, 202);
    assert.equal(pendingBody(second).id, pendingBody(first).id);
    const listed = await server.listPendingActions('user_1');
    assert.equal(listed.filter((r) => r.state === 'pending').length, 1);
  });

  it('approve executes the stored proposal once and records the outcome', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, (req, ctx) => {
      ran += 1;
      assert.equal(ctx.pendingAction?.actionId, 'orders.checkout');
      return { status: 200, body: { order: 'ord_1' } };
    });
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token, { body: '{"cart":"c1"}' }));
    const id = pendingBody(res).id;
    const record = await server.decidePendingAction(id, 'approve', 'user_1');
    assert.equal(record.state, 'succeeded');
    assert.equal(ran, 1);
    assert.equal(record.outcome?.status, 200);
    // Executing again returns the terminal record; the handler never re-runs.
    const again = await server.config.stores.pendingActions.get(id);
    assert.equal(again?.state, 'succeeded');
    assert.equal(ran, 1);
  });

  it('reject leaves the action unexecuted and undecidable again', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    const record = await server.decidePendingAction(id, 'reject', 'user_1', 'not today');
    assert.equal(record.state, 'rejected');
    assert.equal(record.reason, 'not today');
    assert.equal(ran, 0);
    await assert.rejects(
      () => server.decidePendingAction(id, 'approve', 'user_1'),
      (err) => err instanceof TrailGateError && err.code === Codes.ACTION_STATE_INVALID,
    );
    assert.equal(ran, 0);
  });

  it('only the grant subject may decide', async () => {
    clockNow = NOW;
    const server = makeServer();
    const handler = server.protect(CHECKOUT_ROUTE, () => ({ status: 200 }));
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    await assert.rejects(
      () => server.decidePendingAction(id, 'approve', 'mallory'),
      (err) => err instanceof TrailGateError && err.code === Codes.ACTION_UNKNOWN,
    );
    const record = await server.config.stores.pendingActions.get(id);
    assert.equal(record?.state, 'pending');
  });

  it('expired proposals cannot be decided or executed', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    clockNow = NOW + 90_000; // past pendingActionTtlSeconds (86_400)
    await assert.rejects(
      () => server.decidePendingAction(id, 'approve', 'user_1'),
      (err) => err instanceof TrailGateError && err.code === Codes.ACTION_STATE_INVALID,
    );
    assert.equal((await server.config.stores.pendingActions.get(id))?.state, 'expired');
    assert.equal(ran, 0);
    clockNow = NOW;
  });

  it('grant revocation cancels open pending actions', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    await server.revokeGrant(grant.jti, { reason: 'user revoked', actor: 'user_1' });
    assert.equal((await server.config.stores.pendingActions.get(id))?.state, 'cancelled');
    await assert.rejects(
      () => server.decidePendingAction(id, 'approve', 'user_1'),
      (err) => err instanceof TrailGateError && err.code === Codes.ACTION_STATE_INVALID,
    );
    assert.equal(ran, 0);
  });

  it('execution re-checks live scope: narrowed permission fails the action', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server, { permissions: ['tg.order.create', 'tg.cart.read'] });
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    // The user narrows the grant after queueing; approval must not resurrect it.
    await server.updateGrantScope(grant.jti, {
      permissions: ['tg.cart.read'],
      actor: 'user_1',
      at: clockNow,
    });
    const record = await server.decidePendingAction(id, 'approve', 'user_1');
    assert.equal(record.state, 'failed');
    assert.equal(ran, 0);
  });

  it('concurrent decisions resolve to exactly one winner', async () => {
    clockNow = NOW;
    const server = makeServer();
    const handler = server.protect(CHECKOUT_ROUTE, () => ({ status: 200 }));
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    const results = await Promise.allSettled([
      server.decidePendingAction(id, 'reject', 'user_1'),
      server.decidePendingAction(id, 'approve', 'user_1'),
    ]);
    const settled = results.map((r) => r.status);
    assert.ok(settled.includes('rejected'), 'one decision loses the CAS');
    const record = await server.config.stores.pendingActions.get(id);
    assert.ok(record?.state === 'succeeded' || record?.state === 'rejected');
  });

  it('policy require_approval queues even on routes without approval: required', async () => {
    clockNow = NOW;
    const server = makeServer({
      policy: {
        authorize: async () => 'require_approval' as const,
      },
    });
    let ran = 0;
    const handler = server.protect(
      {
        permission: 'tg.order.create',
        action: {
          id: 'orders.checkout',
          method: 'POST',
          path: '/orders',
          description: 'check out the cart',
        },
      },
      () => {
        ran += 1;
        return { status: 200 };
      },
    );
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 202);
    assert.equal(pendingBody(res).status, 'pending');
    assert.equal(ran, 0);
  });

  it('denying policy still denies outright instead of queueing', async () => {
    clockNow = NOW;
    const server = makeServer({
      policy: {
        authorize: async () => {
          throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'nope');
        },
      },
    });
    const handler = server.protect(CHECKOUT_ROUTE, () => ({ status: 200 }));
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 403);
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.AUTHORIZATION_DENIED);
    assert.equal((await server.listPendingActions('user_1')).length, 0);
  });

  it('action_status returns the view under the proposing grant and 404s others', async () => {
    clockNow = NOW;
    const server = makeServer();
    const handler = server.protect(CHECKOUT_ROUTE, () => ({ status: 200, body: { ok: 1 } }));
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;

    const statusReq = await signedRequest(grant.token, {
      method: 'GET',
      url: `${ISSUER}/tg/action-status/${id}`,
    });
    const viewed = await server.handleActionStatus(statusReq);
    assert.equal(viewed.status, 200);
    assert.equal((viewed.body as { status: string }).status, 'pending');
    assert.equal((viewed.body as { pending_action: { id: string } }).pending_action.id, id);

    const other = await issueGrant(server, { subject: 'user_2' });
    const foreign = await server.handleActionStatus(
      await signedRequest(other.token, {
        method: 'GET',
        url: `${ISSUER}/tg/action-status/${id}`,
      }),
    );
    assert.equal(foreign.status, 404);
    assert.equal((foreign.body as { error: { code: string } }).error.code, Codes.ACTION_UNKNOWN);
  });

  it('records the executed outcome on the status response for the agent', async () => {
    clockNow = NOW;
    const server = makeServer();
    const handler = server.protect(CHECKOUT_ROUTE, () => ({
      status: 201,
      body: { order: 'ord_9' },
    }));
    const grant = await issueGrant(server);
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    await server.decidePendingAction(id, 'approve', 'user_1');
    const viewed = await server.handleActionStatus(
      await signedRequest(grant.token, {
        method: 'GET',
        url: `${ISSUER}/tg/action-status/${id}`,
      }),
    );
    assert.equal(viewed.status, 200);
    const body = viewed.body as { status: string; pending_action: { result?: { status: number } } };
    assert.equal(body.status, 'succeeded');
    assert.equal(body.pending_action.result?.status, 201);
  });
});

/**
 * Per-permission tri-state (spec section 9): the human chooses deny,
 * require approval, or allow for each permission at consent and can change
 * the pick afterwards. Marks persist as a `require_approval` constraint and
 * are re-read live on every request and every approved execution.
 */
describe('per-permission tri-state policy (spec section 9)', () => {
  it('queues a marked permission and lets unmarked siblings run', async () => {
    clockNow = NOW;
    const server = makeServer();
    let orderRan = 0;
    let cartRan = 0;
    // Neither route declares approval: 'required' and the order route has
    // no action id, so the queue registers under the permission itself.
    const orderHandler = server.protect({ permission: 'tg.order.create' }, () => {
      orderRan += 1;
      return { status: 201, body: { order: 'ord_1' } };
    });
    const cartHandler = server.protect({ permission: 'tg.cart.read' }, () => {
      cartRan += 1;
      return { status: 200, body: { items: [] } };
    });
    const grant = await issueGrant(server, {
      permissions: ['tg.order.create', 'tg.cart.read'],
      approvalPermissions: ['tg.order.create'],
    });

    const read = await cartHandler(
      await signedRequest(grant.token, { method: 'GET', url: `${ISSUER}/cart` }),
    );
    assert.equal(read.status, 200);
    assert.equal(cartRan, 1);

    const queued = await orderHandler(await signedRequest(grant.token, { body: '{}' }));
    assert.equal(queued.status, 202);
    const view = pendingBody(queued);
    assert.equal(view.status, 'pending');
    assert.equal(orderRan, 0, 'the handler must not run before approval');

    const record = await server.decidePendingAction(view.id, 'approve', 'user_1');
    assert.equal(record.state, 'succeeded');
    assert.equal(orderRan, 1);

    // The mark persists: a different operation queues again.
    const again = await orderHandler(await signedRequest(grant.token, { body: '{"n":2}' }));
    assert.equal(again.status, 202);
    assert.equal(orderRan, 1);
  });

  it('a permission absent from the grant is denied without queueing', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect({ permission: 'tg.order.create' }, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server, { permissions: ['tg.cart.read'] });
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 403);
    assert.equal(
      (res.body as { error: { code: string } }).error.code,
      Codes.REQUEST_PERMISSION_DENIED,
    );
    assert.equal(ran, 0);
    assert.equal((await server.listPendingActions('user_1')).length, 0);
  });

  it('refuses approval marks for permissions the user did not grant', async () => {
    clockNow = NOW;
    const server = makeServer();
    const { verifier, challenge } = pkce();
    const created = await server.handleGrantRequest({
      method: 'POST',
      url: `${ISSUER}/tg/grant-request`,
      headers: {},
      body: JSON.stringify({
        version: '0.1',
        permissions: ['tg.order.create', 'tg.cart.read'],
        resources: [],
        constraints: [],
        agent_key: agent.publicJwk,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      }),
    });
    const requestId = (created.body as { request_id: string }).request_id;
    // Deny tg.order.create yet mark it approval: the mark must track a
    // permission that survives narrowing.
    await assert.rejects(
      () =>
        server.decideConsent(requestId, 'approve', 'user_1', {
          permissions: ['tg.cart.read'],
          approvalPermissions: ['tg.order.create'],
        }),
      (err) => err instanceof TrailGateError && err.code === Codes.REQUEST_MALFORMED,
    );
    void verifier;
  });

  it('dropping the permission after queueing fails the approved run', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect({ permission: 'tg.order.create' }, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server, {
      permissions: ['tg.order.create', 'tg.cart.read'],
      approvalPermissions: ['tg.order.create'],
    });
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    // The human flips the permission to deny before deciding the action.
    await server.updateGrantScope(grant.jti, {
      permissions: ['tg.cart.read'],
      actor: 'user_1',
    });
    const record = await server.decidePendingAction(id, 'approve', 'user_1');
    assert.equal(record.state, 'failed');
    assert.equal(ran, 0);
  });

  it('clearing the mark after queueing still needs the recorded decision', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect({ permission: 'tg.order.create' }, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server, {
      permissions: ['tg.order.create'],
      approvalPermissions: ['tg.order.create'],
    });
    const res = await handler(await signedRequest(grant.token));
    const id = pendingBody(res).id;
    // The human switches the permission to allow: the queued proposal is a
    // distinct human decision and is not silently replayed.
    await server.updateGrantScope(grant.jti, {
      permissions: ['tg.order.create'],
      constraints: [],
      actor: 'user_1',
    });
    const still = await server.config.stores.pendingActions.get(id);
    assert.equal(still?.state, 'pending');
    assert.equal(ran, 0);
    const record = await server.decidePendingAction(id, 'approve', 'user_1');
    assert.equal(record.state, 'succeeded');
    assert.equal(ran, 1);
  });

  it('marking a permission on an approval-required route stays gated either way', async () => {
    clockNow = NOW;
    const server = makeServer();
    let ran = 0;
    const handler = server.protect(CHECKOUT_ROUTE, () => {
      ran += 1;
      return { status: 200 };
    });
    const grant = await issueGrant(server, {
      permissions: ['tg.order.create'],
      approvalPermissions: ['tg.order.create'],
    });
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 202);
    const record = await server.decidePendingAction(pendingBody(res).id, 'approve', 'user_1');
    assert.equal(record.state, 'succeeded');
    assert.equal(ran, 1);
  });
});
