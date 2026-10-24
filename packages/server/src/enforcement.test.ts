import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import type { Jwk, KeyResolver } from '@trailgate/core';
import {
  Codes,
  operationDigestOf,
  signRequest,
  TrailGateError,
  verifyReceipt,
} from '@trailgate/core';
import { generateEd25519KeyPair, makeGrantPayload, signCompactJws } from '@trailgate/test-fixtures';
import type { TrailGateServerOptions } from './config.ts';
import { RECEIPT_HEADER } from './enforcement.ts';
import type { TrailGateServer } from './server.ts';
import { createTrailGateServer } from './server.ts';
import type { HostRequest, HostResponse } from './types.ts';

const ISSUER = 'https://shop.example.com';
const NOW = 1_700_000_000;

const site = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();

const siteKeyResolver: KeyResolver = { resolve: async () => site.publicJwk };

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  return { verifier, challenge };
}

function makeServer(overrides: Partial<TrailGateServerOptions> = {}) {
  return createTrailGateServer({
    issuer: ISSUER,
    signingKeys: [{ privateJwk: site.privateJwk }],
    permissions: ['tg.cart.read', 'tg.order.create', 'tg.wallet.charge'],
    clock: { now: () => NOW },
    ...overrides,
  });
}

interface IssuedGrant {
  token: string;
  jti: string;
}

async function issueGrant(
  server: TrailGateServer,
  options: {
    permissions?: string[];
    resources?: string[];
    constraints?: Record<string, unknown>[];
    subject?: string;
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
  await server.decideConsent(requestId, 'approve', options.subject ?? 'user_1');
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

interface SignedRequestOptions {
  method?: string;
  url?: string;
  body?: string;
  nonce?: string;
  idempotencyKey?: string;
  keyid?: string;
  privateJwk?: Jwk;
}

async function signedRequest(
  grant: string,
  options: SignedRequestOptions = {},
): Promise<HostRequest> {
  const body = options.body ?? '';
  const bodyBytes = new TextEncoder().encode(body);
  const headers = await signRequest(
    {
      method: options.method ?? 'POST',
      url: options.url ?? `${ISSUER}/orders`,
      body: bodyBytes,
    },
    {
      privateJwk: options.privateJwk ?? agent.privateJwk,
      keyid: options.keyid ?? agent.jkt,
      nonce: options.nonce ?? randomBytes(16).toString('base64url'),
      created: NOW,
      expires: NOW + 60,
      grant,
      idempotencyKey: options.idempotencyKey ?? randomIdem(),
    },
  );
  return {
    method: options.method ?? 'POST',
    url: options.url ?? `${ISSUER}/orders`,
    headers,
    body,
  };
}

function randomIdem(): string {
  return `idem_${randomBytes(12).toString('base64url')}`;
}

function errorCode(res: HostResponse): string {
  return (res.body as { error: { code: string } }).error.code;
}

const okHandler = () => ({ status: 200, body: { ok: true } });

describe('protected request enforcement', () => {
  it('verifies a signed request, runs the handler, and returns a signed receipt', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { ok: true });
    const receipt = res.headers?.[RECEIPT_HEADER];
    assert.ok(typeof receipt === 'string');
    const payload = await verifyReceipt(receipt, {
      resolveSiteKey: siteKeyResolver,
      issuer: ISSUER,
      audience: ISSUER,
      expectedGrantId: grant.jti,
    });
    assert.equal(payload.tg.decision, 'allowed');
  });

  it('denies a replayed nonce with tg.request.replay_detected', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const nonce = randomBytes(16).toString('base64url');
    const first = await handler(await signedRequest(grant.token, { nonce }));
    assert.equal(first.status, 200);
    const second = await handler(await signedRequest(grant.token, { nonce }));
    assert.equal(second.status, 403);
    assert.equal(errorCode(second), Codes.REQUEST_REPLAY_DETECTED);
  });

  it('denies when the grant lacks the required permission', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, { permissions: ['tg.order.create'] });
    const handler = server.protect({ permission: 'tg.wallet.charge' }, okHandler);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(res), Codes.REQUEST_PERMISSION_DENIED);
  });

  it('denies after revocation with tg.grant.revoked', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    await server.revokeGrant(grant.jti, { reason: 'risk signal', actor: 'site' });
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(res), Codes.GRANT_REVOKED);
  });

  it('denies a signature from a key other than the bound one', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const impostor = generateEd25519KeyPair();
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(
      await signedRequest(grant.token, {
        privateJwk: impostor.privateJwk,
        keyid: impostor.jkt,
      }),
    );
    assert.equal(errorCode(res), Codes.REQUEST_KEY_MISMATCH);
  });

  it('enforces max_amount against the declared spend', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, {
      permissions: ['tg.wallet.charge'],
      constraints: [{ type: 'max_amount', params: { amount: 5000, currency: 'USD' } }],
    });
    const handler = server.protect(
      { permission: 'tg.wallet.charge', amount: { amount: 6500, currency: 'USD' } },
      okHandler,
    );
    const res = await handler(await signedRequest(grant.token));
    assert.equal(res.status, 403);
    assert.equal(errorCode(res), Codes.CONSTRAINT_VIOLATED);
  });

  it('enforces cumulative_budget through reservations', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, {
      permissions: ['tg.wallet.charge'],
      constraints: [{ type: 'cumulative_budget', params: { amount: 10000, currency: 'USD' } }],
    });
    const handler = server.protect(
      { permission: 'tg.wallet.charge', amount: { amount: 6000, currency: 'USD' } },
      okHandler,
    );
    const first = await handler(await signedRequest(grant.token));
    assert.equal(first.status, 200);
    const second = await handler(await signedRequest(grant.token));
    assert.equal(second.status, 403);
    assert.equal(errorCode(second), Codes.CONSTRAINT_VIOLATED);
  });

  it('releases the reservation when the handler fails', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, {
      permissions: ['tg.wallet.charge'],
      constraints: [{ type: 'cumulative_budget', params: { amount: 10000, currency: 'USD' } }],
    });
    const handler = server.protect(
      { permission: 'tg.wallet.charge', amount: { amount: 6000, currency: 'USD' } },
      () => {
        throw new Error('downstream failed');
      },
    );
    const failed = await handler(await signedRequest(grant.token));
    assert.equal(failed.status, 500);
    const retry = await handler(await signedRequest(grant.token));
    assert.equal(retry.status, 500);
    const ledger = server.config.stores.ledger;
    assert.equal(await ledger.consumedMinorUnits(grant.jti, 'USD'), 0);
    assert.equal(await ledger.reservedMinorUnits(grant.jti, 'USD'), 0);
  });

  it('returns the stored outcome on an idempotent retry', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    let calls = 0;
    const handler = server.protect({ permission: 'tg.order.create' }, () => {
      calls += 1;
      return { status: 200, body: { ok: true, call: calls } };
    });
    const key = randomIdem();
    const first = await handler(await signedRequest(grant.token, { idempotencyKey: key }));
    assert.equal(first.status, 200);
    const second = await handler(await signedRequest(grant.token, { idempotencyKey: key }));
    assert.equal(second.status, 200);
    assert.deepEqual(second.body, first.body);
    assert.equal(calls, 1);
  });

  it('detects an idempotency conflict on a different body', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const key = randomIdem();
    await handler(await signedRequest(grant.token, { idempotencyKey: key, body: '{"a":1}' }));
    const conflict = await handler(
      await signedRequest(grant.token, { idempotencyKey: key, body: '{"a":2}' }),
    );
    assert.equal(conflict.status, 409);
    assert.equal(errorCode(conflict), Codes.REQUEST_IDEMPOTENCY_CONFLICT);
  });

  it('answers in_flight when a matching claim is still pending', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const key = randomIdem();
    const req = await signedRequest(grant.token, { idempotencyKey: key });
    // Simulate a concurrent request whose claim landed but has not completed.
    const claim = await server.config.stores.idempotency.claim(
      grant.jti,
      key,
      operationDigestOf(req, grant.jti),
    );
    assert.equal(claim.kind, 'claimed');
    const res = await handler(req);
    assert.equal(res.status, 409);
    assert.equal(errorCode(res), Codes.REQUEST_IDEMPOTENCY_IN_FLIGHT);
  });

  it('rejects oversized requests before verification', async () => {
    const server = makeServer({ maxBodyBytes: 1024 });
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const req = await signedRequest(grant.token, { body: 'x'.repeat(4096) });
    const res = await handler(req);
    assert.equal(res.status, 413);
    assert.equal(errorCode(res), Codes.REQUEST_TOO_LARGE);
  });

  it('enforces spend_window end to end through the reserve path', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, {
      permissions: ['tg.wallet.charge'],
      constraints: [
        { type: 'spend_window', params: { amount: 5000, currency: 'USD', window_seconds: 3600 } },
      ],
    });
    const charge = server.protect(
      {
        permission: 'tg.wallet.charge',
        amount: { amount: 4000, currency: 'USD' },
      },
      okHandler,
    );
    assert.equal((await charge(await signedRequest(grant.token))).status, 200);
    const second = await charge(await signedRequest(grant.token));
    assert.equal(errorCode(second), Codes.CONSTRAINT_VIOLATED);
  });

  it('enforces resource scope and cross-user isolation', async () => {
    const server = makeServer({
      resourceOwners: {
        ownerOf: async (selector) =>
          selector === 'cart:cart_1' || selector === 'cart:cart_9' ? 'user_1' : 'user_2',
      },
    });
    const grant = await issueGrant(server, {
      permissions: ['tg.cart.read'],
      resources: ['cart:cart_1', 'cart:cart_2'],
      subject: 'user_1',
    });
    const own = server.protect({ permission: 'tg.cart.read', resource: 'cart:cart_1' }, okHandler);
    assert.equal((await own(await signedRequest(grant.token))).status, 200);

    const otherUsers = server.protect(
      { permission: 'tg.cart.read', resource: 'cart:cart_2' },
      okHandler,
    );
    const crossUser = await otherUsers(await signedRequest(grant.token));
    assert.equal(errorCode(crossUser), Codes.REQUEST_RESOURCE_DENIED);

    const unlisted = server.protect(
      { permission: 'tg.cart.read', resource: 'cart:cart_9' },
      okHandler,
    );
    const outside = await unlisted(await signedRequest(grant.token));
    assert.equal(errorCode(outside), Codes.REQUEST_RESOURCE_DENIED);
  });

  it('denies when site policy rejects the request', async () => {
    const server = makeServer({
      policy: {
        authorize: async () => {
          throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'blocked by site rules');
        },
      },
    });
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(res), Codes.AUTHORIZATION_DENIED);
  });
});

describe('forged and tampered requests', () => {
  async function forgedGrant(overrides: Parameters<typeof makeGrantPayload>[0]) {
    const payload = makeGrantPayload({
      jkt: agent.jkt,
      issuer: ISSUER,
      audience: ISSUER,
      permissions: ['tg.order.create'],
      ...overrides,
    });
    return signCompactJws(payload, {
      privateJwk: site.privateJwk,
      kid: site.jkt,
      typ: 'trailgate-grant+jwt',
    });
  }

  function serverWithAgentKey() {
    const server = makeServer();
    return server;
  }

  it('rejects a grant issued for a different audience', async () => {
    const server = serverWithAgentKey();
    const token = await forgedGrant({ audience: 'https://other.example.com' });
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(token));
    assert.equal(errorCode(res), Codes.REQUEST_AUDIENCE_MISMATCH);
  });

  it('rejects an expired grant', async () => {
    const server = serverWithAgentKey();
    const token = await forgedGrant({ iat: NOW - 4000, exp: NOW - 10 });
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(token));
    assert.equal(errorCode(res), Codes.GRANT_EXPIRED);
  });

  it('rejects a grant carrying an unevaluable constraint type', async () => {
    const server = serverWithAgentKey();
    await server.config.stores.agentKeys.register(agent.jkt, agent.publicJwk);
    const token = await forgedGrant({ constraints: [{ type: 'geo_fence', params: {} }] });
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(token));
    assert.equal(errorCode(res), Codes.CONSTRAINT_UNKNOWN_TYPE);
  });

  it('rejects a tampered body as a digest mismatch', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const req = await signedRequest(grant.token, { body: '{"amount":1}' });
    req.body = '{"amount":999999}';
    const res = await handler(req);
    assert.equal(errorCode(res), Codes.REQUEST_BODY_DIGEST_MISMATCH);
  });

  it('rejects a request missing required headers', async () => {
    const server = makeServer();
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler({
      method: 'POST',
      url: `${ISSUER}/orders`,
      headers: { 'trailgate-grant': 'eyJ.test.test' },
      body: '',
    });
    assert.equal(res.status, 400);
    assert.equal(errorCode(res), Codes.REQUEST_MALFORMED);
  });
});

describe('grant revocation endpoint', () => {
  it('lets a bound grant revoke itself via a signed request', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const body = JSON.stringify({ grant_id: grant.jti, reason: 'agent done' });
    const req = await signedRequest(grant.token, {
      url: `${ISSUER}/tg/grant-revocation`,
      body,
    });
    const res = await server.handleRevocation(req);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { grant_id: grant.jti, status: 'revoked' });
    assert.equal(await server.config.stores.grants.isRevoked(grant.jti), true);
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const after = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(after), Codes.GRANT_REVOKED);
  });

  it('denies revocation presenting a different grant', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const other = await issueGrant(server);
    const req = await signedRequest(grant.token, {
      url: `${ISSUER}/tg/grant-revocation`,
      body: JSON.stringify({ grant_id: other.jti }),
    });
    const res = await server.handleRevocation(req);
    assert.equal(errorCode(res), Codes.AUTHORIZATION_DENIED);
    assert.equal(await server.config.stores.grants.isRevoked(other.jti), false);
  });

  it('denies unsigned calls without a configured authorizer', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const res = await server.handleRevocation({
      method: 'POST',
      url: `${ISSUER}/tg/grant-revocation`,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ grant_id: grant.jti }),
    });
    assert.equal(errorCode(res), Codes.AUTHORIZATION_DENIED);
    assert.equal(await server.config.stores.grants.isRevoked(grant.jti), false);
  });

  it('answers tg.grant.unknown for unknown ids', async () => {
    const server = makeServer();
    const res = await server.handleStatus({
      method: 'GET',
      url: `${ISSUER}/tg/grant-status?grant_id=grt_missing`,
      headers: {},
    });
    assert.equal(errorCode(res), Codes.GRANT_UNKNOWN);
  });
});

describe('approval_threshold lifecycle', () => {
  const ABOVE = { amount: 6_500, currency: 'USD' };

  async function thresholdGrant(server: TrailGateServer) {
    return issueGrant(server, {
      permissions: ['tg.wallet.charge'],
      constraints: [
        { type: 'approval_threshold', params: { amount: 5_000, currency: 'USD' } },
        { type: 'cumulative_budget', params: { amount: 40_000, currency: 'USD' } },
      ],
    });
  }

  function approvalIdOf(res: HostResponse): string {
    const detail = (res.body as { error?: { detail?: { approval_id?: string } } }).error?.detail;
    assert.ok(detail?.approval_id !== undefined, 'expected an approval_id in the denial');
    return detail.approval_id;
  }

  it('denies above the threshold with a decision surface, then executes once approved', async () => {
    const server = makeServer();
    const grant = await thresholdGrant(server);
    const handler = server.protect({ permission: 'tg.wallet.charge', amount: ABOVE }, okHandler);

    const blocked = await handler(await signedRequest(grant.token));
    assert.equal(blocked.status, 403);
    assert.equal(errorCode(blocked), Codes.CONSTRAINT_APPROVAL_REQUIRED);
    const detail = (blocked.body as { error?: { detail?: Record<string, unknown> } }).error?.detail;
    assert.ok(typeof detail?.['approval_url'] === 'string');
    assert.ok((detail['approval_url'] as string).startsWith(`${ISSUER}/`));
    const approvalId = approvalIdOf(blocked);

    // Another subject cannot decide for this grant's owner.
    await assert.rejects(
      server.decideRequestApproval(approvalId, 'approve', 'user_2'),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.AUTHORIZATION_DENIED,
    );

    await server.decideRequestApproval(approvalId, 'approve', 'user_1');
    const paid = await handler(await signedRequest(grant.token));
    assert.equal(paid.status, 200);

    // Single use: the same operation needs a fresh human decision.
    const again = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(again), Codes.CONSTRAINT_APPROVAL_REQUIRED);
  });

  it('two concurrent requests cannot spend one approval', async () => {
    const server = makeServer();
    const grant = await thresholdGrant(server);
    let calls = 0;
    const handler = server.protect({ permission: 'tg.wallet.charge', amount: ABOVE }, () => {
      calls += 1;
      return { status: 200, body: { ok: true } };
    });

    const blocked = await handler(await signedRequest(grant.token));
    await server.decideRequestApproval(approvalIdOf(blocked), 'approve', 'user_1');

    // Race two signed requests carrying the same operation digest: both pass
    // the constraint peek, but consumeApproved only flips one.
    const [a, b] = await Promise.all([
      handler(await signedRequest(grant.token)),
      handler(await signedRequest(grant.token)),
    ]);
    const statuses = [a.status, b.status].sort();
    assert.deepEqual(statuses, [200, 403]);
    assert.equal(calls, 1);
  });

  it('a failed handler restores the approval for retry', async () => {
    const server = makeServer();
    const grant = await thresholdGrant(server);
    let failOnce = true;
    const handler = server.protect({ permission: 'tg.wallet.charge', amount: ABOVE }, () => {
      if (failOnce) {
        failOnce = false;
        throw new Error('downstream failed');
      }
      return { status: 200, body: { ok: true } };
    });

    const blocked = await handler(await signedRequest(grant.token));
    await server.decideRequestApproval(approvalIdOf(blocked), 'approve', 'user_1');

    const failed = await handler(await signedRequest(grant.token));
    assert.equal(failed.status, 500);
    // The human decision survives the failure: the retry runs without a
    // second trip to the approval page.
    const retry = await handler(await signedRequest(grant.token));
    assert.equal(retry.status, 200);
  });

  it('a denied approval never executes, and revocation still wins over an approval', async () => {
    const server = makeServer();
    const grant = await thresholdGrant(server);
    const handler = server.protect({ permission: 'tg.wallet.charge', amount: ABOVE }, okHandler);

    const blocked = await handler(await signedRequest(grant.token));
    await server.decideRequestApproval(approvalIdOf(blocked), 'deny', 'user_1');
    const retry = await handler(await signedRequest(grant.token));
    assert.equal(retry.status, 403);
    assert.equal(errorCode(retry), Codes.CONSTRAINT_APPROVAL_REQUIRED);

    await server.decideRequestApproval(approvalIdOf(retry), 'approve', 'user_1');
    await server.revokeGrant(grant.jti, { reason: 'test', actor: 'user_1' });
    const revoked = await handler(await signedRequest(grant.token));
    assert.equal(errorCode(revoked), Codes.GRANT_REVOKED);
  });
});

describe('store failure fails closed', () => {
  it('a dead audit sink denies rather than skipping accountability', async () => {
    let down = false;
    let seq = 0;
    const audit = {
      record: async () => {
        if (down) {
          throw new Error('audit store down');
        }
        seq += 1;
        return `evt_${seq}`;
      },
    };
    const server = makeServer({ stores: { audit } });
    const grant = await issueGrant(server, {
      permissions: ['tg.order.create'],
    });
    down = true;
    // The protected request must not proceed unrecorded.
    const handler = server.protect({ permission: 'tg.order.create' }, okHandler);
    const res = await handler(await signedRequest(grant.token));
    assert.notEqual(res.status, 200);
    assert.equal(errorCode(res), Codes.INTERNAL_UNAVAILABLE);
  });
});
