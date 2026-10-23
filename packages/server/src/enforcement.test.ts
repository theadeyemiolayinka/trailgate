import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import type { Jwk, KeyResolver } from '@trailgate/core';
import { Codes, signRequest, TrailGateError, verifyReceipt } from '@trailgate/core';
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
