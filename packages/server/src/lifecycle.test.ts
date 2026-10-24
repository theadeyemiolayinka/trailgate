import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { Codes, TrailGateError, verifyGrant } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import type { TrailGateServerOptions } from './config.ts';
import { createTrailGateServer } from './server.ts';
import type { HostRequest } from './types.ts';

const ISSUER = 'https://shop.example.com';
const NOW = 1_700_000_000;

const site = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();

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
    clock: overrides.clock ?? { now: () => NOW },
    ...overrides,
  });
}

function grantRequestBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: '0.1',
    permissions: ['tg.order.create'],
    resources: [],
    constraints: [],
    agent_key: agent.publicJwk,
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
    ...overrides,
  };
}

function post(url: string, body: unknown): HostRequest {
  return {
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  };
}

function get(url: string): HostRequest {
  return { method: 'GET', url, headers: {} };
}

async function assertCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (err: unknown) => {
    assert.ok(err instanceof TrailGateError, `expected TrailGateError, got ${String(err)}`);
    assert.equal(err.code, code);
    return true;
  });
}

describe('grant request intake', () => {
  it('accepts a valid request and returns request_id, consent_url, expires_at', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
    );
    assert.equal(res.status, 201);
    const body = res.body as { request_id: string; consent_url: string; expires_at: number };
    assert.ok(body.request_id.startsWith('req_'));
    assert.ok(body.consent_url.startsWith(`${ISSUER}/tg/consent?request_id=`));
    assert.equal(body.expires_at, NOW + 900);
  });

  it('rejects malformed bodies with tg.request.malformed', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, { version: '0.1' }),
    );
    assert.equal(res.status, 400);
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.REQUEST_MALFORMED);
  });

  it('rejects unknown permissions with tg.grant.unknown_permission', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ permissions: ['tg.admin.delete'] })),
    );
    assert.equal(res.status, 400);
    assert.equal(
      (res.body as { error: { code: string } }).error.code,
      Codes.GRANT_UNKNOWN_PERMISSION,
    );
  });

  it('rejects constraint types outside the site list with tg.grant.scope_rejected', async () => {
    const server = makeServer({ constraintTypes: ['max_amount'] });
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({
          constraints: [{ type: 'rate_limit', params: { max_requests: 1, window_seconds: 60 } }],
        }),
      ),
    );
    assert.equal(res.status, 403);
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.GRANT_SCOPE_REJECTED);
  });

  it('rejects unsupported protocol versions', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ version: '9.9' })),
    );
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.GRANT_SCOPE_REJECTED);
  });

  it('rejects a malformed agent key', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({ agent_key: { kty: 'OKP', crv: 'Ed25519' } }),
      ),
    );
    assert.equal(res.status, 400);
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.REQUEST_MALFORMED);
  });

  it('lets the host reject out-of-namespace resources via resourcePolicy', async () => {
    const server = makeServer({
      resourcePolicy: (selectors) => {
        if (selectors.some((s) => !s.startsWith('cart:'))) {
          throw new TrailGateError(Codes.GRANT_SCOPE_REJECTED, 'outside cart namespace');
        }
      },
    });
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ resources: ['account:me'] })),
    );
    assert.equal((res.body as { error: { code: string } }).error.code, Codes.GRANT_SCOPE_REJECTED);
  });
});

describe('consent decisions', () => {
  async function pendingRequest(server: ReturnType<typeof makeServer>) {
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
    );
    return (res.body as { request_id: string }).request_id;
  }

  it('renders the stored terms verbatim for the consent page', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({
          permissions: ['tg.order.create', 'tg.cart.read'],
          resources: ['cart:cart_1'],
          constraints: [{ type: 'max_amount', params: { amount: 5000, currency: 'USD' } }],
          requested_seconds: 600,
        }),
      ),
    );
    const view = await server.getConsent((res.body as { request_id: string }).request_id);
    assert.ok(view !== undefined);
    assert.deepEqual(view.requested.permissions, ['tg.order.create', 'tg.cart.read']);
    assert.deepEqual(view.requested.resources, ['cart:cart_1']);
    assert.equal(view.requested.requestedSeconds, 600);
    assert.equal(view.effective.lifetimeSeconds, 600);
    assert.equal(view.agentJkt, agent.jkt);
    assert.equal(view.status, 'pending');
  });

  it('approving without an authenticated user is denied', async () => {
    const server = makeServer();
    const requestId = await pendingRequest(server);
    await assertCode(server.decideConsent(requestId, 'approve'), Codes.AUTHORIZATION_DENIED);
  });

  it('records approval and denial as terminal decisions', async () => {
    const server = makeServer();
    const requestId = await pendingRequest(server);
    const outcome = await server.decideConsent(requestId, 'deny');
    assert.equal(outcome.decision, 'denied');
    await assertCode(server.decideConsent(requestId, 'approve', 'user_1'), Codes.REQUEST_MALFORMED);
  });

  it('builds the redirect target with request_id and state', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({
          redirect_uri: 'https://agent.example.com/callback',
          state: 'xyz-123',
        }),
      ),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    const outcome = await server.decideConsent(requestId, 'approve', 'user_1');
    const target = new URL(outcome.redirectTo as string);
    assert.equal(target.origin, 'https://agent.example.com');
    assert.equal(target.pathname, '/callback');
    assert.equal(target.searchParams.get('request_id'), requestId);
    assert.equal(target.searchParams.get('state'), 'xyz-123');
  });

  it('binds {user} selector templates to the approving subject at consent', async () => {
    const server = makeServer({
      bindSubjectResources: (resources, subject) =>
        resources.map((r) => (r === 'cart:{user}' ? `cart:cart_${subject}` : r)),
    });
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({ resources: ['cart:{user}', 'wallet:wlt_1'] }),
      ),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    const { verifier } = pkce();
    void verifier;
    await server.decideConsent(requestId, 'approve', 'user_1');
    const view = await server.getConsent(requestId);
    assert.deepEqual(view?.effective.resources, ['cart:cart_user_1', 'wallet:wlt_1']);
  });

  it('rejects bound resources that do not derive from the requested scope', async () => {
    const server = makeServer({
      bindSubjectResources: () => ['vault:vlt_other_user'],
    });
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ resources: ['cart:{user}'] })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await assertCode(server.decideConsent(requestId, 'approve', 'user_1'), Codes.INTERNAL_ERROR);
  });

  it('narrows effective scope when the user unchecks permissions at consent', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({ permissions: ['tg.order.create', 'tg.cart.read'] }),
      ),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1', {
      permissions: ['tg.cart.read'],
    });
    const view = await server.getConsent(requestId);
    assert.deepEqual(view?.effective.permissions, ['tg.cart.read']);
    assert.deepEqual(view?.requested.permissions, ['tg.order.create', 'tg.cart.read']);
  });

  it('rejects a consent narrow that is not a subset of the requested scope', async () => {
    const server = makeServer();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ permissions: ['tg.order.create'] })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await assertCode(
      server.decideConsent(requestId, 'approve', 'user_1', {
        permissions: ['tg.order.create', 'tg.admin.all'],
      }),
      Codes.REQUEST_MALFORMED,
    );
  });

  it('lets the consenting user extend the grant lifetime up to the consent cap', async () => {
    const server = makeServer({ maxGrantSeconds: 86_400, maxConsentLifetimeSeconds: 2_592_000 });
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    const view = await server.getConsent(requestId);
    assert.equal(view?.lifetimeCapSeconds, 2_592_000);
    await server.decideConsent(requestId, 'approve', 'user_1', { lifetimeSeconds: 2_592_000 });
    const after = await server.getConsent(requestId);
    assert.equal(after?.effective.lifetimeSeconds, 2_592_000);
  });

  it('clamps a consent-chosen lifetime to the consent cap, which defaults to maxGrantSeconds', async () => {
    const server = makeServer({ maxGrantSeconds: 86_400 });
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1', {
      lifetimeSeconds: 9_999_999,
    });
    const view = await server.getConsent(requestId);
    assert.equal(view?.effective.lifetimeSeconds, 86_400);
  });

  it('issues a grant whose exp reflects the consent-chosen lifetime', async () => {
    const server = makeServer({ maxConsentLifetimeSeconds: 2_592_000 });
    const { verifier, challenge } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1', { lifetimeSeconds: 604_800 });
    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal(redeemed.status, 200);
    const token = (redeemed.body as { grant: string }).grant;
    const payload = await verifyGrant(token, {
      resolveSiteKey: { resolve: async () => site.publicJwk },
      issuer: ISSUER,
      audience: ISSUER,
      now: NOW,
    });
    assert.equal(payload.exp, NOW + 604_800);
  });

  it('rejects a non-positive or non-integer consent lifetime', async () => {
    const server = makeServer();
    for (const bad of [0, -5, 1.5]) {
      const res = await server.handleGrantRequest(
        post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
      );
      const requestId = (res.body as { request_id: string }).request_id;
      await assertCode(
        server.decideConsent(requestId, 'approve', 'user_1', { lifetimeSeconds: bad }),
        Codes.REQUEST_MALFORMED,
      );
    }
  });

  it('rate limits an agent key that floods grant requests', async () => {
    const server = makeServer({ maxPendingRequestsPerAgent: 2, maxGrantRequestsPerMinute: 10 });
    await server.handleGrantRequest(post(`${ISSUER}/tg/grant-request`, grantRequestBody()));
    await server.handleGrantRequest(post(`${ISSUER}/tg/grant-request`, grantRequestBody()));
    const third = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody()),
    );
    assert.equal(third.status, 429);
    assert.equal(
      (third.body as { error: { code: string } }).error.code,
      Codes.REQUEST_RATE_LIMITED,
    );
    // Deciding the pending requests frees the agent's quota.
    const page = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: pkce().challenge })),
    );
    assert.equal(page.status, 429);
  });

  it('refines scope through the configured hook and enforces subset rules', async () => {
    const server = makeServer({
      refineScope: (requested) => ({
        permissions: requested.permissions.slice(0, 1),
        resources: requested.resources,
        constraints: requested.constraints,
        lifetimeSeconds: 120,
      }),
    });
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({ permissions: ['tg.order.create', 'tg.cart.read'] }),
      ),
    );
    const view = await server.getConsent((res.body as { request_id: string }).request_id);
    assert.deepEqual(view?.effective.permissions, ['tg.order.create']);
    assert.equal(view?.effective.lifetimeSeconds, 120);
  });
});

describe('redemption', () => {
  async function approvedRequest(server: ReturnType<typeof makeServer>) {
    const { verifier, challenge } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1');
    return { requestId, verifier };
  }

  it('issues a verifiable grant JWT bound to the agent key', async () => {
    const server = makeServer();
    const { requestId, verifier } = await approvedRequest(server);
    const res = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal(res.status, 200);
    const token = (res.body as { grant: string }).grant;
    const payload = await verifyGrant(token, {
      resolveSiteKey: { resolve: async () => site.publicJwk },
      issuer: ISSUER,
      audience: ISSUER,
      now: NOW,
    });
    assert.equal(payload.cnf.jkt, agent.jkt);
    assert.equal(payload.sub, 'user_1');
    assert.deepEqual(payload.tg.permissions, ['tg.order.create']);
    assert.equal(payload.tg.request_id, requestId);
  });

  it('rejects a wrong verifier and double redemption', async () => {
    const server = makeServer();
    const { requestId, verifier } = await approvedRequest(server);
    const bad = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, {
        request_id: requestId,
        code_verifier: 'wrong-verifier',
      }),
    );
    assert.equal((bad.body as { error: { code: string } }).error.code, Codes.AUTHORIZATION_DENIED);
    const first = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal(first.status, 200);
    const second = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal((second.body as { error: { code: string } }).error.code, Codes.GRANT_REDEEMED);
  });

  it('denies redemption of a pending request', async () => {
    const server = makeServer();
    const { challenge, verifier } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal(
      (redeemed.body as { error: { code: string } }).error.code,
      Codes.AUTHORIZATION_DENIED,
    );
  });

  it('denies redemption after consent denial', async () => {
    const server = makeServer();
    const { challenge, verifier } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'deny');
    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal(
      (redeemed.body as { error: { code: string } }).error.code,
      Codes.GRANT_CONSENT_DENIED,
    );
  });

  it('expires the request past its deadline', async () => {
    const state = { t: NOW };
    const server = makeServer({ clock: { now: () => state.t } });
    const { challenge, verifier } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1');
    state.t = NOW + 901;
    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    assert.equal((redeemed.body as { error: { code: string } }).error.code, Codes.GRANT_EXPIRED);
  });
});

describe('status and revocation', () => {
  it('reports pending, then active after redemption, then revoked', async () => {
    const server = makeServer();
    const { verifier, challenge } = pkce();
    const res = await server.handleGrantRequest(
      post(`${ISSUER}/tg/grant-request`, grantRequestBody({ code_challenge: challenge })),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    let status = await server.handleStatus(
      get(`${ISSUER}/tg/grant-status?request_id=${requestId}`),
    );
    assert.equal((status.body as { status: string }).status, 'pending');

    await server.decideConsent(requestId, 'approve', 'user_1');
    status = await server.handleStatus(get(`${ISSUER}/tg/grant-status?request_id=${requestId}`));
    assert.equal((status.body as { status: string }).status, 'approved');

    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    const token = (redeemed.body as { grant: string }).grant;
    const jti = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8'))
      .jti as string;

    status = await server.handleStatus(get(`${ISSUER}/tg/grant-status?request_id=${requestId}`));
    assert.equal((status.body as { status: string }).status, 'active');
    status = await server.handleStatus(get(`${ISSUER}/tg/grant-status?grant_id=${jti}`));
    assert.equal((status.body as { status: string }).status, 'active');

    await server.revokeGrant(jti, { reason: 'user requested', actor: 'user_1' });
    status = await server.handleStatus(get(`${ISSUER}/tg/grant-status?grant_id=${jti}`));
    assert.equal((status.body as { status: string }).status, 'revoked');
  });
});

describe('post-issuance scope changes', () => {
  async function issuedJti(
    server: ReturnType<typeof makeServer>,
    permissions = ['tg.order.create', 'tg.cart.read'],
  ): Promise<string> {
    const { verifier, challenge } = pkce();
    const res = await server.handleGrantRequest(
      post(
        `${ISSUER}/tg/grant-request`,
        grantRequestBody({ code_challenge: challenge, permissions }),
      ),
    );
    const requestId = (res.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1');
    const redeemed = await server.handleRedemption(
      post(`${ISSUER}/tg/grant-redemption`, { request_id: requestId, code_verifier: verifier }),
    );
    const token = (redeemed.body as { grant: string }).grant;
    return JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8'))
      .jti as string;
  }

  it('narrows the effective set without touching the signed grant', async () => {
    const server = makeServer();
    const jti = await issuedJti(server);
    const narrowed = await server.updateGrantScope(jti, {
      permissions: ['tg.cart.read'],
      actor: 'user:user_1',
    });
    assert.deepEqual(narrowed.effectivePermissions, ['tg.cart.read']);
    // The issued set is unchanged; effectivePermissions is the live scope.
    assert.deepEqual(narrowed.permissions, ['tg.order.create', 'tg.cart.read']);
  });

  it('lets the site add a permission from its own vocabulary later', async () => {
    const server = makeServer();
    const jti = await issuedJti(server, ['tg.cart.read']);
    const grown = await server.updateGrantScope(jti, {
      permissions: ['tg.cart.read', 'tg.wallet.charge'],
      actor: 'user:user_1',
    });
    assert.deepEqual(grown.effectivePermissions, ['tg.cart.read', 'tg.wallet.charge']);
    // The signed grant still records what consent originally approved.
    assert.deepEqual(grown.permissions, ['tg.cart.read']);
  });

  it('refuses scope outside the vocabulary, an empty set, or a revoked grant', async () => {
    const server = makeServer();
    const jti = await issuedJti(server);
    await assertCode(
      server.updateGrantScope(jti, {
        permissions: ['tg.cart.read', 'tg.admin.all'],
        actor: 'user:user_1',
      }),
      Codes.REQUEST_MALFORMED,
    );
    await assertCode(
      server.updateGrantScope(jti, { permissions: [], actor: 'user:user_1' }),
      Codes.REQUEST_MALFORMED,
    );
    await server.revokeGrant(jti, { reason: 'test', actor: 'user_1' });
    await assertCode(
      server.updateGrantScope(jti, { permissions: ['tg.cart.read'], actor: 'user:user_1' }),
      Codes.GRANT_UNKNOWN,
    );
  });

  it('applies the site resourcePolicy to scope updates, same as intake', async () => {
    const server = makeServer({
      resourcePolicy: (selectors) => {
        const bad = selectors.filter((s) => !s.startsWith('cart:'));
        if (bad.length > 0) {
          throw new TrailGateError(Codes.GRANT_SCOPE_REJECTED, 'selector outside namespace');
        }
      },
    });
    const jti = await issuedJti(server);
    const ok = await server.updateGrantScope(jti, {
      permissions: ['tg.cart.read'],
      resources: ['cart:user_1'],
      actor: 'user:user_1',
    });
    assert.deepEqual(ok.effectiveResources, ['cart:user_1']);
    await assertCode(
      server.updateGrantScope(jti, {
        permissions: ['tg.cart.read'],
        resources: ['wallet:user_1'],
        actor: 'user:user_1',
      }),
      Codes.GRANT_SCOPE_REJECTED,
    );
    await assertCode(
      server.updateGrantScope(jti, {
        permissions: ['tg.cart.read'],
        resources: ['cart:user_1', 42] as unknown as string[],
        actor: 'user:user_1',
      }),
      Codes.REQUEST_MALFORMED,
    );
  });
});
