import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import type { Jwk } from '@trailgate/core';
import { Codes, signRequest } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import type { TrailGateServerOptions } from './config.ts';
import type { TrailGateServer } from './server.ts';
import { createTrailGateServer } from './server.ts';
import type { HostRequest, HostResponse } from './types.ts';

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
    signingKeys: [{ privateJwk: site.privateJwk as Jwk }],
    permissions: ['tg.order.create', 'tg.wallet.charge'],
    clock: { now: () => NOW },
    ...overrides,
  });
}

async function issueGrant(
  server: TrailGateServer,
  constraints: Record<string, unknown>[] = [],
): Promise<{ token: string; jti: string }> {
  const { verifier, challenge } = pkce();
  const created = await server.handleGrantRequest({
    method: 'POST',
    url: `${ISSUER}/tg/grant-request`,
    headers: {},
    body: JSON.stringify({
      version: '0.1',
      permissions: ['tg.wallet.charge'],
      resources: [],
      constraints,
      agent_key: agent.publicJwk,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }),
  });
  assert.equal(created.status, 201);
  const requestId = (created.body as { request_id: string }).request_id;
  await server.decideConsent(requestId, 'approve', 'user_1');
  const redeemed = await server.handleRedemption({
    method: 'POST',
    url: `${ISSUER}/tg/grant-redemption`,
    headers: {},
    body: JSON.stringify({ request_id: requestId, code_verifier: verifier }),
  });
  const token = (redeemed.body as { grant: string }).grant;
  const jti = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8'))
    .jti as string;
  return { token, jti };
}

async function signedRequest(grant: string, nonce?: string): Promise<HostRequest> {
  const headers = await signRequest(
    { method: 'POST', url: `${ISSUER}/charge`, body: new TextEncoder().encode('{}') },
    {
      privateJwk: agent.privateJwk as Jwk,
      keyid: agent.jkt,
      nonce: nonce ?? randomBytes(16).toString('base64url'),
      created: NOW,
      expires: NOW + 60,
      grant,
      idempotencyKey: `idem_${randomBytes(12).toString('base64url')}`,
    },
  );
  return { method: 'POST', url: `${ISSUER}/charge`, headers, body: '{}' };
}

function code(res: HostResponse): string | undefined {
  return (res.body as { error?: { code?: string } }).error?.code;
}

describe('concurrency safety', () => {
  it('never overspends under concurrent spending requests', async () => {
    const server = makeServer();
    const grant = await issueGrant(server, [
      { type: 'cumulative_budget', params: { amount: 10000, currency: 'USD' } },
    ]);
    let succeeded = 0;
    const handler = server.protect(
      { permission: 'tg.wallet.charge', amount: { amount: 4000, currency: 'USD' } },
      () => {
        succeeded += 1;
        return { status: 200, body: { ok: true } };
      },
    );
    const requests = await Promise.all(Array.from({ length: 5 }, () => signedRequest(grant.token)));
    const results = await Promise.all(requests.map((req) => handler(req)));
    const allowed = results.filter((res) => res.status === 200);
    const denied = results.filter((res) => code(res) === Codes.CONSTRAINT_VIOLATED);
    assert.equal(allowed.length, 2, 'exactly two 4000-charges fit a 10000 budget');
    assert.equal(denied.length, 3);
    assert.equal(succeeded, 2);
    assert.equal(await server.config.stores.ledger.consumedMinorUnits(grant.jti, 'USD'), 8000);
  });

  it('redeems a grant request exactly once under parallel redemptions', async () => {
    const server = makeServer();
    const { verifier, challenge } = pkce();
    const created = await server.handleGrantRequest({
      method: 'POST',
      url: `${ISSUER}/tg/grant-request`,
      headers: {},
      body: JSON.stringify({
        version: '0.1',
        permissions: ['tg.wallet.charge'],
        resources: [],
        constraints: [],
        agent_key: agent.publicJwk,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      }),
    });
    const requestId = (created.body as { request_id: string }).request_id;
    await server.decideConsent(requestId, 'approve', 'user_1');
    const attempts = await Promise.all(
      Array.from({ length: 4 }, () =>
        server.handleRedemption({
          method: 'POST',
          url: `${ISSUER}/tg/grant-redemption`,
          headers: {},
          body: JSON.stringify({ request_id: requestId, code_verifier: verifier }),
        }),
      ),
    );
    const wins = attempts.filter((res) => res.status === 200);
    const redeemed = attempts.filter((res) => code(res) === Codes.GRANT_REDEEMED);
    assert.equal(wins.length, 1);
    assert.equal(redeemed.length, 3);
  });

  it('rejects a nonce reused across parallel requests', async () => {
    const server = makeServer();
    const grant = await issueGrant(server);
    const handler = server.protect({ permission: 'tg.wallet.charge' }, () => ({
      status: 200,
      body: { ok: true },
    }));
    const nonce = randomBytes(16).toString('base64url');
    const requests = await Promise.all([
      signedRequest(grant.token, nonce),
      signedRequest(grant.token, nonce),
      signedRequest(grant.token),
    ]);
    const results = await Promise.all(requests.map((req) => handler(req)));
    const allowed = results.filter((res) => res.status === 200);
    const replays = results.filter((res) => code(res) === Codes.REQUEST_REPLAY_DETECTED);
    assert.equal(allowed.length, 2);
    assert.equal(replays.length, 1);
  });
});
