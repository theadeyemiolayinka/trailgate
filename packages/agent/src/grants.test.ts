import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import type { DiscoveryDocument } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import { makeDiscovery } from '@trailgate/test-fixtures';
import type { SiteContext } from './discovery.ts';
import {
  awaitConsentDecision,
  buildGrantRequestBody,
  codeChallengeFor,
  fetchGrantStatus,
  generateCodeVerifier,
  redeemGrantRequest,
  submitGrantRequest,
} from './grants.ts';
import { fakeTransport, jsonResponse, requestJson } from './helpers.test.ts';
import { SoftwareKeyProvider } from './keys.ts';

const ORIGIN = 'https://shop.example.com';

function site(overrides: Record<string, unknown> = {}): SiteContext {
  return {
    origin: ORIGIN,
    issuer: ORIGIN,
    protocolVersion: '0.1',
    document: makeDiscovery(overrides) as DiscoveryDocument,
    fetchedAt: 0,
    cacheMaxAgeSeconds: 3600,
  };
}

function expectTgError(err: unknown, code: string): boolean {
  return err instanceof TrailGateError && err.code === code;
}

describe('PKCE material', () => {
  it('derives the S256 challenge from the verifier', () => {
    const verifier = generateCodeVerifier();
    assert.equal(verifier.length, 43);
    const expected = createHash('sha256').update(verifier, 'utf8').digest().toString('base64url');
    assert.equal(codeChallengeFor(verifier), expected);
    assert.equal(codeChallengeFor(verifier).length, 43);
  });
});

describe('buildGrantRequestBody', () => {
  it('produces the spec section 10.2 shape with a public key only', () => {
    const signer = SoftwareKeyProvider.generate();
    const body = buildGrantRequestBody(
      '0.1',
      {
        permissions: ['tg.order.create'],
        resources: ['order:ord_1'],
        constraints: [{ type: 'max_amount', params: { amount: 500, currency: 'USD' } }],
        redirectUri: 'https://agent.example.com/cb',
        state: 'opaque-state',
        requestedSeconds: 600,
      },
      signer,
      'test-verifier',
    );
    assert.equal(body.version, '0.1');
    assert.deepEqual(body.permissions, ['tg.order.create']);
    assert.deepEqual(body.resources, ['order:ord_1']);
    assert.equal(body.agent_key, signer.publicJwk);
    assert.equal(body.agent_key.d, undefined, 'private key material must never be sent');
    assert.equal(body.code_challenge, codeChallengeFor('test-verifier'));
    assert.equal(body.code_challenge_method, 'S256');
    assert.equal(body.redirect_uri, 'https://agent.example.com/cb');
    assert.equal(body.state, 'opaque-state');
    assert.equal(body.requested_seconds, 600);
  });

  it('defaults optional arrays to empty', () => {
    const signer = SoftwareKeyProvider.generate();
    const body = buildGrantRequestBody('0.1', { permissions: ['tg.cart.read'] }, signer, 'v');
    assert.deepEqual(body.resources, []);
    assert.deepEqual(body.constraints, []);
    assert.equal(body.redirect_uri, undefined);
    assert.equal(body.state, undefined);
  });
});

describe('submitGrantRequest', () => {
  it('posts the body and returns the consent session', async () => {
    const ctx = site();
    const { transport, requests } = fakeTransport(() =>
      jsonResponse(201, {
        request_id: 'req_123',
        consent_url: `${ORIGIN}/tg/consent?request_id=req_123`,
        expires_at: 1700000900,
      }),
    );
    const signer = SoftwareKeyProvider.generate();
    const body = buildGrantRequestBody('0.1', { permissions: ['tg.order.create'] }, signer, 'v');
    const session = await submitGrantRequest(ctx, body, transport);
    assert.equal(requests.length, 1);
    const req = requests[0];
    assert.equal(req?.method, 'POST');
    assert.equal(req?.url, `${ORIGIN}/tg/grant-request`);
    assert.equal(req?.headers?.['content-type'], 'application/json');
    assert.equal(requestJson(req as never)['code_challenge'], body.code_challenge);
    assert.equal(session.requestId, 'req_123');
    assert.equal(session.expiresAt, 1700000900);
  });

  it('rejects a consent_url outside the site origin', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() =>
      jsonResponse(201, {
        request_id: 'req_123',
        consent_url: 'https://evil.example.com/consent',
        expires_at: 1700000900,
      }),
    );
    const signer = SoftwareKeyProvider.generate();
    const body = buildGrantRequestBody('0.1', { permissions: ['tg.order.create'] }, signer, 'v');
    await assert.rejects(submitGrantRequest(ctx, body, transport), (err) =>
      expectTgError(err, Codes.REQUEST_MALFORMED),
    );
  });

  it('propagates site error codes', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() =>
      jsonResponse(400, {
        error: { code: 'tg.grant.unknown_permission', message: 'not in vocabulary' },
      }),
    );
    const signer = SoftwareKeyProvider.generate();
    const body = buildGrantRequestBody('0.1', { permissions: ['tg.nope.nope'] }, signer, 'v');
    await assert.rejects(submitGrantRequest(ctx, body, transport), (err) =>
      expectTgError(err, Codes.GRANT_UNKNOWN_PERMISSION),
    );
  });
});

describe('redeemGrantRequest', () => {
  it('posts request_id and code_verifier', async () => {
    const ctx = site();
    const { transport, requests } = fakeTransport(() =>
      jsonResponse(200, { grant: 'aaa.bbb.ccc' }),
    );
    const result = await redeemGrantRequest(ctx, 'req_123', 'the-verifier', transport);
    assert.equal(result.grant, 'aaa.bbb.ccc');
    const sent = requestJson(requests[0] as never);
    assert.equal(sent['request_id'], 'req_123');
    assert.equal(sent['code_verifier'], 'the-verifier');
  });

  it('surfaces tg.grant.redeemed on replay', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() =>
      jsonResponse(409, {
        error: { code: 'tg.grant.redeemed', message: 'already redeemed' },
      }),
    );
    await assert.rejects(redeemGrantRequest(ctx, 'req_123', 'v', transport), (err) =>
      expectTgError(err, Codes.GRANT_REDEEMED),
    );
  });
});

describe('fetchGrantStatus', () => {
  it('queries by request_id and parses the response', async () => {
    const ctx = site();
    const { transport, requests } = fakeTransport(() =>
      jsonResponse(200, { status: 'pending', expires_at: 1700000900 }),
    );
    const status = await fetchGrantStatus(ctx, { requestId: 'req_1' }, transport);
    assert.equal(status.status, 'pending');
    assert.equal(status.expires_at, 1700000900);
    const url = new URL(requests[0]?.url as string);
    assert.equal(url.searchParams.get('request_id'), 'req_1');
  });

  it('queries by grant_id', async () => {
    const ctx = site();
    const { transport, requests } = fakeTransport(() =>
      jsonResponse(200, { status: 'active', issued_at: 1, expires_at: 2 }),
    );
    const status = await fetchGrantStatus(ctx, { grantId: 'grt_1' }, transport);
    assert.equal(status.status, 'active');
    const url = new URL(requests[0]?.url as string);
    assert.equal(url.searchParams.get('grant_id'), 'grt_1');
  });

  it('requires one of request_id or grant_id', async () => {
    const ctx = site();
    const { transport, requests } = fakeTransport(() => jsonResponse(200, {}));
    await assert.rejects(fetchGrantStatus(ctx, {}, transport), (err) =>
      expectTgError(err, Codes.REQUEST_MALFORMED),
    );
    assert.equal(requests.length, 0);
  });

  it('rejects an unknown status value', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() => jsonResponse(200, { status: 'mysterious' }));
    await assert.rejects(fetchGrantStatus(ctx, { requestId: 'r' }, transport), (err) =>
      expectTgError(err, Codes.REQUEST_MALFORMED),
    );
  });
});

describe('awaitConsentDecision', () => {
  const instant = { intervalMs: 1, sleep: () => Promise.resolve() };

  it('resolves when the request becomes approved', async () => {
    const ctx = site();
    const statuses = ['pending', 'pending', 'approved'];
    const { transport } = fakeTransport(() =>
      jsonResponse(200, { status: statuses.shift() ?? 'approved' }),
    );
    await awaitConsentDecision(ctx, 'req_1', transport, instant);
  });

  it('throws tg.grant.consent_denied on denial', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() => jsonResponse(200, { status: 'denied' }));
    await assert.rejects(awaitConsentDecision(ctx, 'req_1', transport, instant), (err) =>
      expectTgError(err, Codes.GRANT_CONSENT_DENIED),
    );
  });

  it('throws tg.grant.expired on expiry', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() => jsonResponse(200, { status: 'expired' }));
    await assert.rejects(awaitConsentDecision(ctx, 'req_1', transport, instant), (err) =>
      expectTgError(err, Codes.GRANT_EXPIRED),
    );
  });

  it('times out while still pending', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() => jsonResponse(200, { status: 'pending' }));
    await assert.rejects(
      awaitConsentDecision(ctx, 'req_1', transport, { ...instant, timeoutMs: 5 }),
      (err) => expectTgError(err, Codes.GRANT_EXPIRED),
    );
  });
});

describe('transport failure', () => {
  it('lets transport port errors propagate to the caller', async () => {
    const ctx = site();
    const { transport } = fakeTransport(() => {
      throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'socket hangup');
    });
    await assert.rejects(fetchGrantStatus(ctx, { requestId: 'r' }, transport), (err) =>
      expectTgError(err, Codes.INTERNAL_UNAVAILABLE),
    );
  });
});
