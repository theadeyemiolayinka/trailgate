import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { Jwk } from '@trailgate/core';
import { buildReceiptPayload, requestDigestOf, signReceipt } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import { verifyReceiptHeader } from './receipts.ts';

const ORIGIN = 'https://shop.example.com';
const siteKey = generateEd25519KeyPair();

const deps = {
  resolveSiteKey: {
    resolve: async (kid: string) => (kid === siteKey.jkt ? siteKey.publicJwk : undefined),
  },
  issuer: ORIGIN,
  audience: ORIGIN,
};

async function signTestReceipt(overrides: Record<string, unknown> = {}) {
  const payload = buildReceiptPayload({
    issuer: ORIGIN,
    audience: ORIGIN,
    grantId: 'grt_1',
    signatureBase: 'sig-base',
    decision: 'allowed',
    auditId: 'aud_1',
    now: Math.floor(Date.now() / 1000),
    ...overrides,
  });
  return signReceipt(payload, { privateJwk: siteKey.privateJwk as Jwk, kid: siteKey.jkt });
}

describe('verifyReceiptHeader', () => {
  it('returns undefined when no receipt header is present', async () => {
    assert.equal(await verifyReceiptHeader({}, deps), undefined);
  });

  it('verifies a well-formed receipt', async () => {
    const token = await signTestReceipt();
    const outcome = await verifyReceiptHeader({ 'trailgate-receipt': token }, deps);
    assert.equal(outcome?.verified, true);
    if (outcome?.verified === true) {
      assert.equal(outcome.payload.tg.decision, 'allowed');
      assert.equal(outcome.payload.tg.request_digest, requestDigestOf('sig-base'));
    }
  });

  it('reports a tampered receipt as unverified without throwing', async () => {
    const token = await signTestReceipt();
    const tampered = `${token.slice(0, -4)}AAAA`;
    const outcome = await verifyReceiptHeader({ 'trailgate-receipt': tampered }, deps);
    assert.equal(outcome?.verified, false);
  });

  it('reports a receipt for another grant as unverified', async () => {
    const token = await signTestReceipt();
    const outcome = await verifyReceiptHeader(
      { 'trailgate-receipt': token },
      { ...deps, expectedGrantId: 'grt_other' },
    );
    assert.equal(outcome?.verified, false);
  });

  it('reports a receipt bound to a different request digest as unverified', async () => {
    const token = await signTestReceipt();
    const outcome = await verifyReceiptHeader(
      { 'trailgate-receipt': token },
      { ...deps, expectedRequestDigest: requestDigestOf('other-base') },
    );
    assert.equal(outcome?.verified, false);
  });
});
