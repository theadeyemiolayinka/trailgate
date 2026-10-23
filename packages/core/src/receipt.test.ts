import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { FIXTURE_ORIGIN, generateEd25519KeyPair } from '../../test-fixtures/src/index.ts';
import { Codes, TrailGateError } from './errors.ts';
import { buildReceiptPayload, parseReceiptPayload, signReceipt, verifyReceipt } from './receipt.ts';

const site = generateEd25519KeyPair();
const SITE_KID = site.jkt;
const NOW = 1700000000;

const resolver = {
  resolve: async (kid: string) => (kid === SITE_KID ? site.publicJwk : undefined),
};

const DEPS = {
  resolveSiteKey: resolver,
  issuer: FIXTURE_ORIGIN,
  audience: FIXTURE_ORIGIN,
};

async function expectCode(code: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

async function receipt(overrides: Record<string, unknown> = {}) {
  const payload = buildReceiptPayload({
    issuer: FIXTURE_ORIGIN,
    audience: FIXTURE_ORIGIN,
    grantId: 'grt_1',
    signatureBase: '"@method": POST\n"@signature-params": ("@method")',
    decision: 'allowed',
    auditId: 'aud_1',
    now: NOW,
    amounts: { consumed: { amount: 4200, currency: 'USD' } },
    ...overrides,
  });
  return signReceipt(payload, { privateJwk: site.privateJwk, kid: SITE_KID });
}

describe('buildReceiptPayload', () => {
  it('produces schema-valid payloads', () => {
    const payload = buildReceiptPayload({
      issuer: FIXTURE_ORIGIN,
      audience: FIXTURE_ORIGIN,
      grantId: 'grt_1',
      signatureBase: 'x',
      decision: 'denied',
      code: 'tg.constraint.violated',
      auditId: 'aud_1',
      now: NOW,
    });
    assert.equal(payload.tg.decision, 'denied');
    assert.equal(payload.tg.code, 'tg.constraint.violated');
  });

  it('omits code on allowed decisions even when provided', () => {
    const payload = buildReceiptPayload({
      issuer: FIXTURE_ORIGIN,
      audience: FIXTURE_ORIGIN,
      grantId: 'grt_1',
      signatureBase: 'x',
      decision: 'allowed',
      code: 'tg.constraint.violated',
      auditId: 'aud_1',
      now: NOW,
    });
    assert.equal(payload.tg.decision, 'allowed');
    assert.equal(payload.tg.code, undefined);
  });
});

describe('parseReceiptPayload', () => {
  it('rejects structurally invalid payloads', () => {
    try {
      parseReceiptPayload({ iss: 'x' });
    } catch (err) {
      assert.ok(err instanceof TrailGateError);
      assert.equal((err as TrailGateError).code, Codes.REQUEST_MALFORMED);
      return;
    }
    assert.fail('expected rejection');
  });
});

describe('verifyReceipt', () => {
  it('round-trips a signed receipt', async () => {
    const token = await receipt();
    const payload = await verifyReceipt(token, DEPS);
    assert.equal(payload.tg.decision, 'allowed');
    assert.equal(payload.tg.amounts?.consumed?.amount, 4200);
  });

  it('verifies request binding when the digest is supplied', async () => {
    const base = '"@method": POST\n"@signature-params": ("@method")';
    const token = await receipt({ signatureBase: base });
    const digestPayload = await verifyReceipt(token, {
      ...DEPS,
      expectedRequestDigest: createHash('sha256').update(base, 'utf8').digest('base64url'),
    });
    assert.equal(digestPayload.tg.grant_id, 'grt_1');
  });

  it('rejects receipts bound to another request', async () => {
    const token = await receipt();
    await expectCode(Codes.REQUEST_MALFORMED, () =>
      verifyReceipt(token, { ...DEPS, expectedRequestDigest: 'other_digest' }),
    );
  });

  it('rejects receipts signed by another site', async () => {
    const evil = generateEd25519KeyPair();
    const payload = buildReceiptPayload({
      issuer: FIXTURE_ORIGIN,
      audience: FIXTURE_ORIGIN,
      grantId: 'grt_1',
      signatureBase: 'x',
      decision: 'allowed',
      auditId: 'aud_1',
      now: NOW,
    });
    const token = await signReceipt(payload, { privateJwk: evil.privateJwk, kid: SITE_KID });
    await expectCode(Codes.REQUEST_MALFORMED, () => verifyReceipt(token, DEPS));
  });

  it('rejects receipts for another audience', async () => {
    const token = await receipt({ audience: 'https://other.example.com' });
    await expectCode(Codes.REQUEST_AUDIENCE_MISMATCH, () => verifyReceipt(token, DEPS));
  });

  it('rejects receipts answering a different grant', async () => {
    const token = await receipt();
    await expectCode(Codes.REQUEST_MALFORMED, () =>
      verifyReceipt(token, { ...DEPS, expectedGrantId: 'grt_other' }),
    );
    await verifyReceipt(token, { ...DEPS, expectedGrantId: 'grt_1' });
  });

  it('rejects receipts declaring unknown critical fields', async () => {
    const payload = buildReceiptPayload({
      issuer: FIXTURE_ORIGIN,
      audience: FIXTURE_ORIGIN,
      grantId: 'grt_1',
      signatureBase: 'x',
      decision: 'allowed',
      auditId: 'aud_1',
      now: NOW,
    });
    const token = await signReceipt(
      { ...payload, critical: ['mystery_extension'] },
      { privateJwk: site.privateJwk, kid: SITE_KID },
    );
    await expectCode(Codes.REQUEST_MALFORMED, () => verifyReceipt(token, DEPS));
    await verifyReceipt(token, { ...DEPS, knownCriticalFields: ['mystery_extension'] });
  });
});
