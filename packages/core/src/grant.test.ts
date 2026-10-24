import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  FIXTURE_ORIGIN,
  generateEd25519KeyPair,
  makeGrantPayload,
  signCompactJws,
} from '../../test-fixtures/src/index.ts';
import { Codes, TrailGateError } from './errors.ts';
import { GRANT_TYP, parseGrant, signGrant, verifyGrant } from './grant.ts';
import type { KeyResolver } from './ports.ts';

const site = generateEd25519KeyPair();
const SITE_KID = site.jkt;
const agent = generateEd25519KeyPair();
const NOW = 1700000000;

function siteResolver(keys = site, kid = SITE_KID): KeyResolver {
  return {
    resolve: async (requested) => (requested === kid ? keys.publicJwk : undefined),
  };
}

async function grantToken(payloadOverrides: Record<string, unknown> = {}, sign = {}) {
  const payload = makeGrantPayload({
    jkt: agent.jkt,
    iat: NOW - 60,
    exp: NOW + 3600,
    ...payloadOverrides,
  });
  return signCompactJws(payload, {
    privateJwk: site.privateJwk,
    kid: SITE_KID,
    typ: GRANT_TYP,
    ...sign,
  });
}

async function expectCode(code: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError, `expected TrailGateError, got ${String(err)}`);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

const DEPS = {
  resolveSiteKey: siteResolver(),
  issuer: FIXTURE_ORIGIN,
  audience: FIXTURE_ORIGIN,
  now: NOW,
};

describe('parseGrant', () => {
  it('parses a structurally valid grant', async () => {
    const token = await grantToken();
    const { payload } = parseGrant(token);
    assert.equal(payload.iss, FIXTURE_ORIGIN);
    assert.equal(payload.cnf.jkt, agent.jkt);
  });

  it('rejects non-jws input', () => {
    expectGrantMalformed(() => parseGrant('not-a-token'));
    expectGrantMalformed(() => parseGrant('a.b'));
  });

  it('rejects a wrong typ', async () => {
    const token = await grantToken({}, { typ: 'JWT' });
    expectGrantMalformed(() => parseGrant(token));
  });

  it('rejects disallowed jose algorithms', async () => {
    const token = await grantToken();
    const [, payloadPart, signaturePart] = token.split('.');
    const forgedHeader = Buffer.from(
      JSON.stringify({ alg: 'HS256', typ: GRANT_TYP, kid: SITE_KID }),
    ).toString('base64url');
    expectGrantMalformed(() => parseGrant(`${forgedHeader}.${payloadPart}.${signaturePart}`));
  });

  it('rejects payloads missing cnf.jkt', async () => {
    const payload = makeGrantPayload({ jkt: agent.jkt });
    delete payload['cnf'];
    const token = await signCompactJws(payload, {
      privateJwk: site.privateJwk,
      kid: SITE_KID,
      typ: GRANT_TYP,
    });
    expectGrantMalformed(() => parseGrant(token));
  });
});

describe('verifyGrant', () => {
  it('verifies a fully valid grant', async () => {
    const token = await grantToken();
    const grant = await verifyGrant(token, DEPS);
    assert.equal(grant.aud, FIXTURE_ORIGIN);
  });

  it('rejects grants signed by a different site key', async () => {
    const evil = generateEd25519KeyPair();
    const token = await grantToken({}, { privateJwk: evil.privateJwk });
    await expectCode(Codes.GRANT_MALFORMED, () => verifyGrant(token, DEPS));
  });

  it('rejects expired grants', async () => {
    const token = await grantToken({ exp: NOW - 1 });
    await expectCode(Codes.GRANT_EXPIRED, () => verifyGrant(token, DEPS));
  });

  it('rejects grants for a different audience', async () => {
    const token = await grantToken({ audience: 'https://other.example.com' });
    await expectCode(Codes.REQUEST_AUDIENCE_MISMATCH, () => verifyGrant(token, DEPS));
  });

  it('rejects grants from a different issuer', async () => {
    const token = await grantToken({ issuer: 'https://evil.example.com' });
    await expectCode(Codes.GRANT_MALFORMED, () => verifyGrant(token, DEPS));
  });

  it('fails safely when the site key cannot be resolved', async () => {
    const token = await grantToken();
    await expectCode(Codes.INTERNAL_UNAVAILABLE, () =>
      verifyGrant(token, { ...DEPS, resolveSiteKey: { resolve: async () => undefined } }),
    );
  });

  it('rejects jws headers carrying embedded key material', async () => {
    const token = await grantToken();
    const [, payloadPart, signaturePart] = token.split('.');
    const forgedHeader = Buffer.from(
      JSON.stringify({ alg: 'EdDSA', typ: GRANT_TYP, kid: SITE_KID, jwk: { kty: 'OKP' } }),
    ).toString('base64url');
    expectGrantMalformed(() => parseGrant(`${forgedHeader}.${payloadPart}.${signaturePart}`));
  });

  it('rejects grants declaring unknown critical fields', async () => {
    const payload = makeGrantPayload({ jkt: agent.jkt, iat: NOW - 60, exp: NOW + 3600 });
    payload['critical'] = ['mystery_extension'];
    const token = await signCompactJws(payload, {
      privateJwk: site.privateJwk,
      kid: SITE_KID,
      typ: GRANT_TYP,
    });
    await expectCode(Codes.GRANT_MALFORMED, () => verifyGrant(token, DEPS));
    await verifyGrant(token, { ...DEPS, knownCriticalFields: ['mystery_extension'] });
  });
});

describe('signGrant', () => {
  it('produces grants that pass verification', async () => {
    const payload = makeGrantPayload({ jkt: agent.jkt, iat: NOW - 60, exp: NOW + 3600 });
    const token = await signGrant(payload, { privateJwk: site.privateJwk, kid: SITE_KID });
    const verified = await verifyGrant(token, DEPS);
    assert.equal(verified.jti, payload.jti);
    const { header } = parseGrant(token);
    assert.equal(header['typ'], GRANT_TYP);
    assert.equal(header['kid'], SITE_KID);
    assert.equal(header['alg'], 'EdDSA');
  });
});

function expectGrantMalformed(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, Codes.GRANT_MALFORMED);
    return;
  }
  assert.fail('expected tg.grant.malformed');
}
