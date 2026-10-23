import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateEd25519KeyPair } from '../../test-fixtures/src/keys.ts';
import { Codes, TrailGateError } from './errors.ts';
import {
  base64urlDecode,
  base64urlEncode,
  isAgentKeyShape,
  jwkThumbprint,
  jwkToPublicKey,
  signatureAlgorithmFor,
} from './jwk.ts';

describe('jwkThumbprint', () => {
  it('matches the RFC 7638 example thumbprint', () => {
    const jwk = {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29',
    };
    assert.equal(jwkThumbprint(jwk), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('is stable regardless of member order', () => {
    const a = { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' };
    const b = { x: 'AAAA', crv: 'Ed25519', kty: 'OKP' };
    assert.equal(jwkThumbprint(a), jwkThumbprint(b));
  });

  it('rejects keys without kty', () => {
    try {
      jwkThumbprint({ crv: 'Ed25519' });
    } catch (err) {
      assert.ok(err instanceof TrailGateError);
      assert.equal((err as TrailGateError).code, Codes.REQUEST_MALFORMED);
      return;
    }
    assert.fail('expected rejection');
  });
});

describe('signatureAlgorithmFor', () => {
  it('maps supported keys to profile algorithms', () => {
    assert.equal(signatureAlgorithmFor({ kty: 'OKP', crv: 'Ed25519' }), 'ed25519');
    assert.equal(
      signatureAlgorithmFor({ kty: 'EC', crv: 'P-256', x: 'A', y: 'B' }),
      'ecdsa-p256-sha256',
    );
  });

  it('rejects unsupported key material', () => {
    assert.equal(signatureAlgorithmFor({ kty: 'RSA' }), undefined);
    assert.equal(signatureAlgorithmFor({ kty: 'EC', crv: 'P-384', x: 'A', y: 'B' }), undefined);
    assert.equal(signatureAlgorithmFor({ kty: 'OKP' }), undefined);
  });
});

describe('isAgentKeyShape', () => {
  it('accepts ed25519 and p256 public shapes', () => {
    assert.equal(isAgentKeyShape({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }), true);
    assert.equal(isAgentKeyShape({ kty: 'EC', crv: 'P-256', x: 'A', y: 'B' }), true);
  });

  it('rejects other shapes and private-only material', () => {
    assert.equal(isAgentKeyShape({ kty: 'RSA', n: 'x', e: 'y' }), false);
    assert.equal(isAgentKeyShape({ kty: 'OKP', crv: 'Ed25519' }), false);
    assert.equal(isAgentKeyShape({ kty: 'EC', crv: 'P-256', x: 'A' }), false);
  });
});

describe('jwkToPublicKey', () => {
  it('imports a real public key', () => {
    const { publicJwk } = generateEd25519KeyPair();
    const key = jwkToPublicKey(publicJwk);
    assert.equal(key.asymmetricKeyType, 'ed25519');
  });
});

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    const data = new Uint8Array([0, 1, 2, 250, 251, 255]);
    assert.deepEqual(base64urlDecode(base64urlEncode(data)), data);
  });
});
