import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { FIXTURE_ORIGIN, makeDiscovery } from '../../test-fixtures/src/factories.ts';
import { parseDiscoveryDocument, validateDiscoveryDocument } from './discovery.ts';
import { Codes, TrailGateError } from './errors.ts';

const OPTS = { expectedOrigin: FIXTURE_ORIGIN, supportedProtocolVersions: ['0.1'] };

function expectCode(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

describe('validateDiscoveryDocument', () => {
  it('accepts a conforming document', () => {
    const doc = validateDiscoveryDocument(makeDiscovery(), OPTS);
    assert.equal(doc.issuer, FIXTURE_ORIGIN);
    assert.equal(doc.version, '0.1');
  });

  it('rejects an issuer in a different origin', () => {
    expectCode(Codes.DISCOVERY_INVALID, () =>
      validateDiscoveryDocument(makeDiscovery({ issuer: 'https://evil.example.com' }), OPTS),
    );
  });

  it('rejects cross-origin endpoints', () => {
    const doc = makeDiscovery();
    (doc['endpoints'] as Record<string, string>)['grant_request'] =
      'https://attacker.example.net/tg';
    expectCode(Codes.DISCOVERY_INVALID, () => validateDiscoveryDocument(doc, OPTS));
  });

  it('rejects http origins', () => {
    const doc = makeDiscovery({
      issuer: 'http://shop.example.com',
      endpoints: {
        grant_request: 'http://shop.example.com/tg/grant-request',
        grant_redemption: 'http://shop.example.com/tg/redeem',
        grant_status: 'http://shop.example.com/tg/status',
        grant_revocation: 'http://shop.example.com/tg/revoke',
      },
    });
    expectCode(Codes.DISCOVERY_INVALID, () =>
      validateDiscoveryDocument(doc, { ...OPTS, expectedOrigin: 'http://shop.example.com' }),
    );
  });

  it('rejects unknown critical fields', () => {
    expectCode(Codes.DISCOVERY_INVALID, () =>
      validateDiscoveryDocument(makeDiscovery({ critical: ['quantum_lock'] }), OPTS),
    );
  });

  it('rejects when no protocol version overlaps', () => {
    expectCode(Codes.DISCOVERY_UNSUPPORTED_VERSION, () =>
      validateDiscoveryDocument(makeDiscovery({ protocol_versions: ['9.9'] }), OPTS),
    );
  });

  it('rejects documents missing required fields', () => {
    const doc = makeDiscovery();
    delete doc['signing_keys'];
    expectCode(Codes.DISCOVERY_INVALID, () => validateDiscoveryDocument(doc, OPTS));
  });
});

describe('parseDiscoveryDocument', () => {
  it('rejects invalid json', () => {
    expectCode(Codes.DISCOVERY_INVALID, () => parseDiscoveryDocument('{oops', OPTS));
  });
});
