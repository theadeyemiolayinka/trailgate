import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  computeContentDigest,
  parseContentDigest,
  requestDigestOf,
  verifyContentDigest,
} from './digest.ts';
import { Codes, TrailGateError } from './errors.ts';

const BODY = new TextEncoder().encode('hello trailgate');

function expectCode(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError, 'expected TrailGateError');
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

describe('computeContentDigest', () => {
  it('produces the RFC 9530 sha-256 byte-sequence form', () => {
    const expected = `sha-256=:${createHash('sha256').update(BODY).digest('base64')}:`;
    assert.equal(computeContentDigest(BODY), expected);
  });
});

describe('parseContentDigest', () => {
  it('parses a single member', () => {
    const map = parseContentDigest('sha-256=:AAAA:');
    assert.equal(map.get('sha-256'), ':AAAA:');
  });

  it('parses multiple members', () => {
    const map = parseContentDigest('sha-256=:AAAA:, sha-512=:BBBB:');
    assert.equal(map.get('sha-512'), ':BBBB:');
  });
});

describe('verifyContentDigest', () => {
  it('accepts a matching digest', () => {
    verifyContentDigest(computeContentDigest(BODY), BODY);
  });

  it('rejects a missing header as malformed', () => {
    expectCode(Codes.REQUEST_MALFORMED, () => verifyContentDigest(undefined, BODY));
  });

  it('rejects headers without sha-256', () => {
    expectCode(Codes.REQUEST_MALFORMED, () => verifyContentDigest('sha-512=:AAAA:', BODY));
  });

  it('rejects tampered bodies', () => {
    const header = computeContentDigest(BODY);
    expectCode(Codes.REQUEST_BODY_DIGEST_MISMATCH, () =>
      verifyContentDigest(header, new TextEncoder().encode('tampered')),
    );
  });
});

describe('requestDigestOf', () => {
  it('is deterministic base64url sha-256', () => {
    const digest = requestDigestOf('some signature base');
    assert.match(digest, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(digest, requestDigestOf('some signature base'));
    assert.notEqual(digest, requestDigestOf('other'));
  });
});
