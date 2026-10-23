import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, fixedClock, TrailGateError } from '@trailgate/core';
import { generateEd25519KeyPair, makeGrantPayload, signCompactJws } from '@trailgate/test-fixtures';
import { InMemoryGrantStore, recordFromGrantToken, selectGrant } from './store.ts';

const siteKey = generateEd25519KeyPair();
const agentKey = generateEd25519KeyPair();

async function makeGrantToken(overrides: Record<string, unknown> = {}): Promise<string> {
  const payload = makeGrantPayload({ jkt: agentKey.jkt, ...overrides });
  return signCompactJws(payload, {
    privateJwk: siteKey.privateJwk,
    kid: siteKey.jkt,
    typ: 'trailgate-grant+jwt',
  });
}

describe('recordFromGrantToken', () => {
  it('extracts the store record from a valid grant', async () => {
    const token = await makeGrantToken({ jti: 'grt_1', sub: 'sub_1' });
    const record = recordFromGrantToken(token);
    assert.equal(record.jti, 'grt_1');
    assert.equal(record.keyId, agentKey.jkt);
    assert.equal(record.issuer, 'https://shop.example.com');
    assert.equal(record.token, token);
    assert.equal(record.subject, 'sub_1');
    assert.deepEqual(record.permissions, ['tg.order.create']);
  });

  it('rejects a malformed token', () => {
    assert.throws(
      () => recordFromGrantToken('not.a.jwt'),
      (err) => err instanceof TrailGateError && err.code === Codes.GRANT_MALFORMED,
    );
  });
});

describe('InMemoryGrantStore', () => {
  it('puts, gets, lists, and removes records', async () => {
    const store = new InMemoryGrantStore();
    const record = recordFromGrantToken(await makeGrantToken({ jti: 'grt_1' }));
    await store.put(record);
    assert.equal((await store.get('grt_1'))?.jti, 'grt_1');
    assert.equal((await store.list()).length, 1);
    assert.equal((await store.list({ issuer: 'https://other.example.com' })).length, 0);
    assert.equal((await store.list({ issuer: 'https://shop.example.com' })).length, 1);
    await store.remove('grt_1');
    assert.equal(await store.get('grt_1'), undefined);
  });
});

describe('selectGrant', () => {
  it('returns the single unexpired matching grant', async () => {
    const store = new InMemoryGrantStore();
    const now = Math.floor(Date.now() / 1000);
    const valid = recordFromGrantToken(await makeGrantToken({ jti: 'grt_valid' }));
    const expired = recordFromGrantToken(
      await makeGrantToken({ jti: 'grt_dead', iat: now - 7200, exp: now - 3600 }),
    );
    await store.put(valid);
    await store.put(expired);
    const found = selectGrant(await store.list(), {
      issuer: 'https://shop.example.com',
      clock: fixedClock(now),
    });
    assert.equal(found?.jti, 'grt_valid');
  });

  it('filters by permission', async () => {
    const store = new InMemoryGrantStore();
    const record = recordFromGrantToken(
      await makeGrantToken({ jti: 'grt_1', permissions: ['tg.cart.read'] }),
    );
    await store.put(record);
    const found = selectGrant(await store.list(), {
      issuer: 'https://shop.example.com',
      permission: 'tg.order.create',
    });
    assert.equal(found, undefined);
  });

  it('throws when several grants match', async () => {
    const store = new InMemoryGrantStore();
    await store.put(recordFromGrantToken(await makeGrantToken({ jti: 'grt_a' })));
    await store.put(recordFromGrantToken(await makeGrantToken({ jti: 'grt_b' })));
    const records = await store.list();
    assert.throws(
      () => selectGrant(records, { issuer: 'https://shop.example.com' }),
      (err) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });
});
