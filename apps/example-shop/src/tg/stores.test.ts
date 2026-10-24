import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Codes, TrailGateError } from '@trailgate/core';
import type { GrantRequestRecord } from '@trailgate/server';
import { type Db, openDatabase } from '../db/database.ts';
import {
  createAgentKeyDirectory,
  createAuditSink,
  createGrantRegistry,
  createGrantRequestStore,
  createIdempotencyStore,
  createNonceStore,
  createRateLimiter,
  createSpendingLedger,
} from './stores.ts';

function testDb(): Db {
  return openDatabase(':memory:');
}

const NOW = 1_760_000_000;

function makeRequest(requestId: string): GrantRequestRecord {
  return {
    requestId,
    createdAt: NOW,
    expiresAt: NOW + 900,
    status: 'pending',
    agentJkt: 'jkt-test',
    body: {
      version: '0.1',
      permissions: ['tg.cart.read'],
      resources: [],
      constraints: [],
      agent_key: { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    },
  };
}

test('grant request store: insert, get, CAS transition', async () => {
  const db = testDb();
  const store = createGrantRequestStore(db);
  const record = makeRequest('req_1');
  record.effectivePermissions = ['tg.cart.read'];
  await store.insert(record);

  const got = await store.get('req_1');
  assert.equal(got?.status, 'pending');
  assert.deepEqual(got?.effectivePermissions, ['tg.cart.read']);
  assert.equal(await store.get('req_missing'), undefined);

  // CAS fails when status moved on
  const stale = await store.transition('req_1', 'approved', { status: 'denied' });
  assert.equal(stale, undefined);

  const approved = await store.transition('req_1', 'pending', {
    status: 'approved',
    subject: 'usr_demo',
    decidedAt: NOW + 10,
  });
  assert.equal(approved?.status, 'approved');
  assert.equal(approved?.subject, 'usr_demo');

  // Second transition from 'pending' now fails (single-use semantics)
  const replay = await store.transition('req_1', 'pending', { status: 'denied' });
  assert.equal(replay, undefined);
});

test('agent key directory: register and resolve', async () => {
  const db = testDb();
  const dir = createAgentKeyDirectory(db);
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'keymaterial' };
  await dir.register('jkt-1', jwk);
  assert.deepEqual(await dir.resolve('jkt-1'), jwk);
  assert.equal(await dir.resolve('jkt-missing'), undefined);
});

test('grant registry: insert, revoke is atomic and idempotent', async () => {
  const db = testDb();
  const registry = createGrantRegistry(db);
  await registry.insert({
    jti: 'grt_1',
    issuedAt: NOW,
    expiresAt: NOW + 3600,
    agentJkt: 'jkt-1',
    requestId: 'req_1',
    status: 'active',
    subject: 'usr_demo',
    permissions: ['tg.a.b'],
  });
  assert.equal(await registry.isRevoked('grt_1'), false);
  const revoked = await registry.revoke('grt_1', {
    reason: 'test',
    actor: 'user:usr_demo',
    at: NOW,
  });
  assert.equal(revoked?.status, 'revoked');
  assert.equal(await registry.isRevoked('grt_1'), true);
  // Already revoked: no second transition
  assert.equal(await registry.revoke('grt_1', { reason: 'x', actor: 'y', at: NOW }), undefined);
});

test('nonce store: claims are atomic and expire', async () => {
  const db = testDb();
  const nonces = createNonceStore(db);
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await nonces.claim('grt_1', 'nonce-1', 300), true);
  assert.equal(await nonces.claim('grt_1', 'nonce-1', 300), false);
  assert.equal(await nonces.claim('grt_2', 'nonce-1', 300), true);
  // Force expiry
  db.prepare('UPDATE tg_nonces SET expires_at = ?').run(now - 1);
  assert.equal(await nonces.claim('grt_1', 'nonce-1', 300), true);
});

test('idempotency store: records outcome, rejects different digest', async () => {
  const db = testDb();
  const store = createIdempotencyStore(db);
  assert.equal(await store.lookup('grt_1', 'key-1'), undefined);
  await store.record('grt_1', 'key-1', {
    requestDigest: 'digest-a',
    outcome: { status: 200, body: { ok: true } },
  });
  const found = await store.lookup('grt_1', 'key-1');
  assert.equal(found?.requestDigest, 'digest-a');
  assert.equal(found?.outcome?.status, 200);
  // Re-recording same digest is a no-op; different digest must throw
  await store.record('grt_1', 'key-1', { requestDigest: 'digest-a', outcome: { status: 200 } });
  await assert.rejects(
    () => store.record('grt_1', 'key-1', { requestDigest: 'digest-b', outcome: { status: 200 } }),
    (err: unknown) =>
      err instanceof TrailGateError && err.code === Codes.REQUEST_IDEMPOTENCY_CONFLICT,
  );
});

test('idempotency store: claim is atomic, pending rows, record fills outcome', async () => {
  const db = testDb();
  const store = createIdempotencyStore(db);
  assert.deepEqual(await store.claim('grt_1', 'key-1', 'digest-a'), { kind: 'claimed' });
  // Second claim sees the pending record, not a fresh claim.
  const second = await store.claim('grt_1', 'key-1', 'digest-a');
  assert.equal(second.kind, 'existing');
  const conflict = await store.claim('grt_1', 'key-1', 'digest-b');
  assert.equal(conflict.kind, 'conflict');
  // Record fills the claimed row.
  await store.record('grt_1', 'key-1', {
    requestDigest: 'digest-a',
    outcome: { status: 201 },
  });
  const stored = await store.lookup('grt_1', 'key-1');
  assert.equal(stored?.outcome?.status, 201);
  // Digest mismatch on record is a conflict.
  await assert.rejects(
    () => store.record('grt_1', 'key-1', { requestDigest: 'nope', outcome: { status: 200 } }),
    TrailGateError,
  );
  // Recording without a prior claim inserts the outcome directly.
  await store.record('grt_9', 'key-9', { requestDigest: 'x', outcome: { status: 200 } });
  assert.equal((await store.lookup('grt_9', 'key-9'))?.outcome?.status, 200);
});

test('spending ledger: reserve, consume, release, refund, budget headroom', async () => {
  const db = testDb();
  const ledger = createSpendingLedger(db, () => NOW);
  const usd = (amount: number) => ({ amount, currency: 'USD' });
  const budgets = [usd(10_000)];

  const r1 = await ledger.reserve({
    reservationId: 'rsv_1',
    grantId: 'grt_1',
    amount: usd(4000),
    budgets,
    now: NOW,
    ttlSeconds: 300,
  });
  assert.equal(r1.state, 'reserved');
  assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 4000);

  // Reserve beyond headroom fails atomically
  await assert.rejects(
    () =>
      ledger.reserve({
        reservationId: 'rsv_big',
        grantId: 'grt_1',
        amount: usd(7000),
        budgets,
        now: NOW,
        ttlSeconds: 300,
      }),
    (err: unknown) => err instanceof TrailGateError && err.code === Codes.CONSTRAINT_VIOLATED,
  );

  await ledger.consume('rsv_1', NOW);
  assert.equal(await ledger.consumedMinorUnits('grt_1', 'USD'), 4000);
  assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
  await assert.rejects(() => ledger.consume('rsv_1', NOW), TrailGateError);

  const r2 = await ledger.reserve({
    reservationId: 'rsv_2',
    grantId: 'grt_1',
    amount: usd(6000),
    budgets,
    now: NOW,
    ttlSeconds: 300,
  });
  await ledger.release(r2.reservationId, NOW);
  assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
  assert.equal(await ledger.consumedMinorUnits('grt_1', 'USD'), 4000);

  await ledger.postRefund({ grantId: 'grt_1', amount: usd(1500), now: NOW });
  assert.equal(await ledger.consumedMinorUnits('grt_1', 'USD'), 2500);
});

test('spending ledger: expired reservations stop counting against headroom', async () => {
  let at = NOW;
  const db = testDb();
  const ledger = createSpendingLedger(db, () => at);
  const usd = (amount: number) => ({ amount, currency: 'USD' });
  await ledger.reserve({
    reservationId: 'rsv_ttl',
    grantId: 'grt_1',
    amount: usd(9000),
    budgets: [usd(10_000)],
    now: at,
    ttlSeconds: 60,
  });
  at = NOW + 120;
  // TTL elapsed: headroom is free again
  assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
  const r = await ledger.reserve({
    reservationId: 'rsv_after',
    grantId: 'grt_1',
    amount: usd(9000),
    budgets: [usd(10_000)],
    now: at,
    ttlSeconds: 60,
  });
  assert.equal(r.state, 'reserved');
});

test('spending ledger: spend_window headroom and consumedInWindow', async () => {
  const at = NOW;
  const db = testDb();
  const ledger = createSpendingLedger(db, () => at);
  const usd = (amount: number) => ({ amount, currency: 'USD' });
  const windows = [{ limit: usd(5000), windowSeconds: 3600 }];

  await ledger.reserve({
    reservationId: 'rsv_1',
    grantId: 'grt_1',
    amount: usd(4000),
    budgets: [],
    spendWindows: windows,
    now: at,
    ttlSeconds: 300,
  });
  await assert.rejects(
    () =>
      ledger.reserve({
        reservationId: 'rsv_2',
        grantId: 'grt_1',
        amount: usd(2000),
        budgets: [],
        spendWindows: windows,
        now: at,
        ttlSeconds: 300,
      }),
    (err: unknown) =>
      err instanceof TrailGateError &&
      err.code === Codes.CONSTRAINT_VIOLATED &&
      err.detail?.type === 'spend_window',
  );
  await ledger.consume('rsv_1', at);
  assert.equal(await ledger.consumedInWindow?.('grt_1', 'USD', 3600, at), 4000);
  assert.equal(await ledger.consumedInWindow?.('grt_1', 'USD', 10, at + 100), 0);
});

test('rate limiter counts within rolling window', async () => {
  const db = testDb();
  const limiter = createRateLimiter(db);
  await limiter.record('grt_1', NOW - 100);
  await limiter.record('grt_1', NOW - 10);
  await limiter.record('grt_1', NOW);
  assert.equal(await limiter.countInWindow('grt_1', 60, NOW), 2);
  assert.equal(await limiter.countInWindow('grt_1', 200, NOW), 3);
  assert.equal(await limiter.countInWindow('grt_2', 200, NOW), 0);
});

test('audit sink: append-only with query helpers', async () => {
  const db = testDb();
  const audit = createAuditSink(db);
  const id = await audit.record({ event: 'grant.issued', at: NOW, grant_id: 'grt_1', jkt: 'jkt' });
  assert.ok(id.startsWith('evt_'));
  await audit.record({ event: 'request.authenticated', at: NOW + 1, grant_id: 'grt_1' });
  await audit.record({
    event: 'grant.issued',
    at: NOW + 2,
    grant_id: 'grt_2',
    request_id: 'req_2',
  });
  assert.equal(audit.listForGrant('grt_1').length, 2);
  assert.equal(audit.listForRequest('req_2').length, 1);
});
