import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from '@trailgate/core';
import {
  createInMemoryAgentKeyDirectory,
  createInMemoryAuditSink,
  createInMemoryGrantRegistry,
  createInMemoryGrantRequestStore,
  createInMemoryIdempotencyStore,
  createInMemoryLedger,
  createInMemoryNonceStore,
  createInMemoryRateLimiter,
} from './memory.ts';

const USD = (amount: number) => ({ amount, currency: 'USD' });

describe('in-memory grant request store', () => {
  it('applies transitions only from the expected status (single-use CAS)', async () => {
    const store = createInMemoryGrantRequestStore();
    await store.insert({
      requestId: 'req_1',
      createdAt: 0,
      expiresAt: 900,
      status: 'pending',
      body: {
        version: '0.1',
        permissions: ['tg.order.create'],
        resources: [],
        constraints: [],
        agent_key: { kty: 'OKP', crv: 'Ed25519', x: 'x' },
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
      },
      agentJkt: 'jkt',
    });
    const approved = await store.transition('req_1', 'pending', {
      status: 'approved',
      subject: 'user_1',
    });
    assert.equal(approved?.status, 'approved');
    const again = await store.transition('req_1', 'pending', { status: 'denied' });
    assert.equal(again, undefined);
  });
});

describe('in-memory ledger', () => {
  const budgets = [USD(10000)];

  it('reserves within budget and denies beyond headroom', async () => {
    const ledger = createInMemoryLedger(() => 1000);
    const first = await ledger.reserve({
      reservationId: 'rsv_1',
      grantId: 'grt_1',
      amount: USD(6000),
      budgets,
      now: 1000,
      ttlSeconds: 300,
    });
    assert.equal(first.state, 'reserved');
    await assert.rejects(
      ledger.reserve({
        reservationId: 'rsv_2',
        grantId: 'grt_1',
        amount: USD(5000),
        budgets,
        now: 1000,
        ttlSeconds: 300,
      }),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.CONSTRAINT_VIOLATED,
    );
  });

  it('consume moves reserved spend to consumed and refund restores headroom', async () => {
    const ledger = createInMemoryLedger(() => 1000);
    await ledger.reserve({
      reservationId: 'rsv_1',
      grantId: 'grt_1',
      amount: USD(8000),
      budgets,
      now: 1000,
      ttlSeconds: 300,
    });
    await ledger.consume('rsv_1', 1000);
    assert.equal(await ledger.consumedMinorUnits('grt_1', 'USD'), 8000);
    assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
    await ledger.postRefund({ grantId: 'grt_1', amount: USD(3000), now: 1000 });
    assert.equal(await ledger.consumedMinorUnits('grt_1', 'USD'), 5000);
    const reservation = await ledger.reserve({
      reservationId: 'rsv_2',
      grantId: 'grt_1',
      amount: USD(5000),
      budgets,
      now: 1000,
      ttlSeconds: 300,
    });
    assert.equal(reservation.state, 'reserved');
  });

  it('releases reservations past their TTL', async () => {
    let now = 1000;
    const ledger = createInMemoryLedger(() => now);
    await ledger.reserve({
      reservationId: 'rsv_1',
      grantId: 'grt_1',
      amount: USD(8000),
      budgets,
      now: 1000,
      ttlSeconds: 300,
    });
    now = 1301;
    assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
    const second = await ledger.reserve({
      reservationId: 'rsv_2',
      grantId: 'grt_1',
      amount: USD(9000),
      budgets,
      now,
      ttlSeconds: 300,
    });
    assert.equal(second.state, 'reserved');
  });

  it('enforces spend_window inside the atomic reserve', async () => {
    const ledger = createInMemoryLedger(() => 1000);
    const windows = [{ limit: USD(5000), windowSeconds: 3600 }];
    await ledger.reserve({
      reservationId: 'rsv_1',
      grantId: 'grt_1',
      amount: USD(4000),
      budgets: [],
      spendWindows: windows,
      now: 1000,
      ttlSeconds: 300,
    });
    await assert.rejects(
      ledger.reserve({
        reservationId: 'rsv_2',
        grantId: 'grt_1',
        amount: USD(2000),
        budgets: [],
        spendWindows: windows,
        now: 1000,
        ttlSeconds: 300,
      }),
      (err: unknown) =>
        err instanceof TrailGateError &&
        err.code === Codes.CONSTRAINT_VIOLATED &&
        err.detail?.['type'] === 'spend_window',
    );
    await ledger.consume('rsv_1', 1000);
    assert.equal(await ledger.consumedInWindow?.('grt_1', 'USD', 3600, 1000), 4000);
    assert.equal(await ledger.consumedInWindow?.('grt_1', 'USD', 100, 2000), 0);
  });

  it('tracks budgets per currency', async () => {
    const ledger = createInMemoryLedger(() => 1000);
    await ledger.reserve({
      reservationId: 'rsv_1',
      grantId: 'grt_1',
      amount: { amount: 8000, currency: 'EUR' },
      budgets,
      now: 1000,
      ttlSeconds: 300,
    });
    assert.equal(await ledger.reservedMinorUnits('grt_1', 'USD'), 0);
    assert.equal(await ledger.reservedMinorUnits('grt_1', 'EUR'), 8000);
  });
});

describe('in-memory nonce store', () => {
  it('claims a nonce once per grant and expires after ttl', async () => {
    let now = 1000;
    const store = createInMemoryNonceStore(() => now);
    assert.equal(await store.claim('grt_1', 'nonce-a', 360), true);
    assert.equal(await store.claim('grt_1', 'nonce-a', 360), false);
    assert.equal(await store.claim('grt_2', 'nonce-a', 360), true);
    now = 1361;
    assert.equal(await store.claim('grt_1', 'nonce-a', 360), true);
  });
});

describe('in-memory rate limiter', () => {
  it('counts requests inside a rolling window', async () => {
    const limiter = createInMemoryRateLimiter();
    await limiter.record('grt_1', 100);
    await limiter.record('grt_1', 200);
    assert.equal(await limiter.countInWindow('grt_1', 60, 250), 1);
    assert.equal(await limiter.countInWindow('grt_1', 300, 250), 2);
    assert.equal(await limiter.countInWindow('grt_2', 300, 250), 0);
  });
});

describe('in-memory idempotency store', () => {
  it('round-trips a recorded outcome', async () => {
    const store = createInMemoryIdempotencyStore();
    assert.equal(await store.lookup('grt_1', 'idem_1'), undefined);
    await store.record('grt_1', 'idem_1', {
      requestDigest: 'digest-1',
      outcome: { status: 200, body: { ok: true } },
    });
    const stored = await store.lookup('grt_1', 'idem_1');
    assert.equal(stored?.requestDigest, 'digest-1');
    assert.equal(stored?.outcome?.status, 200);
    assert.equal(await store.lookup('grt_2', 'idem_1'), undefined);
  });

  it('claims a key once: second claim sees the pending record', async () => {
    const store = createInMemoryIdempotencyStore();
    assert.deepEqual(await store.claim('grt_1', 'k', 'digest-1'), { kind: 'claimed' });
    const second = await store.claim('grt_1', 'k', 'digest-1');
    assert.equal(second.kind, 'existing');
    const conflict = await store.claim('grt_1', 'k', 'different-digest');
    assert.equal(conflict.kind, 'conflict');
  });

  it('record fills the pending claim row and rejects digest mismatches', async () => {
    const store = createInMemoryIdempotencyStore();
    await store.claim('grt_1', 'k', 'digest-1');
    await store.record('grt_1', 'k', {
      requestDigest: 'digest-1',
      outcome: { status: 201 },
    });
    const stored = await store.lookup('grt_1', 'k');
    assert.equal(stored?.outcome?.status, 201);
    await assert.rejects(
      store.record('grt_1', 'k', {
        requestDigest: 'other',
        outcome: { status: 200 },
      }),
      (err) => (err as TrailGateError).code === Codes.REQUEST_IDEMPOTENCY_CONFLICT,
    );
  });
});

describe('in-memory grant registry', () => {
  it('revokes a grant once and reports revocation state', async () => {
    const registry = createInMemoryGrantRegistry();
    await registry.insert({
      jti: 'grt_1',
      issuedAt: 0,
      expiresAt: 3600,
      agentJkt: 'jkt',
      requestId: 'req_1',
      status: 'active',
    });
    assert.equal(await registry.isRevoked('grt_1'), false);
    const revoked = await registry.revoke('grt_1', {
      reason: 'user action',
      actor: 'user_1',
      at: 100,
    });
    assert.equal(revoked?.status, 'revoked');
    assert.equal(await registry.isRevoked('grt_1'), true);
    assert.equal(
      await registry.revoke('grt_1', { reason: 'again', actor: 'user_1', at: 101 }),
      undefined,
    );
  });
});

describe('in-memory agent key directory and audit sink', () => {
  it('resolves registered keys by thumbprint', async () => {
    const keys = createInMemoryAgentKeyDirectory();
    await keys.register('jkt-1', { kty: 'OKP', crv: 'Ed25519', x: 'x' });
    const jwk = await keys.resolve('jkt-1');
    assert.equal(jwk?.kty, 'OKP');
    assert.equal(await keys.resolve('jkt-2'), undefined);
  });

  it('assigns audit identifiers and keeps append-only order', async () => {
    const sink = createInMemoryAuditSink();
    const first = await sink.record({ event: 'grant.requested', at: 1 });
    const second = await sink.record({ event: 'grant.issued', at: 2 });
    assert.ok(first.startsWith('evt_'));
    assert.notEqual(first, second);
    assert.deepEqual(
      sink.entries.map((entry) => entry.event.event),
      ['grant.requested', 'grant.issued'],
    );
  });
});
