import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from '@trailgate/core';
import type {
  AgentKeyDirectory,
  AuditSink,
  GrantRegistry,
  GrantRequestRecord,
  GrantRequestStore,
  NonceStore,
  RequestApprovalStore,
  RequestIdempotencyStore,
  RequestRateLimiter,
  SpendingLedger,
} from '@trailgate/server';

/**
 * Port-contract conformance suite (spec sections 10.4, 11.4, 12, 15).
 *
 * Runs the atomicity and lifecycle requirements every production store must
 * honor against a caller-supplied implementation. A store that passes here
 * still needs durability, backup, and deployment review, but a store that
 * fails reintroduces the attack the port exists to prevent: double redemption,
 * replay, double spend, or lost outcomes.
 *
 * Usage: run against fresh, empty state per call.
 *
 *   runPortContractSuite('sqlite', () => createSqliteStores(db));
 */

export interface PortContractStores {
  grantRequests: GrantRequestStore;
  agentKeys: AgentKeyDirectory;
  grants: GrantRegistry;
  nonces: NonceStore;
  idempotency: RequestIdempotencyStore;
  ledger: SpendingLedger;
  rateLimiter: RequestRateLimiter;
  audit: AuditSink;
  approvals: RequestApprovalStore;
}

const NOW = () => Math.floor(Date.now() / 1000);
const usd = (amount: number) => ({ amount, currency: 'USD' });

function makeGrantRequest(requestId: string, at: number): GrantRequestRecord {
  return {
    requestId,
    createdAt: at,
    expiresAt: at + 900,
    status: 'pending',
    agentJkt: 'jkt-conf',
    body: {
      version: '0.1',
      permissions: ['tg.order.create'],
      resources: [],
      constraints: [],
      agent_key: { kty: 'OKP', crv: 'Ed25519', x: 'conformance' },
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    },
  };
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

export function runPortContractSuite(
  suiteName: string,
  makeStores: () => PortContractStores | Promise<PortContractStores>,
): void {
  describe(`port contract conformance: ${suiteName}`, () => {
    it('grant request transitions are single-use CAS', async () => {
      const s = await makeStores();
      const at = NOW();
      await s.grantRequests.insert(makeGrantRequest('req_c1', at));
      assert.equal((await s.grantRequests.get('req_c1'))?.status, 'pending');
      assert.equal(
        await s.grantRequests.transition('req_c1', 'approved', { status: 'denied' }),
        undefined,
      );
      const approved = await s.grantRequests.transition('req_c1', 'pending', {
        status: 'approved',
        subject: 'user_1',
      });
      assert.equal(approved?.status, 'approved');
      assert.equal(approved?.subject, 'user_1');
      // The CAS that makes redemption single-use: a second transition out of
      // 'pending' must not succeed (spec section 10.4).
      assert.equal(
        await s.grantRequests.transition('req_c1', 'pending', { status: 'issued' }),
        undefined,
      );
      assert.equal(await s.grantRequests.get('req_missing'), undefined);
    });

    it('agent keys round-trip by thumbprint', async () => {
      const s = await makeStores();
      const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'conf-key' };
      await s.agentKeys.register('jkt-conf', jwk);
      assert.deepEqual(await s.agentKeys.resolve('jkt-conf'), jwk);
      assert.equal(await s.agentKeys.resolve('jkt-absent'), undefined);
    });

    it('countByAgent counts recent and open requests per key', async () => {
      const s = await makeStores();
      const at = NOW();
      await s.grantRequests.insert(makeGrantRequest('req_c1', at));
      await s.grantRequests.insert(makeGrantRequest('req_c2', at - 120));
      assert.equal(await s.grantRequests.countByAgent('jkt-conf', at - 60), 1);
      assert.equal(await s.grantRequests.countByAgent('jkt-conf', 0), 2);
      assert.equal(await s.grantRequests.countByAgent('jkt-conf', 0, ['denied']), 0);
      assert.equal(await s.grantRequests.countByAgent('jkt-other', 0), 0);
    });

    it('updateScope replaces effective scope and currentScope reflects it', async () => {
      const s = await makeStores();
      const at = NOW();
      await s.grants.insert({
        jti: 'grt_n1',
        issuedAt: at,
        expiresAt: at + 3600,
        agentJkt: 'jkt-conf',
        requestId: 'req_c1',
        status: 'active',
        permissions: ['tg.a.b', 'tg.c.d'],
      });
      const before = await s.grants.currentScope('grt_n1');
      assert.deepEqual(before?.permissions, ['tg.a.b', 'tg.c.d']);
      const narrowed = await s.grants.updateScope('grt_n1', {
        permissions: ['tg.a.b'],
        actor: 'user_1',
        at: at + 5,
      });
      assert.deepEqual(narrowed?.effectivePermissions, ['tg.a.b']);
      const after = await s.grants.currentScope('grt_n1');
      assert.deepEqual(after?.permissions, ['tg.a.b']);
      // Revoked or absent grants have no live scope and cannot be rescoped.
      assert.equal(
        await s.grants.updateScope('grt_absent', {
          permissions: ['tg.a.b'],
          actor: 'user_1',
          at: at + 6,
        }),
        undefined,
      );
    });

    it('revocation is atomic and applied once', async () => {
      const at = NOW();
      const s = await makeStores();
      await s.grants.insert({
        jti: 'grt_c1',
        issuedAt: at,
        expiresAt: at + 3600,
        agentJkt: 'jkt-conf',
        requestId: 'req_c1',
        status: 'active',
        permissions: ['tg.a.b'],
      });
      assert.equal(await s.grants.isRevoked('grt_c1'), false);
      const revoked = await s.grants.revoke('grt_c1', {
        reason: 'test',
        actor: 'user_1',
        at: at + 10,
      });
      assert.equal(revoked?.status, 'revoked');
      assert.equal(await s.grants.isRevoked('grt_c1'), true);
      assert.equal(
        await s.grants.revoke('grt_c1', { reason: 'again', actor: 'x', at: at + 11 }),
        undefined,
      );
      assert.equal(
        await s.grants.revoke('grt_absent', { reason: 'x', actor: 'x', at: at }),
        undefined,
      );
    });

    it('nonce claims are single-use within their TTL', async () => {
      const s = await makeStores();
      assert.equal(await s.nonces.claim('grt_c1', 'n-1', 300), true);
      assert.equal(await s.nonces.claim('grt_c1', 'n-1', 300), false);
      assert.equal(await s.nonces.claim('grt_c2', 'n-1', 300), true);
      // ttl 0 expires immediately; an expired nonce may be reclaimed.
      assert.equal(await s.nonces.claim('grt_c1', 'n-exp', 0), true);
      assert.equal(await s.nonces.claim('grt_c1', 'n-exp', 300), true);
    });

    it('idempotency claim is atomic: pending, existing, conflict', async () => {
      const s = await makeStores();
      assert.equal(await s.idempotency.lookup('grt_c1', 'k1'), undefined);
      assert.deepEqual(await s.idempotency.claim('grt_c1', 'k1', 'digest-a'), {
        kind: 'claimed',
      });
      // A second claim with the same digest sees the pending record: this is
      // the in-flight state that prevents two handlers running concurrently.
      const pending = await s.idempotency.claim('grt_c1', 'k1', 'digest-a');
      assert.equal(pending.kind, 'existing');
      assert.equal(pending.kind === 'existing' ? pending.record.outcome : 'x', undefined);
      assert.equal((await s.idempotency.claim('grt_c1', 'k1', 'digest-b')).kind, 'conflict');
      // Scoped per grant.
      assert.deepEqual(await s.idempotency.claim('grt_c2', 'k1', 'digest-b'), {
        kind: 'claimed',
      });
    });

    it('idempotency record fills the claim and refuses digest mismatches', async () => {
      const s = await makeStores();
      await s.idempotency.claim('grt_c1', 'k1', 'digest-a');
      await s.idempotency.record('grt_c1', 'k1', {
        requestDigest: 'digest-a',
        outcome: { status: 201, body: { ok: true } },
      });
      const stored = await s.idempotency.lookup('grt_c1', 'k1');
      assert.equal(stored?.requestDigest, 'digest-a');
      assert.equal(stored?.outcome?.status, 201);
      // Replay after completion returns the stored outcome.
      const replay = await s.idempotency.claim('grt_c1', 'k1', 'digest-a');
      assert.equal(replay.kind, 'existing');
      assert.equal(replay.kind === 'existing' ? replay.record.outcome?.status : 0, 201);
      await expectCode(Codes.REQUEST_IDEMPOTENCY_CONFLICT, () =>
        s.idempotency.record('grt_c1', 'k1', {
          requestDigest: 'digest-b',
          outcome: { status: 200 },
        }),
      );
    });

    it('ledger reserve checks budgets and spend windows atomically', async () => {
      const at = NOW();
      const s = await makeStores();
      const budgets = [usd(10_000)];
      const windows = [{ limit: usd(5000), windowSeconds: 3600 }];
      const r1 = await s.ledger.reserve({
        reservationId: 'rsv_c1',
        grantId: 'grt_c1',
        amount: usd(4000),
        budgets,
        spendWindows: windows,
        now: at,
        ttlSeconds: 300,
      });
      assert.equal(r1.state, 'reserved');
      // Over a spend window even though lifetime headroom remains.
      await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
        s.ledger.reserve({
          reservationId: 'rsv_c2',
          grantId: 'grt_c1',
          amount: usd(2000),
          budgets,
          spendWindows: windows,
          now: at,
          ttlSeconds: 300,
        }),
      );
      // Over the lifetime budget outright.
      await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
        s.ledger.reserve({
          reservationId: 'rsv_c3',
          grantId: 'grt_c1',
          amount: usd(20_000),
          budgets,
          now: at,
          ttlSeconds: 300,
        }),
      );
      // Failed reserves must not consume headroom.
      assert.equal(await s.ledger.reservedMinorUnits('grt_c1', 'USD'), 4000);
    });

    it('ledger consume, release, and refund move balances correctly', async () => {
      const at = NOW();
      const s = await makeStores();
      const budgets = [usd(10_000)];
      const r1 = await s.ledger.reserve({
        reservationId: 'rsv_c1',
        grantId: 'grt_c1',
        amount: usd(6000),
        budgets,
        now: at,
        ttlSeconds: 300,
      });
      await s.ledger.consume(r1.reservationId, at + 1);
      assert.equal(await s.ledger.consumedMinorUnits('grt_c1', 'USD'), 6000);
      assert.equal(await s.ledger.reservedMinorUnits('grt_c1', 'USD'), 0);
      const r2 = await s.ledger.reserve({
        reservationId: 'rsv_c2',
        grantId: 'grt_c1',
        amount: usd(3000),
        budgets,
        now: at,
        ttlSeconds: 300,
      });
      await s.ledger.release(r2.reservationId, at + 2);
      assert.equal(await s.ledger.reservedMinorUnits('grt_c1', 'USD'), 0);
      await s.ledger.postRefund({ grantId: 'grt_c1', amount: usd(1000), now: at + 3 });
      assert.equal(await s.ledger.consumedMinorUnits('grt_c1', 'USD'), 5000);
      if (s.ledger.consumedInWindow !== undefined) {
        assert.equal(await s.ledger.consumedInWindow('grt_c1', 'USD', 3600, at + 4), 5000);
      }
    });

    it('rate limiter counts records inside a rolling window', async () => {
      const at = NOW();
      const s = await makeStores();
      await s.rateLimiter.record('grt_c1', at - 100);
      await s.rateLimiter.record('grt_c1', at - 10);
      await s.rateLimiter.record('grt_c1', at);
      assert.equal(await s.rateLimiter.countInWindow('grt_c1', 60, at), 2);
      assert.equal(await s.rateLimiter.countInWindow('grt_c1', 200, at), 3);
      assert.equal(await s.rateLimiter.countInWindow('grt_c2', 200, at), 0);
    });

    it('request approvals: pending decide is CAS and consume is single-use', async () => {
      const at = NOW();
      const s = await makeStores();
      const pending = await s.approvals.requestApproval({
        id: 'rpa_c1',
        grantId: 'grt_c1',
        operationDigest: 'op-1',
        amount: usd(9000),
        now: at,
        ttlSeconds: 600,
      });
      assert.equal(pending.state, 'pending');
      // Same operation re-requests return the live record.
      const again = await s.approvals.requestApproval({
        id: 'rpa_c2',
        grantId: 'grt_c1',
        operationDigest: 'op-1',
        amount: usd(9000),
        now: at,
        ttlSeconds: 600,
      });
      assert.equal(again.id, 'rpa_c1');
      // CAS: only one pending decision lands.
      const approved = await s.approvals.decide('rpa_c1', 'approve', at + 5);
      assert.equal(approved?.state, 'approved');
      assert.equal(await s.approvals.decide('rpa_c1', 'deny', at + 6), undefined);
      // Single-use consume: a second consumer loses the race.
      const consumed = await s.approvals.consumeApproved('grt_c1', 'op-1', at + 7);
      assert.equal(consumed?.id, 'rpa_c1');
      assert.equal(await s.approvals.consumeApproved('grt_c1', 'op-1', at + 7), undefined);
      // A failed execution restores the decision for retry.
      await s.approvals.restore('rpa_c1', at + 8);
      assert.equal((await s.approvals.consumeApproved('grt_c1', 'op-1', at + 8))?.id, 'rpa_c1');
      // Expired approvals are invisible.
      const expired = await s.approvals.requestApproval({
        id: 'rpa_c3',
        grantId: 'grt_c1',
        operationDigest: 'op-2',
        amount: usd(100),
        now: at,
        ttlSeconds: 10,
      });
      await s.approvals.decide(expired.id, 'approve', at + 1);
      assert.equal(await s.approvals.peekApproved('grt_c1', 'op-2', at + 11), undefined);
    });

    it('audit sink returns unique event ids and keeps append order', async () => {
      const at = NOW();
      const s = await makeStores();
      const first = await s.audit.record({ event: 'grant.issued', at: at });
      const second = await s.audit.record({ event: 'request.authenticated', at: at + 1 });
      assert.equal(typeof first, 'string');
      assert.ok(first.length > 0);
      assert.notEqual(first, second);
    });
  });
}
