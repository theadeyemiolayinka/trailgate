import type { AuditEvent, Jwk, Money, NonceStore } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import { randomId } from './ids.ts';
import type {
  AgentKeyDirectory,
  AuditSink,
  GrantRegistry,
  GrantRequestRecord,
  GrantRequestStore,
  IssuedGrantRecord,
  PendingActionRecord,
  PendingActionState,
  PendingActionStore,
  RequestApprovalRecord,
  RequestApprovalStore,
  RequestIdempotencyStore,
  RequestRateLimiter,
  Reservation,
  SpendingLedger,
  StoredOutcome,
} from './ports.ts';

/**
 * In-memory reference implementations of every server port. Suitable for
 * development, tests, and single-process demos. NOT suitable for production:
 * state is per-process, non-durable, and unshared, which breaks nonce claims,
 * idempotency records, revocation, and atomic reservations the moment a
 * second process or a restart is involved.
 */

export function createInMemoryGrantRequestStore(): GrantRequestStore {
  const records = new Map<string, GrantRequestRecord>();
  return {
    insert: async (record) => {
      records.set(record.requestId, record);
    },
    get: async (requestId) => records.get(requestId),
    countByAgent: async (agentJkt, since, statuses) => {
      let count = 0;
      for (const record of records.values()) {
        if (
          record.agentJkt === agentJkt &&
          record.createdAt >= since &&
          (statuses === undefined || statuses.includes(record.status))
        ) {
          count += 1;
        }
      }
      return count;
    },
    transition: async (requestId, from, patch) => {
      const record = records.get(requestId);
      if (record === undefined || record.status !== from) {
        return undefined;
      }
      const cleaned = Object.fromEntries(
        Object.entries(patch).filter(([, value]) => value !== undefined),
      );
      const next = Object.assign({}, record, cleaned) as GrantRequestRecord;
      records.set(requestId, next);
      return next;
    },
  };
}

export function createInMemoryAgentKeyDirectory(): AgentKeyDirectory {
  const keys = new Map<string, Jwk>();
  return {
    register: async (jkt, jwk) => {
      keys.set(jkt, jwk);
    },
    resolve: async (jkt) => keys.get(jkt),
  };
}

export function createInMemoryGrantRegistry(): GrantRegistry {
  const grants = new Map<string, IssuedGrantRecord>();
  return {
    insert: async (record) => {
      grants.set(record.jti, record);
    },
    get: async (jti) => grants.get(jti),
    listBySubject: async (subject) =>
      [...grants.values()].filter((record) => record.subject === subject),
    isRevoked: async (jti) => grants.get(jti)?.status === 'revoked',
    revoke: async (jti, input) => {
      const record = grants.get(jti);
      if (record === undefined || record.status === 'revoked') {
        return undefined;
      }
      const next: IssuedGrantRecord = {
        ...record,
        status: 'revoked',
        revokedAt: input.at,
        revocationReason: input.reason,
        revocationActor: input.actor,
      };
      grants.set(jti, next);
      return next;
    },
    currentScope: async (jti) => {
      const record = grants.get(jti);
      if (record === undefined || record.status === 'revoked') {
        return undefined;
      }
      return {
        permissions: record.effectivePermissions ?? record.permissions,
        ...(record.effectiveResources !== undefined
          ? { resources: record.effectiveResources }
          : {}),
        ...(record.effectiveConstraints !== undefined
          ? { constraints: record.effectiveConstraints }
          : {}),
      };
    },
    updateScope: async (jti, input) => {
      const record = grants.get(jti);
      if (record === undefined || record.status === 'revoked') {
        return undefined;
      }
      const next: IssuedGrantRecord = {
        ...record,
        effectivePermissions: input.permissions,
        ...(input.resources !== undefined ? { effectiveResources: input.resources } : {}),
        ...(input.constraints !== undefined ? { effectiveConstraints: input.constraints } : {}),
      };
      grants.set(jti, next);
      return next;
    },
  };
}

export function createInMemoryNonceStore(
  now: () => number = () => Math.floor(Date.now() / 1000),
): NonceStore {
  const claimed = new Map<string, number>();
  return {
    claim: async (grantId, nonce, ttlSeconds) => {
      const at = now();
      const key = `${grantId}:${nonce}`;
      const expiry = claimed.get(key);
      if (expiry !== undefined && expiry > at) {
        return false;
      }
      claimed.set(key, at + ttlSeconds);
      return true;
    },
  };
}

interface IdempotencyEntry {
  requestDigest: string;
  outcome?: StoredOutcome;
}

export function createInMemoryIdempotencyStore(): RequestIdempotencyStore {
  const records = new Map<string, IdempotencyEntry>();
  return {
    lookup: async (grantId, key) => records.get(`${grantId}:${key}`),
    claim: async (grantId, key, requestDigest) => {
      const existing = records.get(`${grantId}:${key}`);
      if (existing !== undefined) {
        return existing.requestDigest === requestDigest
          ? { kind: 'existing', record: existing }
          : { kind: 'conflict' };
      }
      records.set(`${grantId}:${key}`, { requestDigest });
      return { kind: 'claimed' };
    },
    record: async (grantId, key, record) => {
      const existing = records.get(`${grantId}:${key}`);
      if (existing !== undefined && existing.requestDigest !== record.requestDigest) {
        throw new TrailGateError(
          Codes.REQUEST_IDEMPOTENCY_CONFLICT,
          'idempotency key was used for a different operation',
        );
      }
      records.set(`${grantId}:${key}`, record);
    },
  };
}

export function createInMemoryRateLimiter(): RequestRateLimiter {
  const hits = new Map<string, number[]>();
  return {
    countInWindow: async (grantId, windowSeconds, now) => {
      // Reads do not prune: evicting entries outside this window would
      // truncate the history a wider-window evaluation needs later.
      const window = hits.get(grantId) ?? [];
      return window.filter((at) => at > now - windowSeconds && at <= now).length;
    },
    record: async (grantId, at) => {
      const window = hits.get(grantId) ?? [];
      window.push(at);
      hits.set(grantId, window);
    },
  };
}

interface LedgerEntry {
  grantId: string;
  amount: Money;
  at: number;
}

/**
 * In-memory reservation ledger. Atomicity is free in a single-threaded
 * process; a SQL or KV implementation must enforce the same check-and-insert
 * in one operation (unique constraints, conditional updates, or a
 * serializable transaction).
 */
export function createInMemoryLedger(now: () => number): SpendingLedger {
  const consumed: LedgerEntry[] = [];
  const reservations = new Map<string, Reservation>();

  const liveReservations = (): Reservation[] => {
    const at = now();
    for (const reservation of reservations.values()) {
      if (reservation.state === 'reserved' && reservation.expiresAt <= at) {
        reservation.state = 'released';
      }
    }
    return [...reservations.values()].filter((reservation) => reservation.state === 'reserved');
  };

  const sum = (entries: { grantId: string; amount: Money }[], grantId: string, currency: string) =>
    entries
      .filter((entry) => entry.grantId === grantId && entry.amount.currency === currency)
      .reduce((total, entry) => total + entry.amount.amount, 0);

  return {
    consumedMinorUnits: async (grantId, currency) => sum(consumed, grantId, currency),
    reservedMinorUnits: async (grantId, currency) => sum(liveReservations(), grantId, currency),
    consumedInWindow: async (grantId, currency, windowSeconds, now) =>
      consumed
        .filter(
          (entry) =>
            entry.grantId === grantId &&
            entry.amount.currency === currency &&
            entry.at > now - windowSeconds &&
            entry.at <= now,
        )
        .reduce((total, entry) => total + entry.amount.amount, 0),
    reserve: async ({
      reservationId,
      grantId,
      amount,
      budgets,
      spendWindows,
      now: at,
      ttlSeconds,
    }) => {
      const held = sum(liveReservations(), grantId, amount.currency);
      const spent = sum(consumed, grantId, amount.currency);
      for (const budget of budgets) {
        if (spent + held + amount.amount > budget.amount) {
          throw new TrailGateError(
            Codes.CONSTRAINT_VIOLATED,
            'cumulative_budget would be exceeded',
            {
              type: 'cumulative_budget',
              limit: budget,
              consumed: spent,
              reserved: held,
            },
          );
        }
      }
      for (const window of spendWindows ?? []) {
        const spentInWindow = consumed
          .filter(
            (entry) =>
              entry.grantId === grantId &&
              entry.amount.currency === amount.currency &&
              entry.at > at - window.windowSeconds &&
              entry.at <= at,
          )
          .reduce((total, entry) => total + entry.amount.amount, 0);
        if (spentInWindow + held + amount.amount > window.limit.amount) {
          throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'spend_window would be exceeded', {
            type: 'spend_window',
            limit: window.limit,
            window_seconds: window.windowSeconds,
            consumed: spentInWindow,
            reserved: held,
          });
        }
      }
      const reservation: Reservation = {
        reservationId,
        grantId,
        amount,
        state: 'reserved',
        createdAt: at,
        expiresAt: at + ttlSeconds,
      };
      reservations.set(reservationId, reservation);
      return reservation;
    },
    consume: async (reservationId, at) => {
      const reservation = reservations.get(reservationId);
      if (reservation === undefined || reservation.state !== 'reserved') {
        throw new TrailGateError(Codes.INTERNAL_ERROR, 'reservation is not active');
      }
      reservation.state = 'consumed';
      consumed.push({ grantId: reservation.grantId, amount: reservation.amount, at });
    },
    release: async (reservationId) => {
      const reservation = reservations.get(reservationId);
      if (reservation === undefined || reservation.state !== 'reserved') {
        throw new TrailGateError(Codes.INTERNAL_ERROR, 'reservation is not active');
      }
      reservation.state = 'released';
    },
    postRefund: async ({ grantId, amount, now: at }) => {
      consumed.push({ grantId, amount: { amount: -amount.amount, currency: amount.currency }, at });
    },
  };
}

export interface InMemoryAuditSink extends AuditSink {
  readonly entries: readonly { id: string; event: AuditEvent }[];
}

export function createInMemoryAuditSink(): InMemoryAuditSink {
  const entries: { id: string; event: AuditEvent }[] = [];
  return {
    entries,
    record: async (event) => {
      const id = randomId('evt');
      entries.push({ id, event });
      return id;
    },
  };
}

const OPEN_PENDING_STATES: readonly PendingActionState[] = ['pending', 'approved', 'executing'];

/**
 * In-memory pending-action store (spec section 12.5). Same caveat as the
 * other in-memory adapters: single-process only, not durable.
 */
export function createInMemoryPendingActionStore(): PendingActionStore {
  const records = new Map<string, PendingActionRecord>();
  return {
    insert: async (record) => {
      for (const existing of records.values()) {
        if (
          existing.grantId === record.grantId &&
          existing.requestDigest === record.requestDigest &&
          OPEN_PENDING_STATES.includes(existing.state)
        ) {
          return { kind: 'existing', record: existing };
        }
      }
      records.set(record.id, record);
      return { kind: 'inserted' };
    },
    get: async (id) => records.get(id),
    listBySubject: async (subject) =>
      [...records.values()]
        .filter((record) => record.subject === subject)
        .sort((a, b) => b.createdAt - a.createdAt),
    listOpenByGrant: async (grantId) =>
      [...records.values()].filter(
        (record) => record.grantId === grantId && OPEN_PENDING_STATES.includes(record.state),
      ),
    countOpenByGrant: async (grantId) =>
      [...records.values()].filter(
        (record) => record.grantId === grantId && OPEN_PENDING_STATES.includes(record.state),
      ).length,
    transition: async (id, from, patch) => {
      const record = records.get(id);
      if (record === undefined || !from.includes(record.state)) {
        return undefined;
      }
      const cleaned = Object.fromEntries(
        Object.entries(patch).filter(([, value]) => value !== undefined),
      );
      const next = Object.assign({}, record, cleaned) as PendingActionRecord;
      records.set(id, next);
      return next;
    },
  };
}

export function createInMemoryApprovalStore(): RequestApprovalStore {
  const records = new Map<string, RequestApprovalRecord>();
  const liveFor = (grantId: string, operationDigest: string, now: number) =>
    [...records.values()].find(
      (r) =>
        r.grantId === grantId &&
        r.operationDigest === operationDigest &&
        r.expiresAt > now &&
        (r.state === 'pending' || r.state === 'approved'),
    );
  const approvedFor = (grantId: string, operationDigest: string, now: number) =>
    [...records.values()].find(
      (r) =>
        r.grantId === grantId &&
        r.operationDigest === operationDigest &&
        r.expiresAt > now &&
        r.state === 'approved',
    );
  return {
    requestApproval: async ({ id, grantId, operationDigest, amount, now, ttlSeconds }) => {
      const existing = liveFor(grantId, operationDigest, now);
      if (existing !== undefined) {
        return existing;
      }
      const record: RequestApprovalRecord = {
        id,
        grantId,
        operationDigest,
        amount,
        state: 'pending',
        createdAt: now,
        expiresAt: now + ttlSeconds,
      };
      records.set(id, record);
      return record;
    },
    get: async (id) => records.get(id),
    decide: async (id, decision, now) => {
      const record = records.get(id);
      if (record === undefined || record.state !== 'pending' || record.expiresAt <= now) {
        return undefined;
      }
      record.state = decision === 'approve' ? 'approved' : 'denied';
      record.decidedAt = now;
      return record;
    },
    peekApproved: async (grantId, operationDigest, now) =>
      approvedFor(grantId, operationDigest, now),
    consumeApproved: async (grantId, operationDigest, now) => {
      const record = approvedFor(grantId, operationDigest, now);
      if (record === undefined) {
        return undefined;
      }
      record.state = 'used';
      return record;
    },
    restore: async (id) => {
      const record = records.get(id);
      if (record?.state === 'used') {
        record.state = 'approved';
      }
    },
  };
}
