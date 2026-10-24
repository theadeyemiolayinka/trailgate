import type { AuditEvent, Jwk, NonceStore } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import type {
  AgentKeyDirectory,
  AuditSink,
  GrantRegistry,
  GrantRequestRecord,
  GrantRequestStatus,
  GrantRequestStore,
  IssuedGrantRecord,
  RequestIdempotencyStore,
  RequestRateLimiter,
  Reservation,
  SpendingLedger,
  StoredIdempotencyRecord,
} from '@trailgate/server';
import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';

/**
 * SQLite implementations of every Server SDK store port
 * (packages/server/src/ports.ts). These replace the SDK's in-memory
 * defaults with durable, atomic state: compare-and-swap transitions run as
 * conditional UPDATEs, nonce claims as INSERT ... ON CONFLICT, and the
 * budget headroom check plus reservation insert run inside one IMMEDIATE
 * transaction, which is what makes concurrent grants unable to overspend.
 */

interface GrantRequestRow {
  request_id: string;
  created_at: number;
  expires_at: number;
  status: GrantRequestStatus;
  body: string;
  agent_jkt: string;
  subject: string | null;
  decided_at: number | null;
  grant_id: string | null;
  effective_permissions: string | null;
  effective_resources: string | null;
  effective_constraints: string | null;
  effective_lifetime_seconds: number | null;
}

function parseJsonColumn<T>(value: string | null): T | undefined {
  return value === null ? undefined : (JSON.parse(value) as T);
}

function toGrantRequestRecord(row: GrantRequestRow): GrantRequestRecord {
  const record: GrantRequestRecord = {
    requestId: row.request_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    status: row.status,
    body: JSON.parse(row.body) as GrantRequestRecord['body'],
    agentJkt: row.agent_jkt,
  };
  const effectivePermissions = parseJsonColumn<string[]>(row.effective_permissions);
  const effectiveResources = parseJsonColumn<string[]>(row.effective_resources);
  const effectiveConstraints = parseJsonColumn<GrantRequestRecord['effectiveConstraints']>(
    row.effective_constraints,
  );
  if (row.subject !== null) record.subject = row.subject;
  if (row.decided_at !== null) record.decidedAt = row.decided_at;
  if (row.grant_id !== null) record.grantId = row.grant_id;
  if (effectivePermissions !== undefined) record.effectivePermissions = effectivePermissions;
  if (effectiveResources !== undefined) record.effectiveResources = effectiveResources;
  if (effectiveConstraints !== undefined) record.effectiveConstraints = effectiveConstraints;
  if (row.effective_lifetime_seconds !== null) {
    record.effectiveLifetimeSeconds = row.effective_lifetime_seconds;
  }
  return record;
}

const REQUEST_PATCH_COLUMNS: Record<string, string> = {
  status: 'status',
  subject: 'subject',
  decidedAt: 'decided_at',
  grantId: 'grant_id',
  effectivePermissions: 'effective_permissions',
  effectiveResources: 'effective_resources',
  effectiveConstraints: 'effective_constraints',
  effectiveLifetimeSeconds: 'effective_lifetime_seconds',
};

export function createGrantRequestStore(db: Db): GrantRequestStore {
  return {
    insert: async (record) => {
      db.prepare(
        `INSERT INTO tg_grant_requests
         (request_id, created_at, expires_at, status, body, agent_jkt, subject, decided_at,
          grant_id, effective_permissions, effective_resources, effective_constraints,
          effective_lifetime_seconds)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        record.requestId,
        record.createdAt,
        record.expiresAt,
        record.status,
        JSON.stringify(record.body),
        record.agentJkt,
        record.subject ?? null,
        record.decidedAt ?? null,
        record.grantId ?? null,
        record.effectivePermissions !== undefined
          ? JSON.stringify(record.effectivePermissions)
          : null,
        record.effectiveResources !== undefined ? JSON.stringify(record.effectiveResources) : null,
        record.effectiveConstraints !== undefined
          ? JSON.stringify(record.effectiveConstraints)
          : null,
        record.effectiveLifetimeSeconds ?? null,
      );
    },
    get: async (requestId) => {
      const row = db
        .prepare('SELECT * FROM tg_grant_requests WHERE request_id = ?')
        .get(requestId) as unknown as GrantRequestRow | undefined;
      return row === undefined ? undefined : toGrantRequestRecord(row);
    },
    transition: async (requestId, from, patch) => {
      const sets: string[] = [];
      const values: unknown[] = [];
      for (const [key, column] of Object.entries(REQUEST_PATCH_COLUMNS)) {
        if (!(key in patch)) {
          continue;
        }
        const value = (patch as Record<string, unknown>)[key];
        if (value === undefined) {
          continue;
        }
        sets.push(`${column} = ?`);
        values.push(value === null || typeof value !== 'object' ? value : JSON.stringify(value));
      }
      if (sets.length === 0) {
        return undefined;
      }
      const result = db
        .prepare(
          `UPDATE tg_grant_requests SET ${sets.join(', ')}
           WHERE request_id = ? AND status = ?`,
        )
        .run(...(values as (string | number)[]), requestId, from);
      if (result.changes === 0) {
        return undefined;
      }
      const row = db
        .prepare('SELECT * FROM tg_grant_requests WHERE request_id = ?')
        .get(requestId) as unknown as GrantRequestRow;
      return toGrantRequestRecord(row);
    },
  };
}

export function createAgentKeyDirectory(db: Db): AgentKeyDirectory {
  return {
    register: async (jkt, jwk) => {
      db.prepare(
        `INSERT INTO tg_agent_keys (jkt, jwk, registered_at) VALUES (?, ?, ?)
         ON CONFLICT (jkt) DO UPDATE SET jwk = excluded.jwk`,
      ).run(jkt, JSON.stringify(jwk), Math.floor(Date.now() / 1000));
    },
    resolve: async (jkt) => {
      const row = db.prepare('SELECT jwk FROM tg_agent_keys WHERE jkt = ?').get(jkt) as
        | { jwk: string }
        | undefined;
      return row === undefined ? undefined : (JSON.parse(row.jwk) as Jwk);
    },
  };
}

interface GrantRow {
  jti: string;
  issued_at: number;
  expires_at: number;
  agent_jkt: string;
  subject: string | null;
  request_id: string;
  status: 'active' | 'revoked';
  revoked_at: number | null;
  revocation_reason: string | null;
  revocation_actor: string | null;
}

function toGrantRecord(row: GrantRow): IssuedGrantRecord {
  const record: IssuedGrantRecord = {
    jti: row.jti,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    agentJkt: row.agent_jkt,
    requestId: row.request_id,
    status: row.status,
  };
  if (row.subject !== null) record.subject = row.subject;
  if (row.revoked_at !== null) record.revokedAt = row.revoked_at;
  if (row.revocation_reason !== null) record.revocationReason = row.revocation_reason;
  if (row.revocation_actor !== null) record.revocationActor = row.revocation_actor;
  return record;
}

export function createGrantRegistry(db: Db): GrantRegistry {
  return {
    insert: async (record) => {
      db.prepare(
        `INSERT INTO tg_grants
         (jti, issued_at, expires_at, agent_jkt, subject, request_id, status,
          revoked_at, revocation_reason, revocation_actor)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        record.jti,
        record.issuedAt,
        record.expiresAt,
        record.agentJkt,
        record.subject ?? null,
        record.requestId,
        record.status,
        record.revokedAt ?? null,
        record.revocationReason ?? null,
        record.revocationActor ?? null,
      );
    },
    get: async (jti) => {
      const row = db.prepare('SELECT * FROM tg_grants WHERE jti = ?').get(jti) as
        | GrantRow
        | undefined;
      return row === undefined ? undefined : toGrantRecord(row);
    },
    isRevoked: async (jti) => {
      const row = db.prepare('SELECT status FROM tg_grants WHERE jti = ?').get(jti) as
        | { status: string }
        | undefined;
      return row?.status === 'revoked';
    },
    revoke: async (jti, input) => {
      const result = db
        .prepare(
          `UPDATE tg_grants
           SET status = 'revoked', revoked_at = ?, revocation_reason = ?, revocation_actor = ?
           WHERE jti = ? AND status = 'active'`,
        )
        .run(input.at, input.reason, input.actor, jti);
      if (result.changes === 0) {
        return undefined;
      }
      const row = db
        .prepare('SELECT * FROM tg_grants WHERE jti = ?')
        .get(jti) as unknown as GrantRow;
      return toGrantRecord(row);
    },
  };
}

export function createNonceStore(db: Db): NonceStore {
  const insert = db.prepare(
    'INSERT INTO tg_nonces (grant_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING',
  );
  const sweep = db.prepare('DELETE FROM tg_nonces WHERE expires_at <= ?');
  return {
    claim: async (grantId, nonce, ttlSeconds) => {
      const now = Math.floor(Date.now() / 1000);
      sweep.run(now);
      const result = insert.run(grantId, nonce, now + ttlSeconds);
      return result.changes === 1;
    },
  };
}

export function createIdempotencyStore(db: Db): RequestIdempotencyStore {
  const read = (grantId: string, key: string): StoredIdempotencyRecord | undefined => {
    const row = db
      .prepare('SELECT request_digest, outcome FROM tg_idempotency WHERE grant_id = ? AND key = ?')
      .get(grantId, key) as { request_digest: string; outcome: string | null } | undefined;
    if (row === undefined) {
      return undefined;
    }
    const record: StoredIdempotencyRecord = { requestDigest: row.request_digest };
    if (row.outcome !== null) {
      record.outcome = JSON.parse(row.outcome) as NonNullable<StoredIdempotencyRecord['outcome']>;
    }
    return record;
  };
  return {
    lookup: async (grantId, key) => read(grantId, key),
    claim: async (grantId, key, requestDigest) => {
      // INSERT ON CONFLICT is the atomic claim: two concurrent claims cannot
      // both insert the pending row (spec section 11.4).
      const result = db
        .prepare(
          `INSERT INTO tg_idempotency (grant_id, key, request_digest, outcome, created_at)
           VALUES (?, ?, ?, NULL, ?) ON CONFLICT (grant_id, key) DO NOTHING`,
        )
        .run(grantId, key, requestDigest, Math.floor(Date.now() / 1000));
      if (result.changes === 1) {
        return { kind: 'claimed' };
      }
      const existing = read(grantId, key);
      if (existing === undefined) {
        return { kind: 'claimed' };
      }
      return existing.requestDigest === requestDigest
        ? { kind: 'existing', record: existing }
        : { kind: 'conflict' };
    },
    record: async (grantId, key, record) => {
      // Fill the pending row claim() created; insert when no claim ran.
      const updated = db
        .prepare(
          `UPDATE tg_idempotency SET outcome = ?
           WHERE grant_id = ? AND key = ? AND request_digest = ?`,
        )
        .run(JSON.stringify(record.outcome), grantId, key, record.requestDigest);
      if (updated.changes === 1) {
        return;
      }
      const result = db
        .prepare(
          `INSERT INTO tg_idempotency (grant_id, key, request_digest, outcome, created_at)
           VALUES (?, ?, ?, ?, ?) ON CONFLICT (grant_id, key) DO NOTHING`,
        )
        .run(
          grantId,
          key,
          record.requestDigest,
          JSON.stringify(record.outcome),
          Math.floor(Date.now() / 1000),
        );
      if (result.changes === 0) {
        const existing = read(grantId, key);
        if (existing !== undefined && existing.requestDigest !== record.requestDigest) {
          throw new TrailGateError(
            Codes.REQUEST_IDEMPOTENCY_CONFLICT,
            'idempotency key was used for a different operation',
          );
        }
      }
    },
  };
}

interface SumRow {
  total: number | null;
}

export function createSpendingLedger(db: Db, now: () => number): SpendingLedger {
  const sweepExpired = () =>
    db
      .prepare(
        "UPDATE tg_ledger_reservations SET state = 'released' WHERE state = 'reserved' AND expires_at <= ?",
      )
      .run(now());

  const sumConsumed = (grantId: string, currency: string): number =>
    (
      db
        .prepare(
          'SELECT SUM(amount_minor) AS total FROM tg_ledger_consumed WHERE grant_id = ? AND currency = ?',
        )
        .get(grantId, currency) as unknown as SumRow
    ).total ?? 0;

  const sumReserved = (grantId: string, currency: string): number =>
    (
      db
        .prepare(
          `SELECT SUM(amount_minor) AS total FROM tg_ledger_reservations
           WHERE grant_id = ? AND currency = ? AND state = 'reserved'`,
        )
        .get(grantId, currency) as unknown as SumRow
    ).total ?? 0;

  const sumConsumedInWindow = (
    grantId: string,
    currency: string,
    windowSeconds: number,
    now: number,
  ): number =>
    (
      db
        .prepare(
          `SELECT SUM(amount_minor) AS total FROM tg_ledger_consumed
           WHERE grant_id = ? AND currency = ? AND at > ? AND at <= ?`,
        )
        .get(grantId, currency, now - windowSeconds, now) as unknown as SumRow
    ).total ?? 0;

  return {
    consumedMinorUnits: async (grantId, currency) => {
      return sumConsumed(grantId, currency);
    },
    reservedMinorUnits: async (grantId, currency) => {
      sweepExpired();
      return sumReserved(grantId, currency);
    },
    consumedInWindow: async (grantId, currency, windowSeconds, now) => {
      return sumConsumedInWindow(grantId, currency, windowSeconds, now);
    },
    reserve: async ({
      reservationId,
      grantId,
      amount,
      budgets,
      spendWindows,
      now: at,
      ttlSeconds,
    }) => {
      db.exec('BEGIN IMMEDIATE');
      try {
        sweepExpired();
        const spent = sumConsumed(grantId, amount.currency);
        const held = sumReserved(grantId, amount.currency);
        for (const budget of budgets) {
          if (spent + held + amount.amount > budget.amount) {
            throw new TrailGateError(
              Codes.CONSTRAINT_VIOLATED,
              'cumulative_budget would be exceeded',
              { type: 'cumulative_budget', limit: budget, consumed: spent, reserved: held },
            );
          }
        }
        for (const window of spendWindows ?? []) {
          const spentInWindow = sumConsumedInWindow(
            grantId,
            amount.currency,
            window.windowSeconds,
            at,
          );
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
        db.prepare(
          `INSERT INTO tg_ledger_reservations
           (reservation_id, grant_id, amount_minor, currency, state, created_at, expires_at)
           VALUES (?, ?, ?, ?, 'reserved', ?, ?)`,
        ).run(reservationId, grantId, amount.amount, amount.currency, at, at + ttlSeconds);
        db.exec('COMMIT');
        return reservation;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
    consume: async (reservationId, at) => {
      db.exec('BEGIN');
      try {
        const reservation = db
          .prepare('SELECT * FROM tg_ledger_reservations WHERE reservation_id = ?')
          .get(reservationId) as
          | {
              reservation_id: string;
              grant_id: string;
              amount_minor: number;
              currency: string;
              state: string;
            }
          | undefined;
        if (reservation === undefined || reservation.state !== 'reserved') {
          throw new TrailGateError(Codes.INTERNAL_ERROR, 'reservation is not active');
        }
        db.prepare(
          "UPDATE tg_ledger_reservations SET state = 'consumed' WHERE reservation_id = ?",
        ).run(reservationId);
        db.prepare(
          `INSERT INTO tg_ledger_consumed (id, grant_id, reservation_id, amount_minor, currency, at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        ).run(
          newId('led'),
          reservation.grant_id,
          reservationId,
          reservation.amount_minor,
          reservation.currency,
          at,
        );
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
    release: async (reservationId) => {
      const result = db
        .prepare(
          "UPDATE tg_ledger_reservations SET state = 'released' WHERE reservation_id = ? AND state = 'reserved'",
        )
        .run(reservationId);
      if (result.changes === 0) {
        throw new TrailGateError(Codes.INTERNAL_ERROR, 'reservation is not active');
      }
    },
    postRefund: async ({ grantId, amount, now: at }) => {
      db.prepare(
        `INSERT INTO tg_ledger_consumed (id, grant_id, reservation_id, amount_minor, currency, at)
         VALUES (?, ?, NULL, ?, ?, ?)`,
      ).run(newId('led'), grantId, -amount.amount, amount.currency, at);
    },
  };
}

export function createRateLimiter(db: Db): RequestRateLimiter {
  return {
    countInWindow: async (grantId, windowSeconds, now) =>
      (
        db
          .prepare(
            'SELECT COUNT(*) AS n FROM tg_rate_hits WHERE grant_id = ? AND at > ? AND at <= ?',
          )
          .get(grantId, now - windowSeconds, now) as { n: number }
      ).n,
    record: async (grantId, at) => {
      db.prepare('INSERT INTO tg_rate_hits (grant_id, at) VALUES (?, ?)').run(grantId, at);
    },
  };
}

export interface SqliteAuditSink extends AuditSink {
  /** Events attributed to a grant, newest first (for the activity page). */
  listForGrant(grantId: string, limit?: number): { id: string; event: AuditEvent }[];
  listForRequest(requestId: string): { id: string; event: AuditEvent }[];
}

export function createAuditSink(db: Db): SqliteAuditSink {
  return {
    record: async (event) => {
      const id = newId('evt');
      const { event: _name, ...rest } = event;
      db.prepare('INSERT INTO tg_audit (id, at, event, payload) VALUES (?, ?, ?, ?)').run(
        id,
        event.at,
        event.event,
        JSON.stringify(rest),
      );
      return id;
    },
    listForGrant: (grantId, limit = 200) => {
      const rows = db
        .prepare(
          `SELECT id, event, payload FROM tg_audit
           WHERE json_extract(payload, '$.grant_id') = ? ORDER BY at DESC LIMIT ?`,
        )
        .all(grantId, limit) as { id: string; event: string; payload: string }[];
      return rows.map((row) => ({
        id: row.id,
        event: { event: row.event, ...JSON.parse(row.payload) } as AuditEvent,
      }));
    },
    listForRequest: (requestId) => {
      const rows = db
        .prepare(
          `SELECT id, event, payload FROM tg_audit
           WHERE json_extract(payload, '$.request_id') = ? ORDER BY at`,
        )
        .all(requestId) as { id: string; event: string; payload: string }[];
      return rows.map((row) => ({
        id: row.id,
        event: { event: row.event, ...JSON.parse(row.payload) } as AuditEvent,
      }));
    },
  };
}
