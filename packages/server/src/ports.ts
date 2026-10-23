import type {
  AuditEvent,
  GrantRequestBody,
  IdempotencyRecord,
  IdempotencyStore,
  Jwk,
  KeyResolver,
  Ledger,
  Money,
  NonceStore,
  RateLimiter,
  RevocationChecker,
} from '@trailgate/core';
import type { HostRequest } from './types.ts';

/**
 * Server-side integration ports for @trailgate/server.
 *
 * These are the storage, accounting, and authorization boundaries a host
 * website implements. `packages/core` defines the verification pipeline;
 * these interfaces define what the pipeline reads and what the lifecycle and
 * enforcement layers write. Correctness requirements (atomicity, durability,
 * fail-closed behavior) are stated per interface: a weak implementation
 * silently reintroduces the attack the port exists to prevent
 * (docs/threat-model.md, "Unresolved risks").
 */

export type GrantRequestStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'issued';

/** Persisted state of a grant request (spec section 10.1 lifecycle). */
export interface GrantRequestRecord {
  requestId: string;
  createdAt: number;
  /** Absolute deadline for the whole request, max 900 s after creation (spec section 10.2). */
  expiresAt: number;
  status: GrantRequestStatus;
  /** Validated request body, retained verbatim for consent rendering. */
  body: GrantRequestBody;
  /** SHA-256 JWK thumbprint of the agent key presented in `body.agent_key`. */
  agentJkt: string;
  /** The site user context (grant `sub`) that approved, set on approval. */
  subject?: string;
  decidedAt?: number;
  /** The effective scope recorded at intake; issued into the grant at redemption. */
  effectivePermissions?: string[];
  effectiveResources?: string[];
  effectiveConstraints?: GrantRequestBody['constraints'];
  effectiveLifetimeSeconds?: number;
  /** Set when the request was redeemed; links request status to grant status. */
  grantId?: string;
}

export interface GrantRequestStore {
  insert(record: GrantRequestRecord): Promise<void>;
  get(requestId: string): Promise<GrantRequestRecord | undefined>;
  /**
   * Atomically moves a request out of `from` status while applying `patch`.
   * Returns the updated record, or undefined when the stored status does not
   * equal `from`. Equivalent to `UPDATE ... WHERE request_id = ? AND status = ?`.
   * This CAS primitive is what makes redemption single-use (spec section 10.4).
   */
  transition(
    requestId: string,
    from: GrantRequestStatus,
    patch: Partial<GrantRequestRecord> & { status: GrantRequestStatus },
  ): Promise<GrantRequestRecord | undefined>;
}

/**
 * Agent public keys by thumbprint, populated at grant-request intake. Used at
 * enforcement to resolve `keyid`/`cnf.jkt` to key material (spec section 11.2).
 * Agent key rotation registers a new `jkt`; a grant is never re-bound.
 */
export interface AgentKeyDirectory extends KeyResolver {
  register(jkt: string, jwk: Jwk): Promise<void>;
}

export type IssuedGrantStatus = 'active' | 'revoked';

/** Persisted record of an issued grant. The JWT itself is not stored. */
export interface IssuedGrantRecord {
  jti: string;
  issuedAt: number;
  expiresAt: number;
  agentJkt: string;
  subject?: string;
  requestId: string;
  status: IssuedGrantStatus;
  revokedAt?: number;
  revocationReason?: string;
  revocationActor?: string;
}

export interface GrantRegistry extends RevocationChecker {
  insert(record: IssuedGrantRecord): Promise<void>;
  get(jti: string): Promise<IssuedGrantRecord | undefined>;
  /**
   * Atomically marks a grant revoked. Returns the updated record, or undefined
   * when the grant is absent or already revoked. Revocation is checked at
   * every enforcement pass against current state (spec section 13).
   */
  revoke(
    jti: string,
    input: { reason: string; actor: string; at: number },
  ): Promise<IssuedGrantRecord | undefined>;
}

export type ReservationState = 'reserved' | 'consumed' | 'released';

export interface Reservation {
  reservationId: string;
  grantId: string;
  amount: Money;
  state: ReservationState;
  createdAt: number;
  expiresAt: number;
}

/**
 * Authoritative spending state (spec section 12). Extends the read-only
 * `Ledger` port from core with the write lifecycle.
 */
export interface SpendingLedger extends Ledger {
  /**
   * Atomically checks `consumed + reserved + amount <= budget` for every
   * applicable budget and inserts a reservation. The headroom check and the
   * insert MUST be one atomic operation: two concurrent requests must not both
   * observe the same headroom (spec section 12). Throws
   * `tg.constraint.violated` when a budget would be exceeded.
   */
  reserve(input: {
    reservationId: string;
    grantId: string;
    amount: Money;
    budgets: readonly Money[];
    now: number;
    ttlSeconds: number;
  }): Promise<Reservation>;
  /** Converts a reservation to a consumed entry after the operation succeeds. */
  consume(reservationId: string, now: number): Promise<void>;
  /** Converts a reservation to a released entry; its headroom returns. */
  release(reservationId: string, now: number): Promise<void>;
  /**
   * Posts an offsetting consumed entry with a negative amount attributed to
   * the grant (spec section 12 refunds).
   */
  postRefund(input: { grantId: string; amount: Money; now: number }): Promise<void>;
}

/** The outcome recorded for an `Idempotency-Key` and returned on replay. */
export interface StoredOutcome {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
}

/**
 * Idempotency records per `(grantId, Idempotency-Key)` (spec section 11.4).
 * `requestDigest` on records is the operation digest (method, target URI,
 * `Content-Digest`, grant `jti`), not the signature-base digest; see
 * `docs/decisions/0008`.
 */
export interface StoredIdempotencyRecord extends IdempotencyRecord {
  outcome?: StoredOutcome;
}

export interface RequestIdempotencyStore extends IdempotencyStore {
  lookup(grantId: string, key: string): Promise<StoredIdempotencyRecord | undefined>;
  /**
   * Persists the outcome for a key after the operation completes.
   * Implementations MUST NOT overwrite a record whose `requestDigest`
   * differs. A real store SHOULD claim the key at lookup time (unique
   * constraint) so concurrent duplicates cannot both execute.
   */
  record(
    grantId: string,
    key: string,
    record: { requestDigest: string; outcome: StoredOutcome },
  ): Promise<void>;
}

/**
 * Per-grant protected-request counter behind the `rate_limit` constraint.
 * `countInWindow` answers the read side; `record` appends an authenticated
 * request. Window semantics (rolling) are the implementation's contract with
 * the spec's open question on counting mode (docs/threat-model.md).
 */
export interface RequestRateLimiter extends RateLimiter {
  record(grantId: string, at: number): Promise<void>;
}

/**
 * Append-only audit log (spec section 15). `record` returns the assigned
 * event identifier, which is embedded in receipts as `tg.audit_id`. Failing
 * to record MUST surface to the caller: the SDK fails closed on the allowed
 * path when the audit event cannot be written.
 */
export interface AuditSink {
  record(event: AuditEvent): Promise<string>;
}

/**
 * Caller authorization for the provisional grant-revocation endpoint.
 * The endpoint's request format is not yet specified (no schema in spec
 * draft 0.1); this callback lets the host decide who may revoke. Returning
 * undefined denies. When unconfigured, the endpoint denies every call.
 *
 * @provisional Pending a normative revocation request schema and caller
 * model in the spec; raise changes through D0.
 */
export type RevocationAuthorizer = (
  req: HostRequest,
  grant: IssuedGrantRecord,
) => Promise<{ actor: string; reason?: string } | undefined>;

/**
 * Host validation of requested resource selectors at grant-request intake
 * (spec section 6.3: a site rejects resources outside its namespace). Throw
 * `tg.grant.scope_rejected` to refuse. Default accepts every selector; the
 * per-request ownership check at enforcement still applies.
 */
export type ResourceScopePolicy = (selectors: readonly string[]) => Promise<void> | void;

/** Re-exported core ports the host also implements where relevant. */
export type { IdempotencyStore, KeyResolver, Ledger, NonceStore, RateLimiter, RevocationChecker };
