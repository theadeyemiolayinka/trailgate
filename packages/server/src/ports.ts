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

/** A `spend_window` limit evaluated inside the atomic reservation (spec section 9.2). */
export interface SpendWindowLimit {
  limit: Money;
  windowSeconds: number;
}

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
    /**
     * `spend_window` limits the reservation must also satisfy (spec section
     * 9.2): `consumed` in each window plus live `reserved` plus `amount` must
     * not exceed `limit`. Checked inside the same atomic operation as the
     * lifetime budgets.
     */
    spendWindows?: readonly SpendWindowLimit[];
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

/** Lifecycle states of a per-request human approval (spec section 9.2/12.4). */
export type RequestApprovalState = 'pending' | 'approved' | 'denied' | 'used';

/**
 * A recorded human approval for one protected operation under
 * `approval_threshold`. Bound to the operation digest (method, target URI,
 * `Content-Digest`, grant `jti`), so an approval can never be swapped onto
 * a different request; single-use via the `consumeApproved` transition.
 */
export interface RequestApprovalRecord {
  id: string;
  grantId: string;
  operationDigest: string;
  amount: Money;
  state: RequestApprovalState;
  createdAt: number;
  expiresAt: number;
  decidedAt?: number;
}

/**
 * Per-request approval store (spec section 12.4). The read side satisfies
 * core's `RequestApprovalChecker`; the transitions are CAS-style so a single
 * approval can never authorize two executions.
 */
export interface RequestApprovalStore {
  /**
   * Creates a pending record for `(grantId, operationDigest)`, or returns
   * the live pending/approved one already recorded. Used by the denial path
   * to hand the agent a stable `approval_url`.
   */
  requestApproval(input: {
    id: string;
    grantId: string;
    operationDigest: string;
    amount: Money;
    now: number;
    ttlSeconds: number;
  }): Promise<RequestApprovalRecord>;
  get(id: string): Promise<RequestApprovalRecord | undefined>;
  /**
   * Atomically transitions `pending -> approved|denied`. Returns undefined
   * when the record is absent, expired, or no longer pending.
   */
  decide(
    id: string,
    decision: 'approve' | 'deny',
    now: number,
  ): Promise<RequestApprovalRecord | undefined>;
  /** Live approved record for the operation, or undefined (read side). */
  peekApproved(
    grantId: string,
    operationDigest: string,
    now: number,
  ): Promise<RequestApprovalRecord | undefined>;
  /**
   * Atomically transitions `approved -> used` for the operation's live
   * approved record. Returns the record, or undefined when none was
   * approved: exactly one concurrent request may consume an approval.
   */
  consumeApproved(
    grantId: string,
    operationDigest: string,
    now: number,
  ): Promise<RequestApprovalRecord | undefined>;
  /**
   * Returns a `used` record to `approved` when the operation it authorized
   * failed to execute, so the human's decision survives a retry.
   */
  restore(id: string, now: number): Promise<void>;
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

/** Result of an atomic idempotency claim (spec section 11.4). */
export type IdempotencyClaim =
  | { kind: 'claimed' }
  | { kind: 'existing'; record: StoredIdempotencyRecord }
  | { kind: 'conflict' };

export interface RequestIdempotencyStore extends IdempotencyStore {
  lookup(grantId: string, key: string): Promise<StoredIdempotencyRecord | undefined>;
  /**
   * Atomically claims `(grantId, key)` before the operation executes (spec
   * section 11.4 claim-at-lookup). MUST insert a pending record (no outcome)
   * if absent and return `claimed`; MUST return `existing` with the stored
   * record when a record with the same `requestDigest` is present; MUST
   * return `conflict` when a record with a different `requestDigest` is
   * present. A unique constraint or equivalent serialization is REQUIRED:
   * two concurrent claims for the same pair must not both return `claimed`.
   */
  claim(grantId: string, key: string, requestDigest: string): Promise<IdempotencyClaim>;
  /**
   * Persists the outcome for a key after the operation completes, filling in
   * the pending record `claim` created (or inserting one for callers that
   * skipped `claim`). Implementations MUST NOT overwrite a record whose
   * `requestDigest` differs.
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
 * Caller authorization for the `grant_revocation` endpoint (spec section
 * 13). The ratified caller model gives every bound grant the right to
 * revoke itself by presenting the revocation call as a section 11 signed
 * request; this callback covers every other caller (site-authenticated
 * surfaces, admin tooling). Returning undefined denies. When unconfigured,
 * unsigned callers are denied but agent self-revocation still works.
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
