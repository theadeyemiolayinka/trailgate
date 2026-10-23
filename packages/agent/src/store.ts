import type { Clock } from '@trailgate/core';
import { Codes, parseGrant, systemClock, TrailGateError } from '@trailgate/core';

/**
 * Local record of an issued grant: the compact JWS plus the metadata the
 * SDK needs to select and present it. This is the SDK's own shape, not a
 * protocol wire format. `token` is the only secret-adjacent member; it is
 * sent in the `trailgate-grant` header anyway.
 */
export interface StoredGrantRecord {
  /** Grant `jti`. */
  jti: string;
  /** Site issuer the grant is bound to (`iss`/`aud`). */
  issuer: string;
  /** The compact JWS as issued. */
  token: string;
  /** `cnf.jkt`: the key the grant is bound to. Requests must be signed by it. */
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  permissions: string[];
  resources: string[];
  /** Pseudonymous user context (`sub`), when the site assigned one. */
  subject?: string;
}

/**
 * Local grant metadata storage port. Implementations persist records
 * between consent and use. Persisted records are untrusted input on load:
 * `recordFromGrantToken` re-validates the embedded JWT structure, and
 * implementers SHOULD verify signature and `exp` again before relying on a
 * record for security decisions.
 */
export interface GrantStore {
  put(record: StoredGrantRecord): Promise<void>;
  get(jti: string): Promise<StoredGrantRecord | undefined>;
  remove(jti: string): Promise<void>;
  list(filter?: { issuer?: string }): Promise<StoredGrantRecord[]>;
}

/**
 * Derives a store record from a grant token. `parseGrant` performs the
 * structural and schema checks; signature verification against the site's
 * `signing_keys` happens at redemption time before this is called.
 */
export function recordFromGrantToken(token: string): StoredGrantRecord {
  const { payload } = parseGrant(token);
  const record: StoredGrantRecord = {
    jti: payload.jti,
    issuer: payload.iss,
    token,
    keyId: payload.cnf.jkt,
    issuedAt: payload.iat,
    expiresAt: payload.exp,
    permissions: [...payload.tg.permissions],
    resources: [...payload.tg.resources],
  };
  if (payload.sub !== undefined) {
    record.subject = payload.sub;
  }
  return record;
}

/** Volatile store for development, tests, and single-process runtimes. */
export class InMemoryGrantStore implements GrantStore {
  readonly #records = new Map<string, StoredGrantRecord>();

  async put(record: StoredGrantRecord): Promise<void> {
    this.#records.set(record.jti, record);
  }

  async get(jti: string): Promise<StoredGrantRecord | undefined> {
    return this.#records.get(jti);
  }

  async remove(jti: string): Promise<void> {
    this.#records.delete(jti);
  }

  async list(filter?: { issuer?: string }): Promise<StoredGrantRecord[]> {
    const all = [...this.#records.values()];
    return filter?.issuer === undefined
      ? all
      : all.filter((record) => record.issuer === filter.issuer);
  }
}

/**
 * Finds a usable grant for a site: unexpired, optionally covering a
 * permission. Expiry is advisory only (spec section 13): enforcement-time
 * checks are authoritative, and a locally-unexpired grant can still be
 * revoked server-side.
 */
export function selectGrant(
  records: readonly StoredGrantRecord[],
  criteria: { issuer: string; permission?: string; clock?: Clock },
): StoredGrantRecord | undefined {
  const clock = criteria.clock ?? systemClock;
  const now = clock.now();
  const candidates = records.filter(
    (record) =>
      record.issuer === criteria.issuer &&
      record.expiresAt > now &&
      (criteria.permission === undefined || record.permissions.includes(criteria.permission)),
  );
  if (candidates.length > 1) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'multiple stored grants match; specify a grant id explicitly',
    );
  }
  return candidates[0];
}
