import type { Clock } from '@trailgate/core';
import { SUPPORTED_PROTOCOL_VERSIONS, systemClock } from '@trailgate/core';
import type { SiteContext } from './discovery.ts';
import type { AgentSigner } from './keys.ts';
import type { StoredGrantRecord } from './store.ts';

/**
 * Distinguishable result of checking local grant availability for a site.
 *
 * This answers "can this client act on this site under the requested scope?"
 * before any consent flow or request is attempted. Each non-ready status is
 * a distinct shape so runtimes can branch precisely instead of guessing from
 * an absent token. A stored grant is never treated as proof of access: only
 * `ready` means the local evidence is consistent, and even then the site's
 * enforcement remains authoritative (spec sections 6.3, 13).
 */
export type AccessCheck =
  | { status: 'ready'; grant: StoredGrantRecord; signer: AgentSigner }
  | { status: 'no_grant'; issuer: string }
  | { status: 'expired'; grant: StoredGrantRecord }
  | { status: 'insufficient_permission'; grant: StoredGrantRecord; missing: string[] }
  | { status: 'wrong_key'; grant: StoredGrantRecord; expectedKeyId: string }
  | { status: 'revoked'; grant: StoredGrantRecord }
  | { status: 'unsupported_version'; site: string[]; client: readonly string[] };

export interface AccessCriteria {
  /** Permissions the intended action needs. Defaults to none (presence check). */
  permissions?: readonly string[];
  /** Restrict to a grant bound to this `cnf.jkt`. */
  keyId?: string;
  /** Query `grant_status` for the freshest lifecycle state (adds a request). */
  confirmFresh?: boolean;
}

export interface AccessDeps {
  clock?: Clock;
  signers?: ReadonlyMap<string, AgentSigner>;
  /** Protocol versions this client speaks; defaults to the supported set. */
  clientVersions?: readonly string[];
  /**
   * Optional live status lookup (spec section 10.5); used by
   * `confirmFresh`. The response may carry the site's current effective
   * scope (`permissions`, `resources`).
   */
  statusOf?: (
    grantId: string,
  ) => Promise<{ status: string; permissions?: string[]; resources?: string[] }>;
}

function missingPermissions(record: StoredGrantRecord, needed: readonly string[]): string[] {
  const held = new Set(record.permissions);
  return needed.filter((p) => !held.has(p));
}

/**
 * Evaluates stored grants for `site` against `criteria`, returning the
 * first failure reason encountered in this order:
 *
 * 1. `unsupported_version` - no shared protocol version (checked before any
 *    local evidence; a grant cannot help here).
 * 2. `no_grant` - nothing stored for the issuer (and key, if restricted).
 * 3. `insufficient_permission` - every stored grant lacks a needed permission.
 * 4. `expired` - `exp` passed per the local clock (advisory; the site is
 *    authoritative but an expired grant will never succeed).
 * 5. `wrong_key` - the matching grant is bound to a `cnf.jkt` with no
 *    registered signer, so requests cannot be signed.
 * 6. `revoked` - only via `checkAccessAsync` with `confirmFresh`, when the
 *    site's `grant_status` reports it.
 */
export function checkAccess(
  site: SiteContext,
  grants: readonly StoredGrantRecord[],
  criteria: AccessCriteria = {},
  deps: AccessDeps = {},
): AccessCheck {
  const clientVersions = deps.clientVersions ?? SUPPORTED_PROTOCOL_VERSIONS;
  if (!clientVersions.some((v) => site.document.protocol_versions.includes(v))) {
    return {
      status: 'unsupported_version',
      site: [...site.document.protocol_versions],
      client: clientVersions,
    };
  }

  const candidates = grants.filter(
    (r) => r.issuer === site.origin && (criteria.keyId === undefined || r.keyId === criteria.keyId),
  );
  if (candidates.length === 0) {
    return { status: 'no_grant', issuer: site.origin };
  }

  const needed = criteria.permissions ?? [];
  const clock = deps.clock ?? systemClock;
  const now = clock.now();
  const signers = deps.signers ?? new Map<string, AgentSigner>();

  // Scope check first: if no stored grant covers the needed permissions,
  // that is the honest answer regardless of expiry or keys.
  const viable = candidates.filter((r) => missingPermissions(r, needed).length === 0);
  if (viable.length === 0) {
    const best = candidates[0] as StoredGrantRecord;
    return {
      status: 'insufficient_permission',
      grant: best,
      missing: missingPermissions(best, needed),
    };
  }

  let expiredGrant: StoredGrantRecord | undefined;
  let wrongKeyGrant: StoredGrantRecord | undefined;
  for (const record of viable) {
    if (record.expiresAt <= now) {
      expiredGrant ??= record;
      continue;
    }
    const signer = signers.get(record.keyId);
    if (signer === undefined) {
      wrongKeyGrant ??= record;
      continue;
    }
    return { status: 'ready', grant: record, signer };
  }

  if (expiredGrant !== undefined) {
    return { status: 'expired', grant: expiredGrant };
  }
  const wrong = wrongKeyGrant as StoredGrantRecord;
  return { status: 'wrong_key', grant: wrong, expectedKeyId: wrong.keyId };
}

/**
 * Same as `checkAccess` plus an optional live `grant_status` refresh
 * (`criteria.confirmFresh`): stored grants are reconciled with the site's
 * current effective scope first - permissions the site later allowed or
 * removed are adopted - then a `ready` result is re-checked so a revoked
 * grant surfaces as `revoked` instead of looking usable. Scope updates
 * reported by the site are applied to the records, so callers should
 * treat returned records as fresh and persist them if they keep copies.
 */
export async function checkAccessAsync(
  site: SiteContext,
  grants: readonly StoredGrantRecord[],
  criteria: AccessCriteria = {},
  deps: AccessDeps = {},
): Promise<AccessCheck> {
  let records = grants;
  if (criteria.confirmFresh === true && deps.statusOf !== undefined) {
    records = await Promise.all(
      grants.map(async (record) => {
        try {
          const fresh = await deps.statusOf?.(record.jti);
          if (fresh === undefined) {
            return record;
          }
          return {
            ...record,
            ...(fresh.permissions !== undefined ? { permissions: [...fresh.permissions] } : {}),
            ...(fresh.resources !== undefined ? { resources: [...fresh.resources] } : {}),
          };
        } catch {
          // A failed status lookup must not downgrade local evidence;
          // enforcement remains authoritative either way.
          return record;
        }
      }),
    );
  }
  const result = checkAccess(site, records, criteria, deps);
  if (result.status !== 'ready' || criteria.confirmFresh !== true || deps.statusOf === undefined) {
    return result;
  }
  try {
    const fresh = await deps.statusOf(result.grant.jti);
    if (fresh.status === 'revoked') {
      return { status: 'revoked', grant: result.grant };
    }
    if (fresh.status === 'expired') {
      return { status: 'expired', grant: result.grant };
    }
  } catch {
    // A failed status lookup must not downgrade a locally consistent result
    // into an error; enforcement remains authoritative either way.
  }
  return result;
}
