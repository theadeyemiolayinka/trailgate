import { Codes, TrailGateError } from './errors.ts';
import type { Jwk } from './types.ts';

export async function callPort<T>(fn: () => Promise<T>, unavailable: string): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof TrailGateError) {
      throw err;
    }
    throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, unavailable);
  }
}

export interface Clock {
  now(): number;
}

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

export function fixedClock(at: number): Clock {
  return { now: () => at };
}

export interface KeyResolver {
  resolve(jkt: string): Promise<Jwk | undefined>;
}

export interface NonceStore {
  claim(grantId: string, nonce: string, ttlSeconds: number): Promise<boolean>;
}

export interface RevocationChecker {
  isRevoked(grantId: string): Promise<boolean>;
}

/**
 * The site's current effective scope for a grant, consulted at every
 * request so post-issuance scope changes take effect without reissuing a
 * JWT. Only the site can write this state; an agent can never change its
 * own scope. When present, `permissions` replaces the signed set (the
 * lifecycle layer keeps it inside the site's advertised vocabulary).
 */
export interface GrantScope {
  permissions?: readonly string[];
  resources?: readonly string[];
}

export interface GrantScopeChecker {
  currentScope(grantId: string): Promise<GrantScope | undefined>;
}

export interface Ledger {
  consumedMinorUnits(grantId: string, currency: string): Promise<number>;
  reservedMinorUnits(grantId: string, currency: string): Promise<number>;
  /**
   * Sum of consumed entries within `(now - windowSeconds, now]` for the
   * `spend_window` constraint (spec section 9.2). Required only when grants
   * carry `spend_window`; its absence fails closed with
   * `tg.internal.unavailable`.
   */
  consumedInWindow?(
    grantId: string,
    currency: string,
    windowSeconds: number,
    now: number,
  ): Promise<number>;
}

export interface RateLimiter {
  countInWindow(grantId: string, windowSeconds: number, now: number): Promise<number>;
}

/**
 * Read side of the per-request approval store behind the
 * `approval_threshold` constraint (spec section 9.2). Returns the live
 * approved record for `(grantId, operationDigest)`, or undefined when no
 * human approval exists or it has expired. The consuming transition lives
 * on the server's full store interface; evaluators only peek.
 */
export interface RequestApprovalChecker {
  peekApproved(grantId: string, operationDigest: string, now: number): Promise<unknown | undefined>;
}

export interface ResourceOwnerResolver {
  ownerOf(selector: string): Promise<string | undefined>;
}

export interface IdempotencyRecord {
  requestDigest: string;
}

export interface IdempotencyStore {
  lookup(grantId: string, key: string): Promise<IdempotencyRecord | undefined>;
}

export interface VerifiedRequestContext {
  grantId: string;
  subject?: string;
  permissions: string[];
  resources: string[];
  method: string;
  url: string;
  requestDigest: string;
}

export interface SitePolicy {
  authorize(context: VerifiedRequestContext): Promise<void>;
}
