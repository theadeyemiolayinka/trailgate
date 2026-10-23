import type { Jwk } from './types.ts';

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

export interface Ledger {
  consumedMinorUnits(grantId: string, currency: string): Promise<number>;
  reservedMinorUnits(grantId: string, currency: string): Promise<number>;
}

export interface RateLimiter {
  countInWindow(grantId: string, windowSeconds: number, now: number): Promise<number>;
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
