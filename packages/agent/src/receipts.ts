import type { KeyResolver, ReceiptPayload } from '@trailgate/core';
import { isTrailGateError, verifyReceipt } from '@trailgate/core';

/**
 * Response header the server uses to deliver the receipt JWS (spec section
 * 14.1). Mirrors `RECEIPT_HEADER` in `@trailgate/server`.
 */
export const RECEIPT_HEADER = 'trailgate-receipt';

export type ReceiptOutcome =
  | { verified: true; payload: ReceiptPayload }
  | { verified: false; reason: string; code?: string };

export interface ReceiptVerificationDeps {
  resolveSiteKey: KeyResolver;
  issuer: string;
  audience: string;
  expectedGrantId?: string;
  expectedRequestDigest?: string;
}

/**
 * Reads and verifies the `trailgate-receipt` header (spec section 14.3).
 * Returns undefined when no receipt header is present. A receipt that
 * fails verification is reported as untrusted, not thrown: the receipt is
 * audit evidence, and its absence or invalidity does not change the
 * response body the site already gave.
 *
 * Unsigned denial receipts (`capabilities.supports_receipts_unsigned`) are
 * not parsed in this draft; an unsigned value fails JWS decoding and is
 * reported unverified.
 */
export async function verifyReceiptHeader(
  headers: Record<string, string>,
  deps: ReceiptVerificationDeps,
): Promise<ReceiptOutcome | undefined> {
  const token = headers[RECEIPT_HEADER];
  if (token === undefined) {
    return undefined;
  }
  const verifyDeps: Parameters<typeof verifyReceipt>[1] = {
    resolveSiteKey: deps.resolveSiteKey,
    issuer: deps.issuer,
    audience: deps.audience,
  };
  if (deps.expectedGrantId !== undefined) {
    verifyDeps.expectedGrantId = deps.expectedGrantId;
  }
  if (deps.expectedRequestDigest !== undefined) {
    verifyDeps.expectedRequestDigest = deps.expectedRequestDigest;
  }
  try {
    const payload = await verifyReceipt(token, verifyDeps);
    return { verified: true, payload };
  } catch (err) {
    return {
      verified: false,
      reason: err instanceof Error ? err.message : String(err),
      ...(isTrailGateError(err) ? { code: err.code } : {}),
    };
  }
}
