import { createPrivateKey, type JsonWebKey, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { requestDigestOf } from './digest.ts';
import { Codes, TrailGateError } from './errors.ts';
import { base64urlEncode } from './jwk.ts';
import { checkJwsHeader, decodeCompactJws, type JwtAlgorithm, verifyJwsSignature } from './jwt.ts';
import { callPort, type KeyResolver } from './ports.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { Jwk, Money, ReceiptPayload } from './types.ts';

export const RECEIPT_TYP = 'trailgate-receipt+jwt';

export function parseReceiptPayload(
  payload: unknown,
  knownCriticalFields: readonly string[] = [],
): ReceiptPayload {
  if (!schemaRegistry().validate(SCHEMA_IDS.receipt, payload)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt payload failed schema validation', {
      schema: schemaRegistry().errors(SCHEMA_IDS.receipt),
    });
  }
  const typed = payload as ReceiptPayload;
  const known = new Set(knownCriticalFields);
  const unknownCritical = (typed.critical ?? []).filter((field) => !known.has(field));
  if (unknownCritical.length > 0) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt lists unknown critical fields', {
      unknown: unknownCritical,
    });
  }
  return typed;
}

export interface BuildReceiptInput {
  issuer: string;
  audience: string;
  grantId: string;
  signatureBase: string;
  decision: 'allowed' | 'denied';
  code?: string;
  amounts?: { reserved?: Money; consumed?: Money; released?: Money };
  auditId: string;
  now: number;
  receiptId?: string;
}

export function buildReceiptPayload(input: BuildReceiptInput): ReceiptPayload {
  const tg: ReceiptPayload['tg'] = {
    grant_id: input.grantId,
    request_digest: requestDigestOf(input.signatureBase),
    decision: input.decision,
    audit_id: input.auditId,
  };
  if (input.decision === 'denied' && input.code !== undefined) {
    tg.code = input.code;
  }
  if (input.amounts !== undefined) {
    tg.amounts = input.amounts;
  }
  const payload: ReceiptPayload = {
    iss: input.issuer,
    aud: input.audience,
    jti: input.receiptId ?? `rcp_${base64urlEncode(randomBytes(16))}`,
    iat: input.now,
    tg,
  };
  return parseReceiptPayload(payload);
}

export interface SignReceiptOptions {
  privateJwk: Jwk;
  kid: string;
  alg?: JwtAlgorithm;
}

export async function signReceipt(
  payload: ReceiptPayload,
  options: SignReceiptOptions,
): Promise<string> {
  const alg = options.alg ?? 'EdDSA';
  const key = createPrivateKey({ key: options.privateJwk as JsonWebKey, format: 'jwk' });
  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg, typ: RECEIPT_TYP, kid: options.kid })
    .sign(key);
}

export interface VerifyReceiptDeps {
  resolveSiteKey: KeyResolver;
  issuer: string;
  audience: string;
  expectedRequestDigest?: string;
  expectedGrantId?: string;
  knownCriticalFields?: readonly string[];
}

export async function verifyReceipt(
  token: string,
  deps: VerifyReceiptDeps,
): Promise<ReceiptPayload> {
  const decoded = decodeCompactJws(token);
  const alg = checkJwsHeader(decoded.header, RECEIPT_TYP);
  const kid = decoded.header['kid'];
  if (typeof kid !== 'string' || kid.length === 0) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt header missing kid');
  }
  const key = await callPort(
    () => deps.resolveSiteKey.resolve(kid),
    'receipt signing key is unavailable',
  );
  if (key === undefined) {
    throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'receipt signing key is unresolvable');
  }
  const verified = await verifyJwsSignature(token, key, alg, Codes.REQUEST_MALFORMED);
  const payload = parseReceiptPayload(verified, deps.knownCriticalFields);
  if (payload.iss !== deps.issuer) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt issuer mismatch');
  }
  if (payload.aud !== deps.audience) {
    throw new TrailGateError(Codes.REQUEST_AUDIENCE_MISMATCH, 'receipt audience mismatch');
  }
  if (deps.expectedGrantId !== undefined && payload.tg.grant_id !== deps.expectedGrantId) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt answers a different grant');
  }
  if (
    deps.expectedRequestDigest !== undefined &&
    payload.tg.request_digest !== deps.expectedRequestDigest
  ) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'receipt does not bind to this request');
  }
  return payload;
}
