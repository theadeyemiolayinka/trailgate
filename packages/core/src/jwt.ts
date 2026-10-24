import type { JsonWebKey } from 'node:crypto';
import { compactVerify, importJWK } from 'jose';
import { Codes, TrailGateError } from './errors.ts';
import { base64urlDecode } from './jwk.ts';
import type { Jwk } from './types.ts';

export const ALLOWED_JWT_ALGORITHMS = ['EdDSA', 'ES256'] as const;
export type JwtAlgorithm = (typeof ALLOWED_JWT_ALGORITHMS)[number];

const FORBIDDEN_HEADER_PARAMS = ['jwk', 'jku', 'x5c', 'x5u', 'x5t', 'x5t#S256'] as const;

export interface DecodedJws {
  header: Record<string, unknown>;
  payload: unknown;
  signature: Uint8Array;
}

function decodeJsonPart(part: string, what: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    throw new TrailGateError(Codes.GRANT_MALFORMED, `${what} is not valid base64url json`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, `${what} is not a json object`);
  }
  return parsed;
}

export function decodeCompactJws(token: string): DecodedJws {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'not a compact jws');
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  const header = decodeJsonPart(headerB64, 'jws header') as Record<string, unknown>;
  const payload = decodeJsonPart(payloadB64, 'jws payload');
  return {
    header,
    payload,
    signature: base64urlDecode(signatureB64),
  };
}

export function checkJwsHeader(header: Record<string, unknown>, expectedTyp: string): JwtAlgorithm {
  const alg = header.alg;
  if (typeof alg !== 'string' || !ALLOWED_JWT_ALGORITHMS.includes(alg as JwtAlgorithm)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'unsupported jws alg');
  }
  if (header.typ !== expectedTyp) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, `unexpected typ: expected ${expectedTyp}`);
  }
  if (header.crit !== undefined) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'crit header parameters are not supported');
  }
  for (const name of FORBIDDEN_HEADER_PARAMS) {
    if (header[name] !== undefined) {
      throw new TrailGateError(
        Codes.GRANT_MALFORMED,
        `jws header parameter ${name} is not supported`,
      );
    }
  }
  return alg as JwtAlgorithm;
}

export async function verifyJwsSignature(
  token: string,
  jwk: Jwk,
  alg: JwtAlgorithm,
  failCode: `tg.${string}.${string}` = Codes.GRANT_MALFORMED,
): Promise<unknown> {
  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(jwk as JsonWebKey, alg);
  } catch {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'cannot import verification key');
  }
  try {
    const { payload } = await compactVerify(token, key, {
      algorithms: [alg],
    });
    return JSON.parse(Buffer.from(payload).toString('utf8')) as unknown;
  } catch {
    throw new TrailGateError(failCode, 'jws signature verification failed');
  }
}
