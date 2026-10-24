import { createPrivateKey, type JsonWebKey } from 'node:crypto';
import { SignJWT } from 'jose';
import { Codes, TrailGateError } from './errors.ts';
import { checkJwsHeader, decodeCompactJws, type JwtAlgorithm, verifyJwsSignature } from './jwt.ts';
import { callPort, type KeyResolver } from './ports.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { GrantPayload, Jwk } from './types.ts';

export const GRANT_TYP = 'trailgate-grant+jwt';

export function assertNoUnknownCriticalFields(
  critical: readonly string[] | undefined,
  knownCriticalFields: readonly string[] = [],
): void {
  const known = new Set(knownCriticalFields);
  const unknown = (critical ?? []).filter((field) => !known.has(field));
  if (unknown.length > 0) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'grant lists unknown critical fields', {
      unknown,
    });
  }
}

export function parseGrant(
  token: string,
  knownCriticalFields: readonly string[] = [],
): {
  header: Record<string, unknown>;
  payload: GrantPayload;
} {
  const decoded = decodeCompactJws(token);
  checkJwsHeader(decoded.header, GRANT_TYP);
  if (!schemaRegistry().validate(SCHEMA_IDS.grant, decoded.payload)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'grant payload failed schema validation', {
      schema: schemaRegistry().errors(SCHEMA_IDS.grant),
    });
  }
  const payload = decoded.payload as GrantPayload;
  assertNoUnknownCriticalFields(payload.critical, knownCriticalFields);
  return { header: decoded.header, payload };
}

export interface SignGrantOptions {
  privateJwk: Jwk;
  kid: string;
  alg?: JwtAlgorithm;
}

/** Signs a grant payload as a compact JWS with the section 6.1 header profile. */
export async function signGrant(payload: GrantPayload, options: SignGrantOptions): Promise<string> {
  const alg = options.alg ?? 'EdDSA';
  const key = createPrivateKey({ key: options.privateJwk as JsonWebKey, format: 'jwk' });
  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg, typ: GRANT_TYP, kid: options.kid })
    .sign(key);
}

export interface GrantVerificationDeps {
  resolveSiteKey: KeyResolver;
  issuer: string;
  audience: string;
  now: number;
  knownCriticalFields?: readonly string[];
}

export async function verifyGrant(
  token: string,
  deps: GrantVerificationDeps,
): Promise<GrantPayload> {
  const { header, payload } = parseGrant(token, deps.knownCriticalFields);
  const alg = checkJwsHeader(header, GRANT_TYP);
  const kid = header.kid;
  if (typeof kid !== 'string' || kid.length === 0) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'grant header missing kid');
  }
  const key = await callPort(
    () => deps.resolveSiteKey.resolve(kid),
    'grant signing key is unavailable',
  );
  if (key === undefined) {
    throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'grant signing key is unresolvable');
  }
  await verifyJwsSignature(token, key, alg);
  validateGrantClaims(payload, deps);
  return payload;
}

export function validateGrantClaims(
  payload: GrantPayload,
  deps: Pick<GrantVerificationDeps, 'issuer' | 'audience' | 'now'>,
): void {
  if (payload.iss !== deps.issuer) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'grant issuer mismatch');
  }
  if (payload.aud !== deps.audience) {
    throw new TrailGateError(
      Codes.REQUEST_AUDIENCE_MISMATCH,
      'grant audience does not match this site',
    );
  }
  if (payload.exp <= deps.now) {
    throw new TrailGateError(Codes.GRANT_EXPIRED, 'grant has expired');
  }
}
