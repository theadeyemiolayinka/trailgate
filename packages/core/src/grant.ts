import { Codes, TrailGateError } from './errors.ts';
import { checkJwsHeader, decodeCompactJws, verifyJwsSignature } from './jwt.ts';
import type { KeyResolver } from './ports.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { GrantPayload } from './types.ts';

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
  const kid = header['kid'];
  if (typeof kid !== 'string' || kid.length === 0) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'grant header missing kid');
  }
  const key = await deps.resolveSiteKey.resolve(kid);
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
