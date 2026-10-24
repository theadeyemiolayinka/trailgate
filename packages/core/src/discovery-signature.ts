import type { JsonWebKey } from 'node:crypto';
import { base64url, CompactSign, compactVerify, importJWK } from 'jose';
import { Codes, TrailGateError } from './errors.ts';
import { jwkThumbprint } from './jwk.ts';
import { checkJwsHeader, type JwtAlgorithm } from './jwt.ts';
import type { Jwk } from './types.ts';

/**
 * Response header carrying discovery document signatures (spec section
 * 5.5). The value is one or more comma-joined detached compact JWSs of the
 * form `protected..signature`; the JWS payload is the response body bytes.
 */
export const DISCOVERY_SIGNATURE_HEADER = 'trailgate-discovery-signature';

export const DISCOVERY_TYP = 'trailgate-discovery+jws';

export interface DiscoverySigningKey {
  privateJwk: Jwk;
  kid: string;
  alg: JwtAlgorithm;
}

/**
 * Signs the exact discovery response body bytes as a detached compact JWS
 * (`protected..signature`). Sites that publish multiple `signing_keys`
 * SHOULD emit one token per key, comma-joined, so that a document fetched
 * during a key rotation is still signed by a key agents already pinned.
 */
export async function signDiscoveryBody(
  body: string | Uint8Array,
  key: DiscoverySigningKey,
): Promise<string> {
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  const jws = await new CompactSign(bytes)
    .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: DISCOVERY_TYP })
    .sign(await importJWK(key.privateJwk as JsonWebKey, key.alg));
  const parts = jws.split('.');
  return `${parts[0] as string}..${parts[2] as string}`;
}

/**
 * Verifies one detached discovery signature token against `keys`, the
 * `signing_keys.keys` array of the document being verified. Returns the
 * `kid` of the key that produced the signature. Throws
 * `tg.discovery.signature_invalid` on any failure.
 */
export async function verifyDiscoverySignatureToken(
  token: string,
  body: Uint8Array,
  keys: readonly Jwk[],
): Promise<{ kid: string; thumbprint: string }> {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] === '' || parts[1] !== '' || parts[2] === '') {
    throw new TrailGateError(
      Codes.DISCOVERY_SIGNATURE_INVALID,
      'discovery signature is not a detached compact jws',
    );
  }
  let header: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(
      Buffer.from(parts[0] as string, 'base64url').toString('utf8'),
    );
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('not an object');
    }
    header = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof TrailGateError) {
      throw err;
    }
    throw new TrailGateError(
      Codes.DISCOVERY_SIGNATURE_INVALID,
      'discovery signature header is not valid base64url json',
    );
  }
  let alg: JwtAlgorithm;
  try {
    alg = checkJwsHeader(header, DISCOVERY_TYP);
  } catch {
    throw new TrailGateError(
      Codes.DISCOVERY_SIGNATURE_INVALID,
      'discovery signature has an unsupported header',
    );
  }
  const kid = header.kid;
  const jwk =
    typeof kid === 'string'
      ? keys.find((k) => k.kid === kid || thumbprintOr(k) === kid)
      : undefined;
  if (jwk === undefined) {
    throw new TrailGateError(
      Codes.DISCOVERY_SIGNATURE_INVALID,
      'discovery signature kid does not match a published signing key',
    );
  }
  const compact = `${parts[0] as string}.${base64url.encode(body)}.${parts[2] as string}`;
  try {
    await compactVerify(compact, await importJWK(jwk as JsonWebKey, alg), {
      algorithms: [alg],
    });
  } catch {
    throw new TrailGateError(
      Codes.DISCOVERY_SIGNATURE_INVALID,
      'discovery signature verification failed',
    );
  }
  return { kid: kid as string, thumbprint: jwkThumbprint(jwk) };
}

function thumbprintOr(jwk: Jwk): string | undefined {
  try {
    return jwkThumbprint(jwk);
  } catch {
    return undefined;
  }
}

/**
 * Computes the JWK-thumbprint set of a document's `signing_keys`. This set
 * is what agents pin for key continuity (spec section 5.5).
 */
export function signingKeyThumbprints(keys: readonly Jwk[]): string[] {
  const out: string[] = [];
  for (const key of keys) {
    const thumb = thumbprintOr(key);
    if (thumb !== undefined) {
      out.push(thumb);
    }
  }
  return out.sort();
}
