import { createHash, createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import { Codes, TrailGateError } from './errors.ts';
import type { Jwk } from './types.ts';

const THUMBPRINT_MEMBERS = ['crv', 'e', 'kty', 'n', 'x', 'y'] as const;

export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64urlDecode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function jwkThumbprint(jwk: Jwk): string {
  const members: Record<string, unknown> = {};
  for (const name of THUMBPRINT_MEMBERS) {
    if (jwk[name] !== undefined) {
      members[name] = jwk[name];
    }
  }
  if (members['kty'] === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'jwk is missing kty');
  }
  const canonical = JSON.stringify(members);
  return base64urlEncode(createHash('sha256').update(canonical, 'utf8').digest());
}

export function jwkToPublicKey(jwk: Jwk): KeyObject {
  try {
    return createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
  } catch {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'jwk cannot be imported as a public key');
  }
}

export function isAgentKeyShape(jwk: Jwk): boolean {
  if (jwk['kty'] === 'OKP') {
    return jwk['crv'] === 'Ed25519' && typeof jwk['x'] === 'string';
  }
  if (jwk['kty'] === 'EC') {
    return jwk['crv'] === 'P-256' && typeof jwk['x'] === 'string' && typeof jwk['y'] === 'string';
  }
  return false;
}

export function signatureAlgorithmFor(jwk: Jwk): 'ed25519' | 'ecdsa-p256-sha256' | undefined {
  if (jwk['kty'] === 'OKP' && jwk['crv'] === 'Ed25519') {
    return 'ed25519';
  }
  if (jwk['kty'] === 'EC' && jwk['crv'] === 'P-256') {
    return 'ecdsa-p256-sha256';
  }
  return undefined;
}
