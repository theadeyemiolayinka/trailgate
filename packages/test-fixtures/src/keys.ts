import { createHash, generateKeyPairSync, type JsonWebKey, type KeyObject } from 'node:crypto';

export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  alg?: string;
  [member: string]: unknown;
}

export interface GeneratedKeyPair {
  publicJwk: Jwk;
  privateJwk: Jwk;
  jkt: string;
}

const THUMBPRINT_MEMBERS = ['crv', 'e', 'kty', 'n', 'x', 'y'] as const;

export function jwkThumbprint(jwk: Jwk): string {
  const members: Record<string, unknown> = {};
  for (const name of THUMBPRINT_MEMBERS) {
    if (jwk[name] !== undefined) {
      members[name] = jwk[name];
    }
  }
  return createHash('sha256')
    .update(JSON.stringify(members), 'utf8')
    .digest()
    .toString('base64url');
}

function exportPair(
  publicKey: KeyObject,
  privateKey: KeyObject,
): { publicJwk: Jwk; privateJwk: Jwk } {
  const publicJwk = publicKey.export({ format: 'jwk' }) as JsonWebKey as Jwk;
  const privateJwk = privateKey.export({ format: 'jwk' }) as JsonWebKey as Jwk;
  return { publicJwk, privateJwk };
}

export function generateEd25519KeyPair(): GeneratedKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { publicJwk, privateJwk } = exportPair(publicKey, privateKey);
  return { publicJwk, privateJwk, jkt: jwkThumbprint(publicJwk) };
}

export function generateP256KeyPair(): GeneratedKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { publicJwk, privateJwk } = exportPair(publicKey, privateKey);
  return { publicJwk, privateJwk, jkt: jwkThumbprint(publicJwk) };
}
