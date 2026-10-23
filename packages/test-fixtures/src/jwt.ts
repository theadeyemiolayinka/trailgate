import { createPrivateKey, type JsonWebKey } from 'node:crypto';
import { SignJWT } from 'jose';
import type { Jwk } from './keys.ts';

export interface SignJwsOptions {
  privateJwk: Jwk;
  kid: string;
  typ: string;
  alg?: string;
}

export async function signCompactJws(
  payload: Record<string, unknown>,
  options: SignJwsOptions,
): Promise<string> {
  const alg = options.alg ?? 'EdDSA';
  const key = createPrivateKey({ key: options.privateJwk as JsonWebKey, format: 'jwk' });
  return new SignJWT(payload)
    .setProtectedHeader({ alg, typ: options.typ, kid: options.kid })
    .sign(key);
}
