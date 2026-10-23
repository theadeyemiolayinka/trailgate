import { createPrivateKey, generateKeyPairSync, type JsonWebKey } from 'node:crypto';
import type { Jwk, JwtAlgorithm, Money, ReceiptPayload } from '@trailgate/core';
import {
  buildReceiptPayload,
  Codes,
  GRANT_TYP,
  jwkThumbprint,
  signReceipt,
  TrailGateError,
} from '@trailgate/core';
import { SignJWT } from 'jose';
import { randomId } from './ids.ts';

/**
 * A site signing key. `kid` is the SHA-256 JWK thumbprint of the public key
 * (spec section 6.1). The public JWK is published in discovery `signing_keys`;
 * the private JWK signs grants and receipts and MUST stay server-side.
 */
export interface SiteSigningKey {
  kid: string;
  alg: JwtAlgorithm;
  privateJwk: Jwk;
  publicJwk: Jwk;
}

export interface SiteSigningKeyInput {
  privateJwk: Jwk;
  alg?: JwtAlgorithm;
}

/** Strips private members and derives the thumbprint kid for a signing key. */
export function siteSigningKey(input: SiteSigningKeyInput): SiteSigningKey {
  const jwk = input.privateJwk;
  const alg = input.alg ?? 'EdDSA';
  const publicJwk: Jwk = { kty: jwk.kty };
  if (jwk.crv !== undefined) {
    publicJwk.crv = jwk.crv;
  }
  if (jwk.x !== undefined) {
    publicJwk.x = jwk.x;
  }
  if (jwk.y !== undefined) {
    publicJwk.y = jwk.y;
  }
  if (jwk.n !== undefined) {
    publicJwk.n = jwk.n;
  }
  if (jwk.e !== undefined) {
    publicJwk.e = jwk.e;
  }
  const kid = jwkThumbprint(publicJwk);
  publicJwk.kid = kid;
  publicJwk.alg = alg;
  publicJwk.use = 'sig';
  return { kid, alg, privateJwk: jwk, publicJwk };
}

/** Signs a grant payload as a compact JWS (spec section 6.1). */
export async function signGrantJwt(
  payload: Record<string, unknown>,
  key: SiteSigningKey,
): Promise<string> {
  const privateKey = createPrivateKey({ key: key.privateJwk as JsonWebKey, format: 'jwk' });
  return new SignJWT(payload)
    .setProtectedHeader({ alg: key.alg, typ: GRANT_TYP, kid: key.kid })
    .sign(privateKey);
}

export interface IssueReceiptInput {
  issuer: string;
  audience: string;
  grantId: string;
  signatureBase: string;
  decision: 'allowed' | 'denied';
  code?: string;
  amounts?: { reserved?: Money; consumed?: Money; released?: Money };
  auditId: string;
  now: number;
}

/**
 * Builds and signs a receipt (spec section 14). Callers MUST issue receipts
 * for denials as well as for allowed requests; an unsigned denial receipt is
 * only permissible when the site advertises `supports_receipts_unsigned`.
 */
export async function issueReceipt(
  input: IssueReceiptInput,
  key: SiteSigningKey,
): Promise<{ token: string; payload: ReceiptPayload }> {
  const payload = buildReceiptPayload({
    issuer: input.issuer,
    audience: input.audience,
    grantId: input.grantId,
    signatureBase: input.signatureBase,
    decision: input.decision,
    auditId: input.auditId,
    now: input.now,
    ...(input.code !== undefined ? { code: input.code } : {}),
    ...(input.amounts !== undefined ? { amounts: input.amounts } : {}),
    receiptId: randomId('rcp'),
  });
  const token = await signReceipt(payload, {
    privateJwk: key.privateJwk,
    kid: key.kid,
    alg: key.alg,
  });
  return { token, payload };
}

/**
 * Generates a site signing keypair for development and evaluation.
 * `privateJwk` goes to the `signingKeys` config option and must stay
 * server-side; `publicJwk` is what discovery publishes. Production
 * deployments should source keys from their KMS or secret store and pass
 * `SiteSigningKeyInput` directly.
 */
export function generateSigningKeyPair(alg: JwtAlgorithm = 'EdDSA'): {
  publicJwk: Jwk;
  privateJwk: Jwk;
} {
  const { publicKey, privateKey } =
    alg === 'EdDSA'
      ? generateKeyPairSync('ed25519')
      : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicJwk: publicKey.export({ format: 'jwk' }) as JsonWebKey as Jwk,
    privateJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey as Jwk,
  };
}

/** Convenience guard used at configuration time. */
export function assertSigningKeysPresent(keys: readonly SiteSigningKey[]): void {
  if (keys.length === 0) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'at least one site signing key is required');
  }
}
