import {
  createPrivateKey,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject,
  sign,
} from 'node:crypto';
import type { Jwk, SignatureAlgorithm } from '@trailgate/core';
import { Codes, jwkThumbprint, signatureAlgorithmFor, TrailGateError } from '@trailgate/core';

/**
 * Agent-side signing boundary.
 *
 * A signer proves possession of the grant-bound private key (`cnf.jkt`) by
 * signing an RFC 9421 signature base. The interface deliberately has no
 * export method: model runtimes, tool adapters, and logs only ever see
 * `jkt`, `publicJwk`, and `algorithm`. Private key material never leaves an
 * implementation through this interface.
 *
 * Threat model (docs/threat-model.md): a leaked agent key plus a live grant
 * equals delegation theft until revocation. Secure-at-rest storage is the
 * provider's job, not this interface's. Note that a keychain or OS secure
 * store protects a key at rest but does NOT prevent a compromised process
 * that can invoke that key; provider implementations must document their
 * platform-specific limitations.
 */
export interface AgentSigner {
  /** SHA-256 JWK thumbprint (RFC 7638) of `publicJwk`; becomes `keyid`/`cnf.jkt`. */
  readonly jkt: string;
  /** Public JWK only. Must never carry `d` or other private members. */
  readonly publicJwk: Jwk;
  /** RFC 9421 alg name for this key (`ed25519` or `ecdsa-p256-sha256`). */
  readonly algorithm: SignatureAlgorithm;
  /** Signs the RFC 9421 signature base and returns raw signature bytes. */
  sign(signatureBase: string): Promise<Uint8Array>;
}

// Only the public members plus `kid`: the grant-request schema's agent_key
// is closed (additionalProperties: false) and allows exactly these members.
function publicOnly(jwk: Jwk): Jwk {
  const out: Jwk = { kty: jwk.kty };
  for (const name of ['crv', 'x', 'y', 'n', 'e', 'kid'] as const) {
    if (jwk[name] !== undefined) {
      out[name] = jwk[name];
    }
  }
  return out;
}

/**
 * In-process software key provider. Generates or imports a private JWK and
 * signs with `node:crypto`.
 *
 * Limitations, stated plainly:
 * - The private JWK lives in process memory. Memory disclosure, crash dumps,
 *   and same-process attackers can extract it.
 * - Nothing here protects the key at rest; that is the deployment's concern
 *   (OS keystore, HSM, KMS). This provider is the reference implementation,
 *   suitable for development and for runtimes that accept process-memory
 *   key custody.
 * - `fromPrivateJwk` exists for key import flows (for example the CLI loading
 *   a key file). Importing a key is trusting the source file completely.
 */
export class SoftwareKeyProvider implements AgentSigner {
  readonly jkt: string;
  readonly publicJwk: Jwk;
  readonly algorithm: SignatureAlgorithm;
  readonly #privateKey: KeyObject;
  readonly #privateJwk: Jwk;

  private constructor(privateJwk: Jwk) {
    const algorithm = signatureAlgorithmFor(privateJwk);
    if (algorithm === undefined) {
      throw new TrailGateError(Codes.INTERNAL_ERROR, 'private key is not an Ed25519 or P-256 key');
    }
    this.#privateKey = createPrivateKey({ key: privateJwk as JsonWebKey, format: 'jwk' });
    this.#privateJwk = privateJwk;
    this.publicJwk = publicOnly(privateJwk);
    this.jkt = jwkThumbprint(this.publicJwk);
    this.algorithm = algorithm;
  }

  /**
   * Returns the private JWK. This exists for persistence flows such as the
   * developer CLI's key file; it is NOT part of the `AgentSigner` interface
   * and must never be wired to a model runtime, log, or tool result. The
   * caller owns the returned material's custody.
   */
  exportPrivateJwk(): Jwk {
    return this.#privateJwk;
  }

  /** Generates a fresh key pair. `kind` is `ed25519` (default) or `p256`. */
  static generate(kind: 'ed25519' | 'p256' = 'ed25519'): SoftwareKeyProvider {
    const { privateKey } =
      kind === 'ed25519'
        ? generateKeyPairSync('ed25519')
        : generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateJwk = privateKey.export({ format: 'jwk' }) as JsonWebKey as Jwk;
    return new SoftwareKeyProvider(privateJwk);
  }

  /** Imports an existing private JWK. The caller is responsible for the source's trustworthiness. */
  static fromPrivateJwk(privateJwk: Jwk): SoftwareKeyProvider {
    if (typeof privateJwk.d !== 'string') {
      throw new TrailGateError(Codes.INTERNAL_ERROR, 'JWK carries no private key material');
    }
    return new SoftwareKeyProvider(privateJwk);
  }

  async sign(signatureBase: string): Promise<Uint8Array> {
    const data = Buffer.from(signatureBase, 'utf8');
    if (this.algorithm === 'ed25519') {
      return new Uint8Array(sign(null, data, this.#privateKey));
    }
    return new Uint8Array(
      sign('sha256', data, { key: this.#privateKey, dsaEncoding: 'ieee-p1363' }),
    );
  }
}
