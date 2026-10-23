import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Jwk } from '@trailgate/core';
import type { AgentSigner } from './keys.ts';
import { SoftwareKeyProvider } from './keys.ts';

/**
 * Key custody port: where `AgentSigner`s live between uses.
 *
 * `AgentSigner` is the signing boundary (no export); `AgentKeyProvider` is
 * the custody boundary: generation, lookup, listing, removal. A provider
 * documents what it protects and what happens when it is unavailable:
 * unavailability MUST surface as an error, never as a silent fallback to a
 * weaker store (that is how plaintext files silently replace a keychain).
 */
export interface AgentKeyProvider {
  /** Human-facing backend name for logs and docs (no secrets). */
  readonly name: string;
  list(): Promise<AgentSigner[]>;
  get(jkt: string): Promise<AgentSigner | undefined>;
  generate(kind: 'ed25519' | 'p256'): Promise<AgentSigner>;
  remove(jkt: string): Promise<void>;
}

/**
 * Process-memory provider. Keys exist for the lifetime of the process and
 * are gone on exit. Appropriate for daemons that re-consent per session and
 * for tests. Unavailability: none beyond process crash.
 */
export class ProcessKeyProvider implements AgentKeyProvider {
  readonly name = 'process-memory';
  readonly #signers = new Map<string, AgentSigner>();

  async list(): Promise<AgentSigner[]> {
    return [...this.#signers.values()];
  }

  async get(jkt: string): Promise<AgentSigner | undefined> {
    return this.#signers.get(jkt);
  }

  async generate(kind: 'ed25519' | 'p256'): Promise<AgentSigner> {
    const signer = SoftwareKeyProvider.generate(kind);
    this.#signers.set(signer.jkt, signer);
    return signer;
  }

  async register(signer: AgentSigner): Promise<void> {
    this.#signers.set(signer.jkt, signer);
  }

  async remove(jkt: string): Promise<void> {
    this.#signers.delete(jkt);
  }
}

/**
 * Development-only file provider. Private JWKs are stored as plaintext JSON
 * at mode 0600.
 *
 * WEAK: this protects the file only against other local users. Any process
 * running as the same user can read every key. It is NOT suitable for
 * production secrets or real funds. Production deployments should provide
 * an `AgentKeyProvider` backed by the OS keystore or a KMS (Windows DPAPI,
 * macOS Keychain, libsecret, or a cloud KMS handle) that returns an
 * `AgentSigner` whose signing happens inside the protected backend.
 *
 * Unavailability: read/parse failures on load produce an empty view rather
 * than a silent plaintext regeneration; a corrupt entry is skipped, never
 * trusted. If the directory is unwritable, writes fail loudly.
 */
export class FileKeyProvider implements AgentKeyProvider {
  readonly name = 'file-dev';
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async #load(): Promise<Map<string, Jwk>> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(this.path, 'utf8'));
    } catch {
      return new Map();
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return new Map();
    }
    const keys = new Map<string, Jwk>();
    for (const [jkt, jwk] of Object.entries(parsed)) {
      if (isPrivateJwk(jwk)) {
        keys.set(jkt, jwk);
      }
    }
    return keys;
  }

  async #save(keys: Map<string, Jwk>): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(Object.fromEntries(keys)), {
      encoding: 'utf8',
      mode: 0o600,
    });
    await rename(tmp, this.path);
  }

  async list(): Promise<AgentSigner[]> {
    const signers: AgentSigner[] = [];
    for (const jwk of (await this.#load()).values()) {
      try {
        signers.push(SoftwareKeyProvider.fromPrivateJwk(jwk));
      } catch {
        // Unimportable material is skipped, not trusted.
      }
    }
    return signers;
  }

  async get(jkt: string): Promise<AgentSigner | undefined> {
    const jwk = (await this.#load()).get(jkt);
    if (jwk === undefined) {
      return undefined;
    }
    try {
      return SoftwareKeyProvider.fromPrivateJwk(jwk);
    } catch {
      return undefined;
    }
  }

  async generate(kind: 'ed25519' | 'p256'): Promise<AgentSigner> {
    const signer = SoftwareKeyProvider.generate(kind);
    const keys = await this.#load();
    keys.set(signer.jkt, signer.exportPrivateJwk());
    await this.#save(keys);
    return signer;
  }

  async register(jwk: Jwk): Promise<AgentSigner> {
    const signer = SoftwareKeyProvider.fromPrivateJwk(jwk);
    const keys = await this.#load();
    keys.set(signer.jkt, jwk);
    await this.#save(keys);
    return signer;
  }

  async remove(jkt: string): Promise<void> {
    const keys = await this.#load();
    if (keys.delete(jkt)) {
      await this.#save(keys);
    }
  }
}

function isPrivateJwk(value: unknown): value is Jwk {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Jwk).kty === 'string' &&
    typeof (value as Jwk).d === 'string'
  );
}
