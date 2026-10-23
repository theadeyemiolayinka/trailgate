import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { PendingGrantRequest } from '@trailgate/agent';
import { type AgentSigner, SoftwareKeyProvider } from '@trailgate/agent';
import type { Jwk } from '@trailgate/core';

/**
 * CLI state: private keys and pending consent sessions, as JSON files under
 * a state directory (default `./.trailgate` or `--state-dir`).
 *
 * `keys.json` holds private JWKs in plaintext, protected only by file
 * permissions (0600). This is a development convenience, not a keychain:
 * it offers no protection against a process that can read the file. See
 * `packages/agent/src/keys.ts` for the provider threat model.
 * `pending.json` holds `code_verifier` values between `request` and
 * `redeem`; treat it as secret material for the same reason.
 */

export interface CliState {
  keysPath: string;
  pendingPath: string;
}

export function statePaths(stateDir: string): CliState {
  return { keysPath: join(stateDir, 'keys.json'), pendingPath: join(stateDir, 'pending.json') };
}

async function readJsonFile(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return undefined;
  }
}

async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  await writeFile(tmp, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
  await rename(tmp, path);
}

function isPrivateJwk(value: unknown): value is Jwk {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Jwk).kty === 'string' &&
    typeof (value as Jwk).d === 'string'
  );
}

/** Loads every stored key as a signer. Malformed entries are skipped. */
export async function loadSigners(stateDir: string): Promise<AgentSigner[]> {
  const parsed = await readJsonFile(statePaths(stateDir).keysPath);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return [];
  }
  const signers: AgentSigner[] = [];
  for (const value of Object.values(parsed)) {
    if (!isPrivateJwk(value)) {
      continue;
    }
    try {
      signers.push(SoftwareKeyProvider.fromPrivateJwk(value));
    } catch {
      // A key that cannot be imported is skipped, not fatal.
    }
  }
  return signers;
}

/** Generates and persists a new key; returns the signer and its thumbprint. */
export async function generateAndStoreKey(
  stateDir: string,
  kind: 'ed25519' | 'p256',
): Promise<AgentSigner> {
  const signer = SoftwareKeyProvider.generate(kind);
  const { keysPath } = statePaths(stateDir);
  const parsed = await readJsonFile(keysPath);
  const keys = (
    typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed : {}
  ) as Record<string, unknown>;
  // SoftwareKeyProvider holds the JWK internally; the CLI persists a copy to
  // reload it in later invocations. This is the documented key-file escape.
  keys[signer.jkt] = signer.exportPrivateJwk();
  await writeJsonFile(keysPath, keys);
  return signer;
}

/** Loads persisted pending consent sessions (keyed by request_id). */
export async function loadPending(stateDir: string): Promise<PendingGrantRequest[]> {
  const parsed = await readJsonFile(statePaths(stateDir).pendingPath);
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.filter(isPendingRecord) as PendingGrantRequest[];
}

function isPendingRecord(value: unknown): value is PendingGrantRequest {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const raw = value as Record<string, unknown>;
  return (
    typeof raw.requestId === 'string' &&
    typeof raw.siteOrigin === 'string' &&
    typeof raw.keyId === 'string' &&
    typeof raw.codeVerifier === 'string' &&
    typeof raw.consentUrl === 'string' &&
    typeof raw.expiresAt === 'number'
  );
}

export async function savePending(stateDir: string, record: PendingGrantRequest): Promise<void> {
  const { pendingPath } = statePaths(stateDir);
  const all = (await loadPending(stateDir)).filter((r) => r.requestId !== record.requestId);
  all.push(record);
  await writeJsonFile(pendingPath, all);
}

export async function dropPending(stateDir: string, requestId: string): Promise<void> {
  const { pendingPath } = statePaths(stateDir);
  const all = (await loadPending(stateDir)).filter((r) => r.requestId !== requestId);
  await writeJsonFile(pendingPath, all);
}
