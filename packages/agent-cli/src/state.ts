import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { PendingGrantRequest } from '@trailgate/agent';
import { type AgentSigner, FileKeyProvider } from '@trailgate/agent';

/**
 * CLI state: private keys and pending consent sessions under a state
 * directory (default `./.trailgate` or `--state-dir`).
 *
 * `keys.json` is managed by `FileKeyProvider`, the development-weak
 * provider (plaintext JWKs, mode 0600): it offers no protection against a
 * process that can read the file. `pending.json` holds `code_verifier`
 * values between `request` and `redeem`; treat it as secret material for
 * the same reason. There is no fallback to plaintext: if the configured
 * provider is unavailable the command fails loudly.
 */

export function keyProviderFor(stateDir: string): FileKeyProvider {
  return new FileKeyProvider(join(stateDir, 'keys.json'));
}

export function pendingPathFor(stateDir: string): string {
  return join(stateDir, 'pending.json');
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

/** Loads every stored key as a signer. Malformed entries are skipped. */
export async function loadSigners(stateDir: string): Promise<AgentSigner[]> {
  return keyProviderFor(stateDir).list();
}

/** Generates and persists a new key; returns the signer. */
export async function generateAndStoreKey(
  stateDir: string,
  kind: 'ed25519' | 'p256',
): Promise<AgentSigner> {
  return keyProviderFor(stateDir).generate(kind);
}

/** Loads persisted pending consent sessions (keyed by request_id). */
export async function loadPending(stateDir: string): Promise<PendingGrantRequest[]> {
  const parsed = await readJsonFile(pendingPathFor(stateDir));
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
  const all = (await loadPending(stateDir)).filter((r) => r.requestId !== record.requestId);
  all.push(record);
  await writeJsonFile(pendingPathFor(stateDir), all);
}

export async function dropPending(stateDir: string, requestId: string): Promise<void> {
  const all = (await loadPending(stateDir)).filter((r) => r.requestId !== requestId);
  await writeJsonFile(pendingPathFor(stateDir), all);
}
