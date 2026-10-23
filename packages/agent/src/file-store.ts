import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { GrantStore, StoredGrantRecord } from './store.ts';
import { recordFromGrantToken } from './store.ts';

/**
 * JSON-file `GrantStore` for CLIs and local daemons.
 *
 * Trust model: the file is a persistence boundary, so its contents are
 * untrusted input on load. Each record's embedded grant token is re-parsed
 * and its claims (jti, issuer, key binding, expiry) are cross-checked
 * against the stored metadata; tampered or malformed records are dropped.
 *
 * Durability: writes go to a sibling temp file then rename, so a crash
 * mid-write leaves the previous file intact. Concurrent writers across
 * processes are NOT serialized; use one process per store file.
 *
 * The file mode is set owner-read/write-only (0600). Grant tokens are
 * bearer artifacts until expiry: protect the file accordingly.
 */
export class FileGrantStore implements GrantStore {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async #load(): Promise<Map<string, StoredGrantRecord>> {
    let text: string;
    try {
      text = await readFile(this.path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return new Map();
      }
      throw err;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return new Map();
    }
    if (!Array.isArray(parsed)) {
      return new Map();
    }
    const records = new Map<string, StoredGrantRecord>();
    for (const item of parsed) {
      const record = validateRecord(item);
      if (record !== undefined) {
        records.set(record.jti, record);
      }
    }
    return records;
  }

  async #save(records: Map<string, StoredGrantRecord>): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify([...records.values()]), {
      encoding: 'utf8',
      mode: 0o600,
    });
    await rename(tmp, this.path);
  }

  async put(record: StoredGrantRecord): Promise<void> {
    const records = await this.#load();
    records.set(record.jti, record);
    await this.#save(records);
  }

  async get(jti: string): Promise<StoredGrantRecord | undefined> {
    return (await this.#load()).get(jti);
  }

  async remove(jti: string): Promise<void> {
    const records = await this.#load();
    if (records.delete(jti)) {
      await this.#save(records);
    }
  }

  async list(filter?: { issuer?: string }): Promise<StoredGrantRecord[]> {
    const all = [...(await this.#load()).values()];
    return filter?.issuer === undefined
      ? all
      : all.filter((record) => record.issuer === filter.issuer);
  }
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

/**
 * Validates one persisted record. Returns undefined when the shape is wrong
 * or the embedded token does not re-derive to the same identity claims.
 */
function validateRecord(item: unknown): StoredGrantRecord | undefined {
  if (typeof item !== 'object' || item === null || Array.isArray(item)) {
    return undefined;
  }
  const raw = item as Record<string, unknown>;
  if (
    typeof raw.jti !== 'string' ||
    typeof raw.issuer !== 'string' ||
    typeof raw.token !== 'string' ||
    typeof raw.keyId !== 'string' ||
    typeof raw.issuedAt !== 'number' ||
    typeof raw.expiresAt !== 'number' ||
    !isStringArray(raw.permissions) ||
    !isStringArray(raw.resources)
  ) {
    return undefined;
  }
  let derived: StoredGrantRecord;
  try {
    derived = recordFromGrantToken(raw.token);
  } catch {
    return undefined;
  }
  if (
    derived.jti !== raw.jti ||
    derived.issuer !== raw.issuer ||
    derived.keyId !== raw.keyId ||
    derived.issuedAt !== raw.issuedAt ||
    derived.expiresAt !== raw.expiresAt
  ) {
    return undefined;
  }
  // The embedded token is authoritative for scope; metadata in the file is
  // only an index and is cross-checked above.
  return derived;
}
