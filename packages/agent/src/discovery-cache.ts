import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { SiteContext } from './discovery.ts';

/** One cached discovery result; `staleAt` triggers refetch per spec 5.4. */
export interface DiscoveryCacheEntry {
  context: SiteContext;
  /** Unix seconds after which the cached document is stale. */
  staleAt: number;
}

/**
 * The cache contract `createAgentClient` accepts via
 * `options.discoveryCache`. A `Map` satisfies it for in-process caching;
 * `FileDiscoveryCache` persists entries across processes for CLI and
 * long-lived runtimes.
 */
export interface DiscoveryCache {
  get(origin: string): DiscoveryCacheEntry | undefined;
  set(origin: string, entry: DiscoveryCacheEntry): void;
}

interface CacheFile {
  entries?: Record<string, DiscoveryCacheEntry>;
}

/**
 * JSON-file discovery cache. Entries are keyed by validated origin (never by
 * user-supplied strings) and expire exactly like the in-memory cache:
 * `staleAt` comes from the spec section 5.4 rule, so a stale or removed
 * entry simply forces a refetch. Write-through on every `set` via an atomic
 * rename; a corrupt or unreadable file behaves like an empty cache rather
 * than failing the process.
 */
export class FileDiscoveryCache implements DiscoveryCache {
  readonly path: string;
  #entries = new Map<string, DiscoveryCacheEntry>();

  constructor(path: string) {
    this.path = path;
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as CacheFile;
      for (const [origin, entry] of Object.entries(parsed.entries ?? {})) {
        if (
          typeof entry?.staleAt === 'number' &&
          typeof entry?.context?.origin === 'string' &&
          entry.context.origin === origin
        ) {
          this.#entries.set(origin, entry);
        }
      }
    } catch {
      // Missing or corrupt cache file: treat as empty; discovery refetches.
    }
  }

  get(origin: string): DiscoveryCacheEntry | undefined {
    return this.#entries.get(origin);
  }

  set(origin: string, entry: DiscoveryCacheEntry): void {
    this.#entries.set(origin, entry);
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ entries: Object.fromEntries(this.#entries) }, null, 2));
    renameSync(tmp, this.path);
  }
}
