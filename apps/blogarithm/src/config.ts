import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface BlogConfig {
  /**
   * The TrailGate issuer identity: a bare https origin (spec section 5.3).
   * In plain-HTTP dev mode it is the signed-URI authority; the shipped
   * loopback transport maps it to the HTTP listener.
   */
  issuer: string;
  /** Bind address for both listeners; use 0.0.0.0 for LAN testing. */
  host: string;
  /** HTTP listener port for the blog UI and (dev) protocol traffic. */
  httpPort: number;
  /** HTTPS listener port used when dev certs exist; should match issuer's port. */
  tlsPort: number;
  /** Whether TLS mode is active (certs loaded). */
  tls: boolean;
  /** SQLite database file, or ':memory:'. */
  dbPath: string;
  /** Whether to seed deterministic demo data when the database is empty. */
  seed: boolean;
  /** Directory holding dev CA + server certificate. */
  certsDir: string;
}

const appRoot = fileURLToPath(new URL('..', import.meta.url));

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): BlogConfig {
  const tlsPort = intFromEnv('BLOG_TLS_PORT', 3444);
  const issuer = env.BLOG_ISSUER ?? `https://localhost:${tlsPort}`;
  const issuerUrl = new URL(issuer);
  if (issuerUrl.protocol !== 'https:' || issuerUrl.pathname !== '/' || issuerUrl.search !== '') {
    throw new Error('BLOG_ISSUER must be a bare https origin (scheme, host, optional port)');
  }
  return {
    issuer: issuerUrl.origin,
    host: env.BLOG_HOST ?? '127.0.0.1',
    httpPort: intFromEnv('BLOG_PORT', 3401),
    tlsPort,
    tls: env.BLOG_TLS === '1' || env.BLOG_TLS === 'true',
    dbPath: env.BLOG_DB ?? join(appRoot, 'data', 'blogarithm.db'),
    seed: env.BLOG_SEED !== '0',
    certsDir: env.BLOG_CERTS_DIR ?? join(appRoot, 'dev-certs'),
  };
}
