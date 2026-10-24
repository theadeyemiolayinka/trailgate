import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface ShopConfig {
  /**
   * The TrailGate issuer identity: a bare https origin (spec section 5.3).
   * This is the protocol identity of the site, independent of the transport
   * the dev server actually listens on. In TLS mode it is also the public
   * origin; in plain-HTTP dev mode it is the signed-URI authority and the
   * shipped loopback transport maps it to the HTTP listener.
   */
  issuer: string;
  /** HTTP listener port for the shop UI and (dev) protocol traffic. */
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
  /**
   * Site spending policy (server-authoritative, minor units of
   * `policyCurrency`): the largest single wallet charge the shop will
   * execute for any caller, and the largest cumulative budget it will let
   * a grant carry. Communicated on the consent page; enforced at intake
   * (`refineScope` tightens budgets) and at charge time.
   */
  maxChargeMinor: number;
  maxGrantBudgetMinor: number;
  policyCurrency: string;
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

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ShopConfig {
  const tlsPort = intFromEnv('SHOP_TLS_PORT', 3443);
  const issuer = env.SHOP_ISSUER ?? `https://localhost:${tlsPort}`;
  const issuerUrl = new URL(issuer);
  if (issuerUrl.protocol !== 'https:' || issuerUrl.pathname !== '/' || issuerUrl.search !== '') {
    throw new Error('SHOP_ISSUER must be a bare https origin (scheme, host, optional port)');
  }
  return {
    issuer: issuerUrl.origin,
    httpPort: intFromEnv('SHOP_PORT', 3300),
    tlsPort,
    tls: env.SHOP_TLS === '1' || env.SHOP_TLS === 'true',
    dbPath: env.SHOP_DB ?? join(appRoot, 'data', 'example-shop.db'),
    seed: env.SHOP_SEED !== '0',
    certsDir: env.SHOP_CERTS_DIR ?? join(appRoot, 'dev-certs'),
    maxChargeMinor: intFromEnv('SHOP_MAX_CHARGE_MINOR', 10_000),
    maxGrantBudgetMinor: intFromEnv('SHOP_MAX_GRANT_BUDGET_MINOR', 50_000),
    policyCurrency: 'USD',
  };
}
