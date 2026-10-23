import type { Jwk } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import type { TrailGateServer } from '@trailgate/server';
import { createTrailGateServer, generateSigningKeyPair } from '@trailgate/server';
import type { ShopConfig } from '../config.ts';
import type { Db } from '../db/database.ts';
import type { ShopPolicy } from '../policy.ts';
import { SHOP_POLICY } from '../policy.ts';
import type { SqliteAuditSink } from './stores.ts';
import {
  createAgentKeyDirectory,
  createAuditSink,
  createGrantRegistry,
  createGrantRequestStore,
  createIdempotencyStore,
  createNonceStore,
  createRateLimiter,
  createSpendingLedger,
} from './stores.ts';
import { isShopSelector, PERMISSIONS } from './vocabulary.ts';

/**
 * Loads the persisted site signing key, generating one on first run. The
 * private JWK is stored in the SQLite database under `app_settings` so
 * issued grants survive restarts. This is a development convenience: a real
 * deployment sources `signingKeys` from its KMS or secret store and never
 * writes private key material to the application database.
 */
function loadOrCreateSiteKey(db: Db): Jwk {
  const row = db.prepare("SELECT value FROM app_settings WHERE key = 'site_signing_jwk'").get() as
    | { value: string }
    | undefined;
  if (row !== undefined) {
    return JSON.parse(row.value) as Jwk;
  }
  const { privateJwk } = generateSigningKeyPair('EdDSA');
  db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run(
    'site_signing_jwk',
    JSON.stringify(privateJwk),
  );
  return privateJwk;
}

/**
 * Resolves a resource selector to the user id that owns it, for the stage-11
 * cross-user isolation check (spec section 8). Unknown selectors and
 * selectors for nonexistent rows both return undefined, which the
 * enforcement pipeline denies.
 */
function ownerOf(db: Db, selector: string): string | undefined {
  const [type, id] = selector.split(':', 2);
  if (type === undefined || id === undefined) {
    return undefined;
  }
  if (type === 'cart') {
    const row = db.prepare('SELECT user_id FROM carts WHERE id = ?').get(id) as
      | { user_id: string }
      | undefined;
    return row?.user_id;
  }
  if (type === 'wallet') {
    const row = db
      .prepare('SELECT user_id FROM wallets WHERE user_id = ?')
      .get(id.replace(/^wlt_/, '')) as { user_id: string } | undefined;
    return row?.user_id;
  }
  if (type === 'order') {
    const row = db.prepare('SELECT user_id FROM orders WHERE id = ?').get(id) as
      | { user_id: string }
      | undefined;
    return row?.user_id;
  }
  return undefined;
}

export interface ShopTrailGate {
  tg: TrailGateServer;
  audit: SqliteAuditSink;
  /** Server-authoritative spending policy shown to users and enforced at intake and charge time. */
  spendingPolicy: ShopPolicy;
}

/**
 * Configures the Server SDK over durable SQLite stores. All TrailGate
 * enforcement lives in the SDK; the app supplies vocabulary, stores, the
 * subject mapping, the resource-ownership resolver, and a stage-13 site
 * policy that denies grants whose subject no longer resolves to a user.
 */
export function createShopTrailGate(db: Db, config: ShopConfig): ShopTrailGate {
  const now = () => Math.floor(Date.now() / 1000);
  const audit = createAuditSink(db);
  const tg = createTrailGateServer({
    issuer: config.issuer,
    signingKeys: [{ privateJwk: loadOrCreateSiteKey(db) }],
    permissions: [...PERMISSIONS],
    maxGrantSeconds: 86_400,
    defaultGrantSeconds: 3600,
    stores: {
      grantRequests: createGrantRequestStore(db),
      agentKeys: createAgentKeyDirectory(db),
      grants: createGrantRegistry(db),
      nonces: createNonceStore(db),
      idempotency: createIdempotencyStore(db),
      ledger: createSpendingLedger(db, now),
      rateLimiter: createRateLimiter(db),
      audit,
    },
    subjectFor: (userId) => userId,
    resourceOwners: { ownerOf: async (selector) => ownerOf(db, selector) },
    resourcePolicy: (selectors) => {
      const bad = selectors.filter((s) => !isShopSelector(s));
      if (bad.length > 0) {
        throw new TrailGateError(
          Codes.GRANT_SCOPE_REJECTED,
          'resource selector outside shop namespace',
          {
            rejected: bad,
          },
        );
      }
    },
    refineScope: (requested) => ({
      permissions: [...requested.permissions],
      resources: [...requested.resources],
      // Site policy ceiling: a cumulative_budget above the shop maximum is
      // tightened to the maximum, never loosened (spec section 9.3).
      constraints: requested.constraints.map((c) =>
        c.type === 'cumulative_budget' &&
        typeof c.params?.['amount'] === 'number' &&
        c.params['amount'] > config.maxGrantBudgetMinor &&
        c.params['currency'] === config.policyCurrency
          ? {
              type: c.type,
              params: { ...c.params, amount: config.maxGrantBudgetMinor },
            }
          : c,
      ),
      lifetimeSeconds: requested.requestedSeconds ?? 3600,
    }),
    policy: {
      authorize: async (ctx) => {
        if (ctx.subject !== undefined) {
          const row = db.prepare('SELECT id FROM users WHERE id = ?').get(ctx.subject);
          if (row === undefined) {
            throw new TrailGateError(
              Codes.AUTHORIZATION_DENIED,
              'grant subject is not a shop account',
            );
          }
        }
      },
    },
    capabilities: {
      supports_redirect: true,
      rate_limits: {
        site: { max_requests: 240, window_seconds: 60, note: 'informational site-level limit' },
      },
    },
  });
  return {
    tg,
    audit,
    spendingPolicy: {
      maxCharge: { amount: config.maxChargeMinor, currency: config.policyCurrency },
      maxGrantBudget: { amount: config.maxGrantBudgetMinor, currency: config.policyCurrency },
      currency: config.policyCurrency,
    },
  };
}
