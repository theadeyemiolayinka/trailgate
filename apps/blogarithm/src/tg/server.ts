import type { Jwk } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import type { TrailGateServer } from '@trailgate/server';
import { createTrailGateServer, generateSigningKeyPair } from '@trailgate/server';
import type { BlogConfig } from '../config.ts';
import type { Db } from '../db/database.ts';
import type { SqliteAuditSink } from './stores.ts';
import {
  createAgentKeyDirectory,
  createApprovalStore,
  createAuditSink,
  createGrantRegistry,
  createGrantRequestStore,
  createIdempotencyStore,
  createNonceStore,
  createRateLimiter,
} from './stores.ts';
import { bindBlogSelectors, isBlogSelector, PERMISSIONS } from './vocabulary.ts';

/**
 * Loads the persisted site signing key, generating one on first run so
 * issued grants survive restarts. Development convenience only: a real
 * deployment sources signingKeys from a secret store.
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
 * Resolves a resource selector to the owning user id for the cross-user
 * isolation check. Unknown selectors return undefined and are denied.
 */
function ownerOf(db: Db, selector: string): string | undefined {
  const [type, id] = selector.split(':', 2);
  if (type === undefined || id === undefined) {
    return undefined;
  }
  if (type === 'post') {
    const row = db.prepare('SELECT author_id FROM posts WHERE id = ?').get(id) as
      | { author_id: string }
      | undefined;
    return row?.author_id;
  }
  if (type === 'comment') {
    const row = db
      .prepare('SELECT p.author_id FROM comments c JOIN posts p ON p.id = c.post_id WHERE c.id = ?')
      .get(id) as { author_id: string } | undefined;
    return row?.author_id;
  }
  return undefined;
}

export interface BlogTrailGate {
  tg: TrailGateServer;
  audit: SqliteAuditSink;
}

/**
 * Configures the Server SDK over durable SQLite stores. All protocol
 * enforcement lives in the SDK; the app supplies vocabulary, stores,
 * subject mapping, resource ownership, and a site policy that denies
 * grants whose subject no longer resolves to a user.
 */
export function createBlogTrailGate(db: Db, config: BlogConfig): BlogTrailGate {
  const audit = createAuditSink(db);
  const tg = createTrailGateServer({
    issuer: config.issuer,
    signingKeys: [{ privateJwk: loadOrCreateSiteKey(db) }],
    permissions: [...PERMISSIONS],
    maxGrantSeconds: 86_400,
    defaultGrantSeconds: 3_600,
    maxConsentLifetimeSeconds: 86_400,
    stores: {
      grantRequests: createGrantRequestStore(db),
      agentKeys: createAgentKeyDirectory(db),
      grants: createGrantRegistry(db),
      nonces: createNonceStore(db),
      idempotency: createIdempotencyStore(db),
      rateLimiter: createRateLimiter(db),
      audit,
      approvals: createApprovalStore(db),
    },
    subjectFor: (userId) => userId,
    bindSubjectResources: (resources, subject) =>
      bindBlogSelectors(resources, subject, (userId) =>
        (
          db.prepare('SELECT id FROM posts WHERE author_id = ?').all(userId) as { id: string }[]
        ).map((r) => r.id),
      ),
    resourceOwners: { ownerOf: async (selector) => ownerOf(db, selector) },
    resourcePolicy: (selectors) => {
      const bad = selectors.filter((s) => !isBlogSelector(s));
      if (bad.length > 0) {
        throw new TrailGateError(
          Codes.GRANT_SCOPE_REJECTED,
          'resource selector outside blog namespace',
          { rejected: bad },
        );
      }
    },
    policy: {
      authorize: async (ctx) => {
        if (ctx.subject !== undefined) {
          const row = db.prepare('SELECT id FROM users WHERE id = ?').get(ctx.subject);
          if (row === undefined) {
            throw new TrailGateError(
              Codes.AUTHORIZATION_DENIED,
              'grant subject is not a blog account',
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
  return { tg, audit };
}
