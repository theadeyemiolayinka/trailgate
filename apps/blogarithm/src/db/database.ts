import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

/**
 * Database handle. `node:sqlite` is synchronous and single-connection;
 * all port implementations and domain operations use it directly. Write
 * paths that must be atomic run inside explicit transactions.
 */
export type Db = DatabaseSync;

export function openDatabase(path: string): Db {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new DatabaseSync(path);
  // busy_timeout must precede journal_mode: the WAL switch takes a lock that
  // cannot wait on the default zero timeout, so a second process opening the
  // database while a writer holds it would fail with "database is locked".
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  migrate(db);
  return db;
}

interface Migration {
  id: number;
  sql?: string;
  /** Conditional migration logic for changes that cannot be expressed idempotently in plain SQL. */
  apply?: (db: Db) => void;
}

/**
 * Ordered migrations, applied inside a transaction and recorded in
 * `schema_migrations`. Never edit an applied migration; append a new one.
 */
const MIGRATIONS: Migration[] = [
  {
    id: 1,
    sql: `
      CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        bio TEXT NOT NULL DEFAULT '',
        avatar TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX idx_sessions_user ON sessions(user_id);

      CREATE TABLE posts (
        id TEXT PRIMARY KEY,
        author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        excerpt TEXT NOT NULL DEFAULT '',
        body TEXT NOT NULL DEFAULT '',
        cover_image TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','deleted')),
        comments_enabled INTEGER NOT NULL DEFAULT 1,
        published_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        deleted_at INTEGER,
        previous_status TEXT
      );
      CREATE INDEX idx_posts_author ON posts(author_id);
      CREATE INDEX idx_posts_status ON posts(status, published_at);

      CREATE TABLE comments (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        author_name TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX idx_comments_post ON comments(post_id, created_at);

      CREATE TABLE notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        resource_id TEXT,
        created_at INTEGER NOT NULL,
        read_at INTEGER
      );
      CREATE INDEX idx_notifications_user ON notifications(user_id, created_at);
    `,
  },
  {
    id: 2,
    sql: `
      CREATE TABLE tg_grant_requests (
        request_id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','issued')),
        body TEXT NOT NULL,
        agent_jkt TEXT NOT NULL,
        subject TEXT,
        decided_at INTEGER,
        grant_id TEXT,
        effective_permissions TEXT,
        effective_resources TEXT,
        effective_constraints TEXT,
        effective_lifetime_seconds INTEGER
      );

      CREATE TABLE tg_agent_keys (
        jkt TEXT PRIMARY KEY,
        jwk TEXT NOT NULL,
        registered_at INTEGER NOT NULL
      );

      CREATE TABLE tg_grants (
        jti TEXT PRIMARY KEY,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        agent_jkt TEXT NOT NULL,
        subject TEXT,
        request_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active','revoked')),
        revoked_at INTEGER,
        revocation_reason TEXT,
        revocation_actor TEXT
      );
      CREATE INDEX idx_tg_grants_subject ON tg_grants(subject);

      CREATE TABLE tg_nonces (
        grant_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (grant_id, nonce)
      );

      CREATE TABLE tg_idempotency (
        grant_id TEXT NOT NULL,
        key TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        outcome TEXT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (grant_id, key)
      );

      CREATE TABLE tg_ledger_consumed (
        id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        reservation_id TEXT,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        at INTEGER NOT NULL
      );
      CREATE INDEX idx_tg_ledger_consumed_grant ON tg_ledger_consumed(grant_id, currency);

      CREATE TABLE tg_ledger_reservations (
        reservation_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('reserved','consumed','released')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX idx_tg_ledger_reservations_grant ON tg_ledger_reservations(grant_id, currency, state);

      CREATE TABLE tg_rate_hits (
        grant_id TEXT NOT NULL,
        at INTEGER NOT NULL
      );
      CREATE INDEX idx_tg_rate_hits_grant ON tg_rate_hits(grant_id, at);

      CREATE TABLE tg_audit (
        id TEXT PRIMARY KEY,
        at INTEGER NOT NULL,
        event TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE INDEX idx_tg_audit_at ON tg_audit(at);
    `,
  },
  {
    id: 3,
    sql: `
      CREATE TABLE app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `,
  },
  {
    id: 4,
    sql: `
      CREATE TABLE tg_receipts (
        id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        decision TEXT NOT NULL CHECK (decision IN ('allowed','denied')),
        code TEXT,
        receipt_jws TEXT NOT NULL,
        method TEXT NOT NULL,
        target TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX idx_tg_receipts_grant ON tg_receipts(grant_id, created_at);
    `,
  },
  {
    id: 5,
    sql: `
      CREATE TABLE tg_request_approvals (
        id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','used')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER
      );
      CREATE INDEX idx_tg_approvals_op ON tg_request_approvals(grant_id, operation_digest, state, expires_at);
    `,
  },
  {
    id: 6,
    sql: `
      -- permissions: the set signed into the grant at issuance.
      -- effective_permissions: the site's current set after post-issuance
      -- narrowing; NULL means unmodified.
      ALTER TABLE tg_grants ADD COLUMN permissions TEXT NOT NULL DEFAULT '[]';
      ALTER TABLE tg_grants ADD COLUMN effective_permissions TEXT;
      ALTER TABLE tg_grants ADD COLUMN effective_resources TEXT;
      CREATE INDEX idx_tg_grant_requests_agent ON tg_grant_requests(agent_jkt, created_at);
    `,
  },
  {
    id: 7,
    sql: `
      -- effective_constraints: the site's current constraint set after
      -- post-issuance changes; NULL means the signed set applies.
      ALTER TABLE tg_grants ADD COLUMN effective_constraints TEXT;
      -- Backfill the issued set for grants written before migration 6
      -- populated permissions: the request row's effective set is what was
      -- signed into the grant.
      UPDATE tg_grants SET permissions = COALESCE(
        (SELECT r.effective_permissions FROM tg_grant_requests r
          WHERE r.request_id = tg_grants.request_id),
        (SELECT json_extract(r2.body, '$.permissions') FROM tg_grant_requests r2
          WHERE r2.request_id = tg_grants.request_id),
        '[]'
      ) WHERE permissions = '[]';
    `,
  },
  {
    id: 8,
    // Databases that applied an early draft of migration 6 can be missing
    // tg_grants.effective_resources; ALTER COLUMN has no IF NOT EXISTS, so
    // the column is added only when absent.
    apply: (db) => {
      const cols = db.prepare('PRAGMA table_info(tg_grants)').all() as { name: string }[];
      if (!cols.some((c) => c.name === 'effective_resources')) {
        db.exec('ALTER TABLE tg_grants ADD COLUMN effective_resources TEXT');
      }
    },
  },
];

export function migrate(db: Db): void {
  db.exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)',
  );
  const applied = new Set(
    (db.prepare('SELECT id FROM schema_migrations').all() as { id: number }[]).map((r) => r.id),
  );
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.id)) {
      continue;
    }
    db.exec('BEGIN');
    try {
      if (migration.sql !== undefined) {
        db.exec(migration.sql);
      }
      migration.apply?.(db);
      db.prepare('INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)').run(
        migration.id,
        Math.floor(Date.now() / 1000),
      );
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
}
