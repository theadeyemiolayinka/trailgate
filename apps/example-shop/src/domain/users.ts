import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';
import { SHOP_CURRENCY } from './money.ts';

export interface User {
  id: string;
  email: string;
  name: string;
  createdAt: number;
}

export interface Session {
  id: string;
  userId: string;
  csrfToken: string;
  expiresAt: number;
}

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;

interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  created_at: number;
}

function toUser(row: UserRow): User {
  return { id: row.id, email: row.email, name: row.name, createdAt: row.created_at };
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, 64);
  return `scrypt:${salt.toString('base64url')}:${derived.toString('base64url')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [scheme, saltB64, hashB64] = stored.split(':');
  if (scheme !== 'scrypt' || saltB64 === undefined || hashB64 === undefined) {
    return false;
  }
  const derived = scryptSync(password, Buffer.from(saltB64, 'base64url'), 64);
  const expected = Buffer.from(hashB64, 'base64url');
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!EMAIL_RE.test(normalized) || normalized.length > 254) {
    throw new ValidationError('Enter a valid email address.');
  }
  return normalized;
}

export function validatePassword(password: string): string {
  if (password.length < 10 || password.length > 256) {
    throw new ValidationError('Password must be at least 10 characters.');
  }
  return password;
}

export function validateName(name: string): string {
  const trimmed = name.trim();
  if (trimmed.length < 1 || trimmed.length > 120) {
    throw new ValidationError('Name is required.');
  }
  return trimmed;
}

export class ValidationError extends Error {
  readonly fields: Record<string, string> | undefined;
  constructor(message: string, fields?: Record<string, string>) {
    super(message);
    this.name = 'ValidationError';
    this.fields = fields;
  }
}

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Registers a user and creates their wallet in one transaction. The wallet
 * starts empty except where the deterministic seed assigns a demo balance.
 */
export function createUser(
  db: Db,
  input: { email: string; name: string; password: string },
  options: { now?: number; id?: string } = {},
): User {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const email = validateEmail(input.email);
  const name = validateName(input.name);
  const password = validatePassword(input.password);
  const id = options.id ?? newId('usr');
  db.exec('BEGIN');
  try {
    db.prepare(
      'INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(id, email, name, hashPassword(password), now);
    db.prepare(
      'INSERT INTO wallets (user_id, currency, balance_minor, created_at) VALUES (?, ?, 0, ?)',
    ).run(id, SHOP_CURRENCY, now);
    db.prepare('INSERT INTO carts (id, user_id, created_at) VALUES (?, ?, ?)').run(
      `cart_${id}`,
      id,
      now,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    if (err instanceof Error && err.message.includes('UNIQUE')) {
      throw new ValidationError('An account with this email already exists.');
    }
    throw err;
  }
  return { id, email, name, createdAt: now };
}

export function findUserByEmail(
  db: Db,
  email: string,
): (User & { passwordHash: string }) | undefined {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase()) as
    | UserRow
    | undefined;
  return row === undefined ? undefined : { ...toUser(row), passwordHash: row.password_hash };
}

export function getUser(db: Db, id: string): User | undefined {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  return row === undefined ? undefined : toUser(row);
}

export function authenticate(db: Db, email: string, password: string): User {
  const found = findUserByEmail(db, email);
  if (found === undefined || !verifyPassword(password, found.passwordHash)) {
    throw new AuthError('Email or password is incorrect.');
  }
  return found;
}

export function createSession(
  db: Db,
  userId: string,
  now: number = Math.floor(Date.now() / 1000),
): Session {
  const session: Session = {
    id: newId('ses'),
    userId,
    csrfToken: randomBytes(24).toString('base64url'),
    expiresAt: now + SESSION_TTL_SECONDS,
  };
  db.prepare(
    'INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
  ).run(session.id, userId, session.csrfToken, now, session.expiresAt);
  return session;
}

export function getSession(
  db: Db,
  id: string,
  now = Math.floor(Date.now() / 1000),
): Session | undefined {
  const row = db
    .prepare('SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?')
    .get(id) as { id: string; user_id: string; csrf_token: string; expires_at: number } | undefined;
  if (row === undefined || row.expires_at <= now) {
    return undefined;
  }
  return { id: row.id, userId: row.user_id, csrfToken: row.csrf_token, expiresAt: row.expires_at };
}

export function destroySession(db: Db, id: string): void {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

export interface Address {
  id: string;
  userId: string;
  label: string;
  line1: string;
  line2?: string;
  city: string;
  region?: string;
  postcode: string;
  country: string;
  isDefault: boolean;
}

interface AddressRow {
  id: string;
  user_id: string;
  label: string;
  line1: string;
  line2: string | null;
  city: string;
  region: string | null;
  postcode: string;
  country: string;
  is_default: number;
}

function toAddress(row: AddressRow): Address {
  return {
    id: row.id,
    userId: row.user_id,
    label: row.label,
    line1: row.line1,
    ...(row.line2 !== null ? { line2: row.line2 } : {}),
    city: row.city,
    ...(row.region !== null ? { region: row.region } : {}),
    postcode: row.postcode,
    country: row.country,
    isDefault: row.is_default === 1,
  };
}

export function listAddresses(db: Db, userId: string): Address[] {
  return (
    db
      .prepare('SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, label')
      .all(userId) as unknown as AddressRow[]
  ).map(toAddress);
}

export function getAddress(db: Db, id: string, userId: string): Address | undefined {
  const row = db.prepare('SELECT * FROM addresses WHERE id = ? AND user_id = ?').get(id, userId) as
    | AddressRow
    | undefined;
  return row === undefined ? undefined : toAddress(row);
}

export function saveAddress(
  db: Db,
  userId: string,
  input: Omit<Address, 'id' | 'userId'>,
): Address {
  for (const [name, value] of [
    ['label', input.label],
    ['line1', input.line1],
    ['city', input.city],
    ['postcode', input.postcode],
    ['country', input.country],
  ] as const) {
    if (typeof value !== 'string' || value.trim().length === 0 || value.length > 200) {
      throw new ValidationError(`${name} is required`);
    }
  }
  const id = newId('adr');
  db.exec('BEGIN');
  try {
    if (input.isDefault) {
      db.prepare('UPDATE addresses SET is_default = 0 WHERE user_id = ?').run(userId);
    }
    db.prepare(
      `INSERT INTO addresses (id, user_id, label, line1, line2, city, region, postcode, country, is_default)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      userId,
      input.label.trim(),
      input.line1.trim(),
      input.line2?.trim() ?? null,
      input.city.trim(),
      input.region?.trim() ?? null,
      input.postcode.trim(),
      input.country.trim(),
      input.isDefault ? 1 : 0,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { id, userId, ...input };
}

export function deleteAddress(db: Db, id: string, userId: string): void {
  db.prepare('DELETE FROM addresses WHERE id = ? AND user_id = ?').run(id, userId);
}
