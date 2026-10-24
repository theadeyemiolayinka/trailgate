import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';

export interface User {
  id: string;
  email: string;
  name: string;
  username: string;
  bio: string;
  avatar: string;
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
  username: string;
  bio: string;
  avatar: string;
  password_hash: string;
  created_at: number;
}

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    username: row.username,
    bio: row.bio,
    avatar: row.avatar,
    createdAt: row.created_at,
  };
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
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;

export function validateEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!EMAIL_RE.test(normalized) || normalized.length > 254) {
    throw new ValidationError('Enter a valid email address.');
  }
  return normalized;
}

export function validateUsername(username: string): string {
  const normalized = username.trim().toLowerCase();
  if (!USERNAME_RE.test(normalized)) {
    throw new ValidationError(
      'Username must be 3-30 characters: lowercase letters, digits, dash or underscore.',
    );
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

export function createUser(
  db: Db,
  input: { email: string; name: string; username: string; password: string },
  options: { now?: number; id?: string; bio?: string; avatar?: string } = {},
): User {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const email = validateEmail(input.email);
  const name = validateName(input.name);
  const username = validateUsername(input.username);
  const password = validatePassword(input.password);
  const id = options.id ?? newId('usr');
  const bio = options.bio ?? '';
  const avatar = options.avatar ?? '';
  try {
    db.prepare(
      `INSERT INTO users (id, email, name, username, bio, avatar, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, email, name, username, bio, avatar, hashPassword(password), now);
  } catch (err) {
    if (err instanceof Error && err.message.includes('UNIQUE')) {
      throw new ValidationError('An account with this email or username already exists.');
    }
    throw err;
  }
  return { id, email, name, username, bio, avatar, createdAt: now };
}

export function updateProfile(
  db: Db,
  userId: string,
  input: {
    name?: string | undefined;
    username?: string | undefined;
    bio?: string | undefined;
    avatar?: string | undefined;
  },
): void {
  const sets: string[] = [];
  const values: (string | null)[] = [];
  if (input.name !== undefined) {
    sets.push('name = ?');
    values.push(validateName(input.name));
  }
  if (input.username !== undefined) {
    sets.push('username = ?');
    values.push(validateUsername(input.username));
  }
  if (input.bio !== undefined) {
    if (input.bio.length > 500) {
      throw new ValidationError('Bio must be at most 500 characters.');
    }
    sets.push('bio = ?');
    values.push(input.bio.trim());
  }
  if (input.avatar !== undefined) {
    if (input.avatar.length > 500) {
      throw new ValidationError('Avatar URL is too long.');
    }
    sets.push('avatar = ?');
    values.push(input.avatar.trim());
  }
  if (sets.length === 0) {
    return;
  }
  try {
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...values, userId);
  } catch (err) {
    if (err instanceof Error && err.message.includes('UNIQUE')) {
      throw new ValidationError('That username is taken.');
    }
    throw err;
  }
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

export function getUserByUsername(db: Db, username: string): User | undefined {
  const row = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username.trim().toLowerCase()) as UserRow | undefined;
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
