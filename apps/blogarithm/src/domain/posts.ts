import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';
import { notify } from './notifications.ts';
import { ValidationError } from './users.ts';

export type PostStatus = 'draft' | 'published' | 'deleted';

export interface Post {
  id: string;
  authorId: string;
  title: string;
  slug: string;
  excerpt: string;
  body: string;
  coverImage: string;
  tags: string[];
  status: PostStatus;
  commentsEnabled: boolean;
  publishedAt?: number;
  createdAt: number;
  updatedAt: number;
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StateError';
  }
}

interface PostRow {
  id: string;
  author_id: string;
  title: string;
  slug: string;
  excerpt: string;
  body: string;
  cover_image: string;
  tags: string;
  status: PostStatus;
  comments_enabled: number;
  published_at: number | null;
  created_at: number;
  updated_at: number;
}

function toPost(row: PostRow): Post {
  return {
    id: row.id,
    authorId: row.author_id,
    title: row.title,
    slug: row.slug,
    excerpt: row.excerpt,
    body: row.body,
    coverImage: row.cover_image,
    tags: JSON.parse(row.tags) as string[],
    status: row.status,
    commentsEnabled: row.comments_enabled === 1,
    ...(row.published_at !== null ? { publishedAt: row.published_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function slugify(title: string): string {
  return (
    title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'post'
  );
}

function uniqueSlug(db: Db, base: string, excludeId?: string): string {
  let slug = base;
  let n = 2;
  while (true) {
    const row = db.prepare('SELECT id FROM posts WHERE slug = ?').get(slug) as
      | { id: string }
      | undefined;
    if (row === undefined || row.id === excludeId) {
      return slug;
    }
    slug = `${base}-${n}`;
    n += 1;
  }
}

export function getPost(db: Db, id: string): Post | undefined {
  const row = db.prepare('SELECT * FROM posts WHERE id = ?').get(id) as PostRow | undefined;
  return row === undefined ? undefined : toPost(row);
}

export function getPostBySlug(db: Db, slug: string): Post | undefined {
  const row = db.prepare('SELECT * FROM posts WHERE slug = ?').get(slug) as PostRow | undefined;
  return row === undefined ? undefined : toPost(row);
}

/** Owner-scoped lookup. Returns undefined for posts the user does not own. */
export function getOwnPost(db: Db, id: string, userId: string): Post | undefined {
  const post = getPost(db, id);
  return post !== undefined && post.authorId === userId ? post : undefined;
}

export function listPosts(
  db: Db,
  userId: string,
  filter: { status?: PostStatus | undefined; q?: string | undefined } = {},
): Post[] {
  let sql = 'SELECT * FROM posts WHERE author_id = ?';
  const args: (string | number)[] = [userId];
  if (filter.status !== undefined) {
    sql += ' AND status = ?';
    args.push(filter.status);
  } else {
    sql += " AND status != 'deleted'";
  }
  if (filter.q !== undefined && filter.q.trim() !== '') {
    sql += ' AND (title LIKE ? OR body LIKE ?)';
    const like = `%${filter.q.trim()}%`;
    args.push(like, like);
  }
  sql += ' ORDER BY updated_at DESC';
  return (db.prepare(sql).all(...args) as unknown as PostRow[]).map(toPost);
}

export function listPublished(
  db: Db,
  filter: {
    q?: string | undefined;
    tag?: string | undefined;
    authorId?: string | undefined;
    limit?: number | undefined;
  } = {},
): Post[] {
  let sql = "SELECT * FROM posts WHERE status = 'published'";
  const args: (string | number)[] = [];
  if (filter.authorId !== undefined) {
    sql += ' AND author_id = ?';
    args.push(filter.authorId);
  }
  if (filter.q !== undefined && filter.q.trim() !== '') {
    sql += ' AND (title LIKE ? OR excerpt LIKE ? OR body LIKE ?)';
    const like = `%${filter.q.trim()}%`;
    args.push(like, like, like);
  }
  if (filter.tag !== undefined && filter.tag.trim() !== '') {
    sql += ' AND tags LIKE ?';
    args.push(`%"${filter.tag.trim()}"%`);
  }
  sql += ' ORDER BY published_at DESC';
  if (filter.limit !== undefined) {
    sql += ' LIMIT ?';
    args.push(filter.limit);
  }
  return (db.prepare(sql).all(...args) as unknown as PostRow[]).map(toPost);
}

export interface PostInput {
  title: string;
  excerpt?: string | undefined;
  body?: string | undefined;
  coverImage?: string | undefined;
  tags?: string[] | undefined;
}

interface ValidatedPostInput {
  title: string;
  excerpt: string;
  body: string;
  coverImage: string;
  tags: string[];
}

function validatePostInput(input: PostInput): ValidatedPostInput {
  const title = (input.title ?? '').trim();
  if (title.length < 1 || title.length > 200) {
    throw new ValidationError('Title is required (max 200 characters).');
  }
  const excerpt = (input.excerpt ?? '').trim();
  if (excerpt.length > 500) {
    throw new ValidationError('Excerpt must be at most 500 characters.');
  }
  const body = input.body ?? '';
  if (body.length > 200_000) {
    throw new ValidationError('Post body is too long.');
  }
  const coverImage = (input.coverImage ?? '').trim();
  if (coverImage.length > 500) {
    throw new ValidationError('Cover image URL is too long.');
  }
  const tags = (input.tags ?? []).map((t) => t.trim().toLowerCase()).filter((t) => t !== '');
  if (tags.length > 10 || tags.some((t) => t.length > 40)) {
    throw new ValidationError('Up to 10 tags of at most 40 characters each.');
  }
  return { title, excerpt, body, coverImage, tags };
}

export function createDraft(db: Db, authorId: string, input: PostInput, now?: number): Post {
  const at = now ?? Math.floor(Date.now() / 1000);
  const v = validatePostInput(input);
  const id = newId('post');
  const slug = uniqueSlug(db, slugify(v.title));
  db.exec('BEGIN');
  try {
    db.prepare(
      `INSERT INTO posts (id, author_id, title, slug, excerpt, body, cover_image, tags,
         status, comments_enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', 1, ?, ?)`,
    ).run(
      id,
      authorId,
      v.title,
      slug,
      v.excerpt,
      v.body,
      v.coverImage,
      JSON.stringify(v.tags),
      at,
      at,
    );
    notify(
      db,
      authorId,
      'draft_created',
      'Draft created',
      `"${v.title}" was saved as a draft.`,
      id,
      at,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return {
    ...v,
    id,
    authorId,
    slug,
    status: 'draft',
    commentsEnabled: true,
    createdAt: at,
    updatedAt: at,
  };
}

export function updatePost(
  db: Db,
  id: string,
  userId: string,
  input: PostInput & { commentsEnabled?: boolean },
  now?: number,
): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status === 'deleted') {
    throw new StateError('A deleted post cannot be edited.');
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  const v = validatePostInput(input);
  const slug = post.title === v.title ? post.slug : uniqueSlug(db, slugify(v.title), id);
  db.exec('BEGIN');
  try {
    db.prepare(
      `UPDATE posts SET title = ?, slug = ?, excerpt = ?, body = ?, cover_image = ?, tags = ?,
         comments_enabled = ?, updated_at = ? WHERE id = ?`,
    ).run(
      v.title,
      slug,
      v.excerpt,
      v.body,
      v.coverImage,
      JSON.stringify(v.tags),
      input.commentsEnabled === undefined
        ? post.commentsEnabled
          ? 1
          : 0
        : input.commentsEnabled
          ? 1
          : 0,
      at,
      id,
    );
    notify(db, userId, 'post_updated', 'Post updated', `"${v.title}" was updated.`, id, at);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return {
    ...post,
    ...v,
    slug,
    commentsEnabled: input.commentsEnabled ?? post.commentsEnabled,
    updatedAt: at,
  };
}

export function publishPost(db: Db, id: string, userId: string, now?: number): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status === 'published') {
    return post;
  }
  if (post.status === 'deleted') {
    throw new StateError('A deleted post cannot be published.');
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  db.exec('BEGIN');
  try {
    db.prepare(
      "UPDATE posts SET status = 'published', published_at = ?, updated_at = ? WHERE id = ?",
    ).run(at, at, id);
    notify(db, userId, 'post_published', 'Post published', `"${post.title}" is now live.`, id, at);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { ...post, status: 'published', publishedAt: at, updatedAt: at };
}

export function unpublishPost(db: Db, id: string, userId: string, now?: number): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status !== 'published') {
    throw new StateError('Only a published post can be unpublished.');
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  db.exec('BEGIN');
  try {
    db.prepare("UPDATE posts SET status = 'draft', updated_at = ? WHERE id = ?").run(at, id);
    notify(
      db,
      userId,
      'post_unpublished',
      'Post unpublished',
      `"${post.title}" was moved back to drafts.`,
      id,
      at,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  const { publishedAt: _dropped, ...rest } = post;
  return { ...rest, status: 'draft', updatedAt: at };
}

export function deletePost(db: Db, id: string, userId: string, now?: number): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status === 'deleted') {
    return post;
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  db.exec('BEGIN');
  try {
    db.prepare(
      "UPDATE posts SET status = 'deleted', previous_status = ?, deleted_at = ?, updated_at = ? WHERE id = ?",
    ).run(post.status, at, at, id);
    notify(
      db,
      userId,
      'post_deleted',
      'Post deleted',
      `"${post.title}" was moved to trash.`,
      id,
      at,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { ...post, status: 'deleted', updatedAt: at };
}

export function restorePost(db: Db, id: string, userId: string, now?: number): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status !== 'deleted') {
    throw new StateError('Only a deleted post can be restored.');
  }
  const previous = (
    db.prepare('SELECT previous_status FROM posts WHERE id = ?').get(id) as
      | { previous_status: string | null }
      | undefined
  )?.previous_status;
  const status: PostStatus = previous === 'published' ? 'published' : 'draft';
  const at = now ?? Math.floor(Date.now() / 1000);
  db.exec('BEGIN');
  try {
    db.prepare('UPDATE posts SET status = ?, deleted_at = NULL, updated_at = ? WHERE id = ?').run(
      status,
      at,
      id,
    );
    notify(db, userId, 'post_restored', 'Post restored', `"${post.title}" was restored.`, id, at);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { ...post, status, updatedAt: at };
}

export function setCommentsEnabled(
  db: Db,
  id: string,
  userId: string,
  enabled: boolean,
  now?: number,
): Post {
  const post = getOwnPost(db, id, userId);
  if (post === undefined) {
    throw new NotFoundError('Post not found.');
  }
  if (post.status === 'deleted') {
    throw new StateError('A deleted post cannot be changed.');
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  db.exec('BEGIN');
  try {
    db.prepare('UPDATE posts SET comments_enabled = ?, updated_at = ? WHERE id = ?').run(
      enabled ? 1 : 0,
      at,
      id,
    );
    notify(
      db,
      userId,
      enabled ? 'comments_enabled' : 'comments_disabled',
      enabled ? 'Comments enabled' : 'Comments disabled',
      `Comments were ${enabled ? 'enabled' : 'disabled'} on "${post.title}".`,
      id,
      at,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { ...post, commentsEnabled: enabled, updatedAt: at };
}
