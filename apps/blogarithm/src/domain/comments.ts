import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';
import { notify } from './notifications.ts';
import { getPost, NotFoundError, StateError } from './posts.ts';
import { ValidationError } from './users.ts';

export interface Comment {
  id: string;
  postId: string;
  authorName: string;
  body: string;
  createdAt: number;
}

interface CommentRow {
  id: string;
  post_id: string;
  author_name: string;
  body: string;
  created_at: number;
}

function toComment(row: CommentRow): Comment {
  return {
    id: row.id,
    postId: row.post_id,
    authorName: row.author_name,
    body: row.body,
    createdAt: row.created_at,
  };
}

export function getComment(db: Db, id: string): Comment | undefined {
  const row = db.prepare('SELECT * FROM comments WHERE id = ?').get(id) as CommentRow | undefined;
  return row === undefined ? undefined : toComment(row);
}

export function listComments(db: Db, postId: string): Comment[] {
  return (
    db
      .prepare('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at DESC')
      .all(postId) as unknown as CommentRow[]
  ).map(toComment);
}

/** Comments on posts owned by the user, newest first. */
export function listCommentsForOwner(db: Db, userId: string, limit = 100): Comment[] {
  return (
    db
      .prepare(
        `SELECT c.* FROM comments c JOIN posts p ON p.id = c.post_id
         WHERE p.author_id = ? ORDER BY c.created_at DESC LIMIT ?`,
      )
      .all(userId, limit) as unknown as CommentRow[]
  ).map(toComment);
}

/**
 * Public comment submission. Only published posts with comments_enabled
 * accept comments; unpublished or deleted posts reject them server-side.
 */
export function addComment(
  db: Db,
  postId: string,
  input: { authorName: string; body: string },
  now?: number,
): Comment {
  const post = getPost(db, postId);
  if (post === undefined || post.status !== 'published') {
    throw new ValidationError('Comments are not accepted on this post.');
  }
  if (!post.commentsEnabled) {
    throw new StateError('Comments are closed on this post.');
  }
  const authorName = input.authorName.trim();
  const body = input.body.trim();
  if (authorName.length < 1 || authorName.length > 80) {
    throw new ValidationError('A display name is required (max 80 characters).');
  }
  if (body.length < 1 || body.length > 2000) {
    throw new ValidationError('Comment must be 1-2000 characters.');
  }
  const at = now ?? Math.floor(Date.now() / 1000);
  const id = newId('cmt');
  db.exec('BEGIN');
  try {
    db.prepare(
      'INSERT INTO comments (id, post_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(id, postId, authorName, body, at);
    notify(
      db,
      post.authorId,
      'comment_received',
      'New comment',
      `${authorName} commented on "${post.title}".`,
      postId,
      at,
    );
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return { id, postId, authorName, body, createdAt: at };
}

/**
 * Deletes a comment. `postOwnerOnly` enforces that the caller owns the
 * parent post; agent flows go through resource ownership instead.
 */
export function deleteComment(db: Db, id: string, ownerId: string): void {
  const comment = getComment(db, id);
  if (comment === undefined) {
    throw new NotFoundError('Comment not found.');
  }
  const post = getPost(db, comment.postId);
  if (post === undefined || post.authorId !== ownerId) {
    throw new StateError('You can only delete comments on your own posts.');
  }
  db.prepare('DELETE FROM comments WHERE id = ?').run(id);
}
