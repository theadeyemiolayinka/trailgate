import type { Db } from '../db/database.ts';
import { newId } from '../db/ids.ts';

export interface Notification {
  id: string;
  userId: string;
  type: string;
  title: string;
  message: string;
  resourceId?: string;
  createdAt: number;
  readAt?: number;
}

interface NotificationRow {
  id: string;
  user_id: string;
  type: string;
  title: string;
  message: string;
  resource_id: string | null;
  created_at: number;
  read_at: number | null;
}

function toNotification(row: NotificationRow): Notification {
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type,
    title: row.title,
    message: row.message,
    ...(row.resource_id !== null ? { resourceId: row.resource_id } : {}),
    createdAt: row.created_at,
    ...(row.read_at !== null ? { readAt: row.read_at } : {}),
  };
}

export function notify(
  db: Db,
  userId: string,
  type: string,
  title: string,
  message: string,
  resourceId?: string,
  at: number = Math.floor(Date.now() / 1000),
): void {
  db.prepare(
    `INSERT INTO notifications (id, user_id, type, title, message, resource_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(newId('ntf'), userId, type, title, message, resourceId ?? null, at);
}

export function listNotifications(
  db: Db,
  userId: string,
  options: { unreadOnly?: boolean; limit?: number } = {},
): Notification[] {
  let sql = 'SELECT * FROM notifications WHERE user_id = ?';
  const args: (string | number)[] = [userId];
  if (options.unreadOnly === true) {
    sql += ' AND read_at IS NULL';
  }
  sql += ' ORDER BY created_at DESC';
  if (options.limit !== undefined) {
    sql += ' LIMIT ?';
    args.push(options.limit);
  }
  return (db.prepare(sql).all(...args) as unknown as NotificationRow[]).map(toNotification);
}

export function unreadCount(db: Db, userId: string): number {
  const row = db
    .prepare('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL')
    .get(userId) as { n: number };
  return row.n;
}

export function markRead(db: Db, userId: string, id: string, at?: number): boolean {
  const result = db
    .prepare(
      'UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL',
    )
    .run(at ?? Math.floor(Date.now() / 1000), id, userId);
  return result.changes > 0;
}

export function markAllRead(db: Db, userId: string, at?: number): void {
  db.prepare('UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL').run(
    at ?? Math.floor(Date.now() / 1000),
    userId,
  );
}
