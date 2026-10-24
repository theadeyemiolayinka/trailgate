import { Codes, decodeCompactJws, TrailGateError } from '@trailgate/core';
import type {
  EnforcementContext,
  HostRequest,
  HostResponse,
  TrailGateServer,
} from '@trailgate/server';
import type { Db } from '../db/database.ts';
import {
  deleteComment,
  getComment,
  listComments,
  listCommentsForOwner,
} from '../domain/comments.ts';
import { listNotifications, markAllRead, markRead, unreadCount } from '../domain/notifications.ts';
import {
  createDraft,
  deletePost,
  getOwnPost,
  listPosts,
  NotFoundError,
  type Post,
  type PostStatus,
  publishPost,
  restorePost,
  StateError,
  setCommentsEnabled,
  unpublishPost,
  updatePost,
} from '../domain/posts.ts';
import { getUser, ValidationError } from '../domain/users.ts';
import { commentSelector, postSelector } from '../tg/vocabulary.ts';

/**
 * Agent-facing JSON API. Every route runs through `tg.protect`, so the
 * spec section 11 pipeline (signature, grant, replay, idempotency,
 * permission, resource, constraints, site policy) executes before the
 * handler. Handlers see only verified context and operate on the grant
 * subject's own rows; ownership is structural, not an input parameter.
 */

interface ApiRoute {
  method: string;
  pattern: string;
  handle: (req: HostRequest) => Promise<HostResponse>;
}

function json(status: number, body: unknown): HostResponse {
  return { status, headers: { 'content-type': 'application/json' }, body };
}

function err(status: number, code: string, message: string): HostResponse {
  return json(status, { error: { code, message } });
}

function matchPath(pattern: string, path: string): Record<string, string> | undefined {
  const want = pattern.split('/').filter((s) => s !== '');
  const got = path.split('/').filter((s) => s !== '');
  if (want.length !== got.length) {
    return undefined;
  }
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    const segment = want[i] as string;
    if (segment.startsWith(':')) {
      params[segment.slice(1)] = decodeURIComponent(got[i] as string);
    } else if (segment !== got[i]) {
      return undefined;
    }
  }
  return params;
}

function paramsOf(req: HostRequest, pattern: string): Record<string, string> {
  const params = matchPath(pattern, new URL(req.url).pathname);
  if (params === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request path did not match route');
  }
  return params;
}

function param(params: Record<string, string>, name: string): string {
  const value = params[name];
  if (value === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `missing path parameter ${name}`);
  }
  return value;
}

function bodyObject(req: HostRequest): Record<string, unknown> {
  const body = req.body;
  if (body === undefined) {
    return {};
  }
  const text = typeof body === 'string' ? body : new TextDecoder().decode(body);
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request body must be a json object');
}

/** The grant's bound user context. Actions never trust a caller-supplied id. */
function requireSubject(ctx: EnforcementContext): string {
  if (ctx.subject === undefined) {
    throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'grant carries no user subject');
  }
  return ctx.subject;
}

function postView(post: Post): Record<string, unknown> {
  return {
    id: post.id,
    title: post.title,
    slug: post.slug,
    excerpt: post.excerpt,
    status: post.status,
    tags: post.tags,
    comments_enabled: post.commentsEnabled,
    published_at: post.publishedAt ?? null,
    created_at: post.createdAt,
    updated_at: post.updatedAt,
    selector: postSelector(post.id),
  };
}

function postInputFrom(body: Record<string, unknown>): {
  title: string;
  excerpt?: string;
  body?: string;
  coverImage?: string;
  tags?: string[];
} {
  const input: Record<string, unknown> = {};
  const title = body.title;
  if (typeof title !== 'string') {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'body must carry title (string)');
  }
  input.title = title;
  if (body.excerpt !== undefined) {
    input.excerpt = body.excerpt;
  }
  if (body.body !== undefined) {
    input.body = body.body;
  }
  if (body.cover_image !== undefined) {
    input.coverImage = body.cover_image;
  }
  if (body.tags !== undefined) {
    input.tags = body.tags;
  }
  return input as { title: string };
}

function domainError(e: unknown): HostResponse {
  if (e instanceof NotFoundError) {
    return err(404, 'blog.resource.not_found', e.message);
  }
  if (e instanceof StateError || e instanceof ValidationError) {
    return err(422, 'blog.state.invalid', e.message);
  }
  throw e;
}

/** Persists the signed receipt a protected response carries for later inspection. */
function captureReceipt(db: Db, req: HostRequest, res: HostResponse): void {
  const header = res.headers?.['trailgate-receipt'];
  if (typeof header !== 'string' || header === '') {
    return;
  }
  try {
    const { payload } = decodeCompactJws(header);
    const jti = (payload as { jti?: string }).jti;
    const grantJti = (payload as { grant_id?: string }).grant_id;
    if (typeof jti !== 'string' || typeof grantJti !== 'string') {
      return;
    }
    db.prepare(
      `INSERT OR REPLACE INTO tg_receipts (jti, grant_id, action, method, target, status, receipt, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      jti,
      grantJti,
      new URL(req.url).pathname,
      req.method,
      req.url,
      res.status,
      header,
      Math.floor(Date.now() / 1000),
    );
  } catch {
    // receipt persistence is best-effort; enforcement already succeeded
  }
}

export function createAgentApi(
  db: Db,
  tg: TrailGateServer,
): { dispatch: (req: HostRequest) => Promise<HostResponse | undefined> } {
  const routes: ApiRoute[] = [
    {
      method: 'GET',
      pattern: '/api/profile',
      handle: tg.protect(
        {
          permission: 'tg.profile.read',
          mutating: false,
          action: {
            id: 'profile.read',
            method: 'GET',
            path: '/api/profile',
            description: 'read the author profile bound to this grant',
          },
        },
        async (_req, ctx) => {
          const user = getUser(db, requireSubject(ctx));
          return user === undefined
            ? err(404, 'blog.profile.not_found', 'profile not found')
            : json(200, {
                user: {
                  id: user.id,
                  name: user.name,
                  username: user.username,
                  bio: user.bio,
                  avatar: user.avatar,
                  created_at: user.createdAt,
                },
              });
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/posts',
      handle: tg.protect(
        {
          permission: 'tg.posts.read',
          mutating: false,
          action: {
            id: 'posts.list',
            method: 'GET',
            path: '/api/posts',
            description:
              'list the owner posts (query: status=draft|published|deleted, q=search text)',
          },
        },
        async (req, ctx) => {
          const url = new URL(req.url);
          const status = url.searchParams.get('status');
          const q = url.searchParams.get('q') ?? undefined;
          if (status !== null && !['draft', 'published', 'deleted'].includes(status)) {
            return err(400, 'blog.request.invalid', 'status must be draft, published, or deleted');
          }
          const posts = listPosts(db, requireSubject(ctx), {
            ...(status !== null ? { status: status as PostStatus } : {}),
            ...(q !== null ? { q } : {}),
          });
          return json(200, { posts: posts.map(postView) });
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/posts/:id',
      handle: tg.protect(
        {
          permission: 'tg.posts.read',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id'), 'id')}`,
          mutating: false,
          action: {
            id: 'posts.get',
            method: 'GET',
            path: '/api/posts/{id}',
            description: 'read one owned post including body and status',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const post = getOwnPost(
            db,
            param(paramsOf(req, '/api/posts/:id'), 'id'),
            requireSubject(ctx),
          );
          return post === undefined
            ? err(404, 'blog.post.not_found', 'post not found')
            : json(200, { post: { ...postView(post), body: post.body } });
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/posts',
      handle: tg.protect(
        {
          permission: 'tg.posts.create',
          action: {
            id: 'posts.create_draft',
            method: 'POST',
            path: '/api/posts',
            description:
              'create a draft post (body: {title, excerpt?, body?, cover_image?, tags?[]})',
          },
        },
        async (req, ctx) => {
          try {
            const post = createDraft(db, requireSubject(ctx), postInputFrom(bodyObject(req)));
            return json(201, { post: { ...postView(post), body: post.body } });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'PATCH',
      pattern: '/api/posts/:id',
      handle: tg.protect(
        {
          permission: 'tg.posts.update',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id'), 'id')}`,
          action: {
            id: 'posts.update',
            method: 'PATCH',
            path: '/api/posts/{id}',
            description:
              'edit an owned draft or published post (body: {title, excerpt?, body?, cover_image?, tags?[]})',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id'), 'id');
          try {
            const post = updatePost(db, id, requireSubject(ctx), postInputFrom(bodyObject(req)));
            return json(200, { post: { ...postView(post), body: post.body } });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      // Approval-gated (spec section 12.5): publishing is public, so the
      // agent submits a proposal and the site user decides. The stored
      // request replays through this handler only after approval.
      method: 'POST',
      pattern: '/api/posts/:id/publish',
      handle: tg.protect(
        {
          permission: 'tg.posts.publish',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id/publish'), 'id')}`,
          approval: 'required',
          describe: (req, ctx) => {
            const id = matchPath('/api/posts/:id/publish', new URL(req.url).pathname)?.id;
            const post =
              id !== undefined && ctx.subject !== undefined
                ? getOwnPost(db, id, ctx.subject)
                : undefined;
            return post === undefined
              ? { summary: `Publish post ${id ?? '(unknown)'}` }
              : {
                  summary: `Publish the post "${post.title}" to the public blog`,
                  detail: {
                    post_id: post.id,
                    title: post.title,
                    slug: post.slug,
                    status: post.status,
                  },
                };
          },
          action: {
            id: 'posts.publish',
            method: 'POST',
            path: '/api/posts/{id}/publish',
            description: 'publish an owned draft to the public blog (requires human approval)',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id/publish'), 'id');
          try {
            const post = publishPost(db, id, requireSubject(ctx));
            return json(200, { post: postView(post) });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/posts/:id/unpublish',
      handle: tg.protect(
        {
          permission: 'tg.posts.publish',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id/unpublish'), 'id')}`,
          action: {
            id: 'posts.unpublish',
            method: 'POST',
            path: '/api/posts/{id}/unpublish',
            description: 'unpublish an owned post back to a private draft',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id/unpublish'), 'id');
          try {
            const post = unpublishPost(db, id, requireSubject(ctx));
            return json(200, { post: postView(post) });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'DELETE',
      pattern: '/api/posts/:id',
      handle: tg.protect(
        {
          permission: 'tg.posts.delete',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id'), 'id')}`,
          action: {
            id: 'posts.delete',
            method: 'DELETE',
            path: '/api/posts/{id}',
            description: 'move an owned post to trash',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id'), 'id');
          try {
            const post = deletePost(db, id, requireSubject(ctx));
            return json(200, { post: postView(post) });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/posts/:id/restore',
      handle: tg.protect(
        {
          permission: 'tg.posts.delete',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id/restore'), 'id')}`,
          action: {
            id: 'posts.restore',
            method: 'POST',
            path: '/api/posts/{id}/restore',
            description: 'restore an owned post from trash',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id/restore'), 'id');
          try {
            const post = restorePost(db, id, requireSubject(ctx));
            return json(200, { post: postView(post) });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/posts/:id/settings',
      handle: tg.protect(
        {
          permission: 'tg.posts.settings',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id/settings'), 'id')}`,
          action: {
            id: 'posts.settings.update',
            method: 'POST',
            path: '/api/posts/{id}/settings',
            description: 'change post settings (body: {comments_enabled: boolean})',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id/settings'), 'id');
          const enabled = bodyObject(req).comments_enabled;
          if (typeof enabled !== 'boolean') {
            return err(400, 'blog.request.invalid', 'body must carry comments_enabled (boolean)');
          }
          try {
            const post = setCommentsEnabled(db, id, requireSubject(ctx), enabled);
            return json(200, { post: postView(post) });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/comments',
      handle: tg.protect(
        {
          permission: 'tg.comments.read',
          mutating: false,
          action: {
            id: 'comments.list',
            method: 'GET',
            path: '/api/comments',
            description: 'list recent comments on the owner posts',
          },
        },
        async (_req, ctx) => {
          const comments = listCommentsForOwner(db, requireSubject(ctx));
          return json(200, { comments });
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/posts/:id/comments',
      handle: tg.protect(
        {
          permission: 'tg.comments.read',
          resource: (req) => `post:${param(paramsOf(req, '/api/posts/:id/comments'), 'id')}`,
          mutating: false,
          action: {
            id: 'comments.list_for_post',
            method: 'GET',
            path: '/api/posts/{id}/comments',
            description: 'list comments on one owned post',
            resource: 'post:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/posts/:id/comments'), 'id');
          const post = getOwnPost(db, id, requireSubject(ctx));
          if (post === undefined) {
            return err(404, 'blog.post.not_found', 'post not found');
          }
          return json(200, { comments: listComments(db, id) });
        },
      ),
    },
    {
      method: 'DELETE',
      pattern: '/api/comments/:id',
      handle: tg.protect(
        {
          permission: 'tg.comments.delete',
          resource: (req) => `comment:${param(paramsOf(req, '/api/comments/:id'), 'id')}`,
          action: {
            id: 'comments.delete',
            method: 'DELETE',
            path: '/api/comments/{id}',
            description: 'delete a comment on an owned post',
            resource: 'comment:<id>',
          },
        },
        async (req, ctx) => {
          const id = param(paramsOf(req, '/api/comments/:id'), 'id');
          const subject = requireSubject(ctx);
          try {
            deleteComment(db, id, subject);
            return json(200, { deleted: id });
          } catch (e) {
            return domainError(e);
          }
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/notifications',
      handle: tg.protect(
        {
          permission: 'tg.notifications.read',
          mutating: false,
          action: {
            id: 'notifications.list',
            method: 'GET',
            path: '/api/notifications',
            description: 'list notifications (query: unread=1, limit=n)',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const url = new URL(req.url);
          const limitParam = url.searchParams.get('limit');
          const limit =
            limitParam === null ? 50 : Math.min(Number.parseInt(limitParam, 10) || 50, 200);
          return json(200, {
            notifications: listNotifications(db, subject, {
              unreadOnly: url.searchParams.get('unread') === '1',
              limit,
            }),
            unread_count: unreadCount(db, subject),
          });
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/notifications/:id/read',
      handle: tg.protect(
        {
          permission: 'tg.notifications.write',
          action: {
            id: 'notifications.mark_read',
            method: 'POST',
            path: '/api/notifications/{id}/read',
            description: 'mark one notification read (id "all" marks every notification)',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const id = param(paramsOf(req, '/api/notifications/:id/read'), 'id');
          if (id === 'all') {
            markAllRead(db, subject);
            return json(200, { marked: 'all' });
          }
          return markRead(db, subject, id)
            ? json(200, { marked: id })
            : err(404, 'blog.notification.not_found', 'notification not found');
        },
      ),
    },
  ];

  const table = routes.map((r) => ({ ...r, segments: r.pattern }));

  return {
    dispatch: async (req) => {
      const path = new URL(req.url).pathname;
      for (const route of table) {
        if (route.method !== req.method.toUpperCase()) {
          continue;
        }
        if (matchPath(route.segments, path) !== undefined) {
          try {
            const res = await route.handle(req);
            captureReceipt(db, req, res);
            return res;
          } catch (e) {
            if (e instanceof TrailGateError) {
              return json(e.httpStatus, {
                error: {
                  code: e.code,
                  message: e.message,
                  ...(e.detail ? { detail: e.detail } : {}),
                },
              });
            }
            throw e;
          }
        }
      }
      return undefined;
    },
  };
}
