import { isTrailGateError } from '@trailgate/core';
import type { HostRequest, HostResponse } from '@trailgate/server';
import { createAgentApi } from './api/routes.ts';
import type { BlogConfig } from './config.ts';
import type { Db } from './db/database.ts';
import {
  addComment,
  deleteComment,
  listComments,
  listCommentsForOwner,
} from './domain/comments.ts';
import { listNotifications, markAllRead, markRead, unreadCount } from './domain/notifications.ts';
import {
  createDraft,
  deletePost,
  getOwnPost,
  getPost,
  getPostBySlug,
  listPosts,
  listPublished,
  NotFoundError,
  publishPost,
  restorePost,
  StateError,
  unpublishPost,
  updatePost,
} from './domain/posts.ts';
import {
  AuthError,
  authenticate,
  createSession,
  createUser,
  destroySession,
  getSession,
  getUser,
  type User,
  updateProfile,
  ValidationError,
} from './domain/users.ts';
import {
  CsrfError,
  parseCookies,
  parseForm,
  parseFormValues,
  parsePermissionModes,
  requireCsrf,
} from './http/forms.ts';
import { html, redirect } from './http/responses.ts';
import type { AppRequest, AppResponse } from './http/router.ts';
import { Router } from './http/router.ts';
import { type BlogTrailGate, createBlogTrailGate } from './tg/server.ts';
import { PERMISSIONS } from './tg/vocabulary.ts';
import { page } from './ui/layout.ts';
import {
  renderAccessPage,
  renderApprovalDetail,
  renderApprovalsPage,
  renderArticle,
  renderAuth,
  renderCommentsPage,
  renderConsent,
  renderEditor,
  renderError,
  renderHome,
  renderNotFound,
  renderNotificationsPage,
  renderOverview,
  renderPostsList,
  renderSettings,
} from './ui/pages.ts';

const SESSION_COOKIE = 'blog_session';
const SESSION_MAX_AGE = 60 * 60 * 24 * 14;

export interface BlogApp {
  handle(req: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: Uint8Array;
  }): Promise<AppResponse>;
  tg: BlogTrailGate;
  /** The authoritative database handle (exposed for tests and tooling). */
  db: Db;
}

interface Ctx {
  db: Db;
  config: BlogConfig;
  tg: BlogTrailGate;
}

function isProtectedPath(path: string): boolean {
  return (
    path === '/.well-known/trailgate' ||
    path.startsWith('/api/') ||
    path === '/tg/grant-request' ||
    path === '/tg/grant-redemption' ||
    path === '/tg/grant-revocation' ||
    path === '/tg/grant-status' ||
    path.startsWith('/tg/action-status/')
  );
}

function sessionCookie(id: string, tls: boolean, maxAge: number): string {
  const parts = [
    `${SESSION_COOKIE}=${id}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ];
  if (tls) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

function hostToAppRequest(
  ctx: Ctx,
  req: { method: string; url: string; headers: Record<string, string>; body?: Uint8Array },
): AppRequest {
  const url = new URL(req.url, ctx.config.issuer);
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[SESSION_COOKIE];
  const session = sessionId !== undefined ? getSession(ctx.db, sessionId) : undefined;
  const user = session !== undefined ? getUser(ctx.db, session.userId) : undefined;
  return {
    method: req.method.toUpperCase(),
    path: url.pathname,
    url,
    params: {},
    query: url.searchParams,
    headers: req.headers,
    cookies,
    ...(req.body !== undefined ? { body: req.body } : {}),
    ...(session !== undefined ? { session } : {}),
    ...(user !== undefined ? { user } : {}),
  };
}

function navSection(path: string): string | undefined {
  if (path === '/') {
    return 'articles';
  }
  if (path === '/search') {
    return 'search';
  }
  if (!path.startsWith('/workspace')) {
    return undefined;
  }
  const segment = path.split('/')[2] ?? '';
  return segment === '' ? 'overview' : segment;
}

function render(
  ctx: Ctx,
  req: AppRequest,
  options: {
    title: string;
    body: string;
    context?: 'public' | 'workspace';
    flash?: { kind: 'info' | 'error' | 'ok'; text: string };
    status?: number;
  },
): AppResponse {
  const section = navSection(req.path);
  return html(
    page({
      title: options.title,
      body: options.body,
      context:
        options.context ??
        (req.user !== undefined && req.path.startsWith('/workspace') ? 'workspace' : 'public'),
      ...(section !== undefined ? { section } : {}),
      ...(req.user !== undefined ? { user: req.user } : {}),
      ...(req.session !== undefined ? { csrf: req.session.csrfToken } : {}),
      ...(req.user !== undefined ? { unreadCount: unreadCount(ctx.db, req.user.id) } : {}),
      ...(options.flash !== undefined ? { flash: options.flash } : {}),
    }),
    options.status ?? 200,
  );
}

export function createBlogApp(db: Db, config: BlogConfig): BlogApp {
  const tg = createBlogTrailGate(db, config);
  const ctx: Ctx = { db, config, tg };
  const api = createAgentApi(db, tg.tg);
  const router = buildRoutes(ctx);

  return {
    tg,
    db,
    handle: async (raw) => {
      const url = new URL(raw.url, config.issuer);
      if (isProtectedPath(url.pathname)) {
        const hostReq: HostRequest = {
          method: raw.method,
          url: `${config.issuer}${raw.url}`,
          headers: raw.headers,
          ...(raw.body !== undefined ? { body: raw.body } : {}),
        };
        const res = await protocolOrApi(ctx, api.dispatch, hostReq);
        return {
          status: res.status,
          headers: res.headers ?? {},
          body:
            res.body === undefined
              ? ''
              : typeof res.body === 'string'
                ? res.body
                : JSON.stringify(res.body),
        };
      }
      const req = hostToAppRequest(ctx, raw);
      try {
        const matched = router.match(req.method, req.path);
        if (matched === undefined) {
          return render(ctx, req, {
            title: 'Not found',
            body: renderNotFound(),
            status: 404,
          });
        }
        req.params = matched.params;
        return await matched.handler(req);
      } catch (err) {
        if (err instanceof CsrfError) {
          return render(ctx, req, {
            title: 'Form expired',
            body: renderError('Your form session expired. Go back and try again.'),
          });
        }
        if (err instanceof ValidationError) {
          return render(ctx, req, {
            title: 'Invalid input',
            body: renderError(err.message),
            status: 422,
          });
        }
        if (err instanceof NotFoundError) {
          return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
        }
        if (err instanceof StateError) {
          return render(ctx, req, {
            title: 'Not allowed',
            body: renderError(err.message),
            status: 409,
          });
        }
        throw err;
      }
    },
  };
}

async function protocolOrApi(
  ctx: Ctx,
  apiDispatch: (req: HostRequest) => Promise<HostResponse | undefined>,
  req: HostRequest,
): Promise<HostResponse> {
  const path = new URL(req.url).pathname;
  if (path === '/.well-known/trailgate') {
    const res = await ctx.tg.tg.handleDiscovery();
    res.headers = { ...res.headers, 'cache-control': 'max-age=300' };
    return res;
  }
  if (path === '/tg/grant-request') {
    return ctx.tg.tg.handleGrantRequest(req);
  }
  if (path === '/tg/grant-redemption') {
    return ctx.tg.tg.handleRedemption(req);
  }
  if (path === '/tg/grant-revocation') {
    return ctx.tg.tg.handleRevocation(req);
  }
  if (path === '/tg/grant-status') {
    return ctx.tg.tg.handleStatus(req);
  }
  if (path.startsWith('/tg/action-status/')) {
    return ctx.tg.tg.handleActionStatus(req);
  }
  const apiRes = await apiDispatch(req);
  if (apiRes !== undefined) {
    return apiRes;
  }
  return {
    status: 404,
    headers: { 'content-type': 'application/json' },
    body: { error: { code: 'blog.route.not_found', message: 'unknown route' } },
  };
}

function requireUser(req: AppRequest): { session: NonNullable<AppRequest['session']>; user: User } {
  if (req.session === undefined || req.user === undefined) {
    throw new AuthError('sign in required');
  }
  return { session: req.session, user: req.user };
}

function safeNext(path: string | undefined): string {
  return path !== undefined && path.startsWith('/') && !path.startsWith('//') ? path : '/workspace';
}

function buildRoutes(ctx: Ctx): Router {
  const router = new Router();
  const { db } = ctx;

  const authed =
    (handler: (req: AppRequest, user: User) => AppResponse | Promise<AppResponse>) =>
    (req: AppRequest): AppResponse | Promise<AppResponse> => {
      if (req.session === undefined || req.user === undefined) {
        return redirect(`/login?next=${encodeURIComponent(req.path)}`);
      }
      return handler(req, req.user);
    };

  // ---------- public blog ----------

  router.get('/', (req) => {
    const q = req.query.get('q') ?? undefined;
    const tag = req.query.get('tag') ?? undefined;
    const posts = listPublished(db, {
      ...(q !== undefined ? { q } : {}),
      ...(tag !== undefined ? { tag } : {}),
    });
    const authors = new Map<string, User>();
    for (const p of posts) {
      if (!authors.has(p.authorId)) {
        const u = getUser(db, p.authorId);
        if (u !== undefined) {
          authors.set(p.authorId, u);
        }
      }
    }
    return render(ctx, req, {
      title: 'Blogarithm',
      body: renderHome(posts, authors, q, tag),
    });
  });

  router.get('/search', (req) => {
    const q = req.query.get('q') ?? '';
    const posts = listPublished(db, { q });
    const authors = new Map<string, User>();
    for (const p of posts) {
      const u = getUser(db, p.authorId);
      if (u !== undefined) {
        authors.set(p.authorId, u);
      }
    }
    return render(ctx, req, {
      title: `Search: ${q}`,
      body: `<div class="page-head"><div><p class="eyebrow">Blogarithm</p><h1>Search</h1></div></div>
        <form method="get" action="/search" class="search-form search-big">
          <input name="q" placeholder="Search published posts" value="${q.replace(/"/g, '&quot;')}">
          <button class="btn btn-primary" type="submit">Search</button>
        </form>
        ${renderHome(posts, authors, q)}`,
    });
  });

  router.get('/post/:slug', (req) => {
    const post = getPostBySlug(db, req.params.slug ?? '');
    if (post === undefined || post.status !== 'published') {
      return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
    }
    const author = getUser(db, post.authorId);
    return render(ctx, req, {
      title: post.title,
      body: renderArticle(post, author, listComments(db, post.id), true),
    });
  });

  router.post('/post/:slug/comments', (req) => {
    const post = getPostBySlug(db, req.params.slug ?? '');
    if (post === undefined || post.status !== 'published') {
      return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
    }
    const form = parseForm(req);
    try {
      addComment(db, post.id, { authorName: form.name ?? '', body: form.body ?? '' });
      return redirect(`/post/${post.slug}#comments`);
    } catch (e) {
      if (e instanceof ValidationError || e instanceof StateError) {
        const author = getUser(db, post.authorId);
        return render(ctx, req, {
          title: post.title,
          body: renderArticle(post, author, listComments(db, post.id), true),
          flash: { kind: 'error', text: e.message },
          status: 422,
        });
      }
      throw e;
    }
  });

  // ---------- auth ----------

  router.get('/login', (req) =>
    render(ctx, req, {
      title: 'Sign in',
      body: renderAuth('login', undefined, safeNext(req.query.get('next') ?? undefined)),
    }),
  );

  router.post('/login', (req) => {
    const form = parseForm(req);
    const next = safeNext(form.next);
    try {
      const user = authenticate(db, form.email ?? '', form.password ?? '');
      const session = createSession(db, user.id);
      const res = redirect(next);
      res.headers = {
        ...res.headers,
        'set-cookie': sessionCookie(session.id, ctx.config.tls, SESSION_MAX_AGE),
      };
      return res;
    } catch (e) {
      if (e instanceof AuthError) {
        return render(ctx, req, {
          title: 'Sign in',
          body: renderAuth('login', e.message, next),
          status: 401,
        });
      }
      throw e;
    }
  });

  router.get('/register', (req) =>
    render(ctx, req, { title: 'Create account', body: renderAuth('register') }),
  );

  router.post('/register', (req) => {
    const form = parseForm(req);
    try {
      const user = createUser(db, {
        email: form.email ?? '',
        name: form.name ?? '',
        username: form.username ?? '',
        password: form.password ?? '',
      });
      const session = createSession(db, user.id);
      const res = redirect('/workspace');
      res.headers = {
        ...res.headers,
        'set-cookie': sessionCookie(session.id, ctx.config.tls, SESSION_MAX_AGE),
      };
      return res;
    } catch (e) {
      if (e instanceof ValidationError) {
        return render(ctx, req, {
          title: 'Create account',
          body: renderAuth('register', e.message),
          status: 422,
        });
      }
      throw e;
    }
  });

  router.post('/logout', (req) => {
    const form = parseForm(req);
    try {
      requireCsrf(req, form);
    } catch (e) {
      if (e instanceof CsrfError) {
        return redirect('/login');
      }
      throw e;
    }
    if (req.session !== undefined) {
      destroySession(db, req.session.id);
    }
    const res = redirect('/');
    res.headers = { ...res.headers, 'set-cookie': sessionCookie('', ctx.config.tls, 0) };
    return res;
  });

  // ---------- workspace ----------

  router.get(
    '/workspace',
    authed((req, user) => {
      const posts = listPosts(db, user.id);
      const comments = listCommentsForOwner(db, user.id);
      return render(ctx, req, {
        title: 'Workspace',
        context: 'workspace',
        body: renderOverview(
          user,
          {
            published: posts.filter((p) => p.status === 'published').length,
            drafts: posts.filter((p) => p.status === 'draft').length,
            comments: comments.length,
          },
          posts.slice(0, 5),
          listNotifications(db, user.id, { limit: 6 }),
        ),
      });
    }),
  );

  router.get(
    '/workspace/posts',
    authed((req, user) => {
      const status = req.query.get('status');
      const q = req.query.get('q') ?? undefined;
      const posts = listPosts(db, user.id, {
        ...(status === 'draft' || status === 'published' || status === 'deleted' ? { status } : {}),
        ...(q !== undefined ? { q } : {}),
      });
      return render(ctx, req, {
        title: 'Posts',
        context: 'workspace',
        body: renderPostsList(
          posts,
          { ...(status !== null ? { status } : {}), ...(q !== undefined ? { q } : {}) },
          req.session?.csrfToken ?? '',
        ),
      });
    }),
  );

  router.get(
    '/workspace/posts/new',
    authed((req) =>
      render(ctx, req, {
        title: 'New post',
        context: 'workspace',
        body: renderEditor(undefined, req.session?.csrfToken ?? ''),
      }),
    ),
  );

  router.get(
    '/workspace/posts/:id/edit',
    authed((req, user) => {
      const post = getOwnPost(db, req.params.id ?? '', user.id);
      if (post === undefined || post.status === 'deleted') {
        return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
      }
      return render(ctx, req, {
        title: `Edit: ${post.title}`,
        context: 'workspace',
        body: renderEditor(post, req.session?.csrfToken ?? ''),
      });
    }),
  );

  router.get(
    '/workspace/posts/:id/preview',
    authed((req, user) => {
      const post = getOwnPost(db, req.params.id ?? '', user.id);
      if (post === undefined) {
        return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
      }
      return render(ctx, req, {
        title: `Preview: ${post.title}`,
        body: renderArticle(
          { ...post, status: 'published' },
          user,
          listComments(db, post.id),
          false,
        ),
      });
    }),
  );

  router.post(
    '/workspace/posts/:id/save',
    authed((req, user) => {
      requireUser(req);
      const form = parseForm(req);
      requireCsrf(req, form);
      const id = req.params.id ?? '';
      const input = {
        title: form.title ?? '',
        excerpt: form.excerpt,
        body: form.body,
        coverImage: form.cover_image,
        tags: (form.tags ?? '')
          .split(',')
          .map((t) => t.trim())
          .filter((t) => t !== ''),
        commentsEnabled: form.comments_enabled === '1',
      };
      const post =
        id === 'new' ? createDraft(db, user.id, input) : updatePost(db, id, user.id, input);
      return redirect(`/workspace/posts/${post.id}/edit?saved=1`);
    }),
  );

  for (const action of ['publish', 'unpublish', 'delete', 'restore'] as const) {
    router.post(
      `/workspace/posts/:id/${action}`,
      authed((req, user) => {
        const form = parseForm(req);
        requireCsrf(req, form);
        const id = req.params.id ?? '';
        if (action === 'publish') {
          publishPost(db, id, user.id);
        } else if (action === 'unpublish') {
          unpublishPost(db, id, user.id);
        } else if (action === 'delete') {
          deletePost(db, id, user.id);
        } else {
          restorePost(db, id, user.id);
        }
        return redirect(action === 'delete' ? '/workspace/posts' : `/workspace/posts/${id}/edit`);
      }),
    );
  }

  router.get(
    '/workspace/comments',
    authed((req, user) => {
      const items = listCommentsForOwner(db, user.id).map((comment) => {
        const post = getPost(db, comment.postId);
        return { comment, post };
      });
      const withPost = items.filter((i) => i.post !== undefined) as {
        comment: (typeof items)[number]['comment'];
        post: NonNullable<(typeof items)[number]['post']>;
      }[];
      return render(ctx, req, {
        title: 'Comments',
        context: 'workspace',
        body: renderCommentsPage(withPost, req.session?.csrfToken ?? ''),
      });
    }),
  );

  router.post(
    '/workspace/comments/:id/delete',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      deleteComment(db, req.params.id ?? '', user.id);
      return redirect('/workspace/comments');
    }),
  );

  router.get(
    '/workspace/notifications',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Notifications',
        context: 'workspace',
        body: renderNotificationsPage(
          listNotifications(db, user.id, { limit: 100 }),
          req.session?.csrfToken ?? '',
        ),
      }),
    ),
  );

  router.post(
    '/workspace/notifications/:id/read',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      markRead(db, user.id, req.params.id ?? '');
      return redirect('/workspace/notifications');
    }),
  );

  router.post(
    '/workspace/notifications/read-all',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      markAllRead(db, user.id);
      return redirect('/workspace/notifications');
    }),
  );

  router.get(
    '/workspace/settings',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Settings',
        context: 'workspace',
        body: renderSettings(user, req.session?.csrfToken ?? ''),
      }),
    ),
  );

  router.post(
    '/workspace/settings',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      updateProfile(db, user.id, {
        name: form.name,
        username: form.username,
        bio: form.bio,
        avatar: form.avatar,
      });
      return redirect('/workspace/settings?saved=1');
    }),
  );

  // ---------- TrailGate consent + grant management ----------

  router.get(
    '/workspace/access',
    authed(async (req, user) => {
      const records = await ctx.tg.tg.config.stores.grants.listBySubject(user.id);
      const grants = records.map((r) => ({
        jti: r.jti,
        agentJkt: r.agentJkt,
        permissions: r.effectivePermissions ?? r.permissions,
        constraints: r.effectiveConstraints ?? [],
        issuedAt: r.issuedAt,
        expiresAt: r.expiresAt,
        status: r.status,
      }));
      return render(ctx, req, {
        title: 'Agent access',
        context: 'workspace',
        body: renderAccessPage(
          grants.sort((a, b) => b.issuedAt - a.issuedAt),
          req.session?.csrfToken ?? '',
          Math.floor(Date.now() / 1000),
        ),
      });
    }),
  );

  // ---------- pending actions (approval-gated requests, spec section 12.5) ----------

  router.get(
    '/workspace/approvals',
    authed(async (req, user) => {
      const records = await ctx.tg.tg.listPendingActions(user.id);
      return render(ctx, req, {
        title: 'Agent approvals',
        context: 'workspace',
        body: renderApprovalsPage(records),
      });
    }),
  );

  router.get(
    '/workspace/approvals/:id',
    authed(async (req, user) => {
      const record = await ctx.tg.tg.config.stores.pendingActions.get(req.params.id ?? '');
      if (record === undefined || record.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
      }
      return render(ctx, req, {
        title: 'Review proposed action',
        context: 'workspace',
        body: renderApprovalDetail(
          record,
          req.session?.csrfToken ?? '',
          Math.floor(Date.now() / 1000),
        ),
      });
    }),
  );

  router.post(
    '/workspace/approvals/decide',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const actionId = form.action_id ?? '';
      const decision = form.decision === 'approve' ? 'approve' : 'reject';
      try {
        const record = await ctx.tg.tg.decidePendingAction(actionId, decision, user.id);
        return redirect(`/workspace/approvals/${record.id}`);
      } catch (err) {
        if (isTrailGateError(err)) {
          return render(ctx, req, {
            title: 'Review proposed action',
            context: 'workspace',
            status: err.httpStatus === 404 ? 404 : 400,
            body: renderError(err.message),
          });
        }
        throw err;
      }
    }),
  );

  // Post-issuance scope control (spec section 13): the tri-state editor
  // posts `mode_<permission>` fields; allow grants, approval marks a
  // require_approval constraint, deny removes the permission.
  router.post(
    '/workspace/access/:jti/scope',
    authed(async (req, user) => {
      const form = parseForm(req);
      const values = parseFormValues(req);
      requireCsrf(req, form);
      const jti = req.params.jti ?? '';
      const record = await ctx.tg.tg.config.stores.grants.get(jti);
      if (record === undefined || record.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
      }
      const modes = parsePermissionModes(form, PERMISSIONS);
      const selected = modes?.permissions ?? values.perm ?? [];
      if (selected.length === 0) {
        return render(ctx, req, {
          title: 'Agent access',
          context: 'workspace',
          status: 400,
          body: renderError('Keep at least one permission, or revoke the access instead.'),
        });
      }
      const kept = (record.effectiveConstraints ?? []).filter(
        (c) => modes === undefined || c.type !== 'require_approval',
      );
      const marked =
        modes === undefined ? [] : modes.approvalPermissions.filter((p) => selected.includes(p));
      try {
        await ctx.tg.tg.updateGrantScope(jti, {
          permissions: selected,
          constraints: [
            ...kept,
            ...(marked.length > 0
              ? [{ type: 'require_approval', params: { permissions: marked } }]
              : []),
          ],
          actor: `user:${user.id}`,
        });
      } catch (err) {
        return render(ctx, req, {
          title: 'Agent access',
          context: 'workspace',
          status: 400,
          body: renderError(err instanceof Error ? err.message : 'The change was refused.'),
        });
      }
      return redirect('/workspace/access');
    }),
  );

  router.post(
    '/workspace/access/:jti/revoke',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const jti = req.params.jti ?? '';
      const record = await ctx.tg.tg.config.stores.grants.get(jti);
      if (record === undefined || record.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', body: renderNotFound(), status: 404 });
      }
      await ctx.tg.tg.revokeGrant(jti, { actor: user.id, reason: 'revoked from the access page' });
      return redirect('/workspace/access');
    }),
  );

  router.get('/tg/consent', async (req) => {
    if (req.session === undefined || req.user === undefined) {
      return redirect(
        `/login?next=${encodeURIComponent(`/tg/consent?request_id=${req.query.get('request_id') ?? ''}`)}`,
      );
    }
    const requestId = req.query.get('request_id') ?? '';
    try {
      const view = await ctx.tg.tg.getConsent(requestId);
      if (view === undefined) {
        throw new Error('unknown request');
      }
      return render(ctx, req, {
        title: 'Authorize access',
        context: 'workspace',
        body: renderConsent({
          requestId,
          csrf: req.session.csrfToken,
          permissions: view.effective.permissions,
          resources: view.effective.resources,
          requestedSeconds: view.requested.requestedSeconds ?? view.effective.lifetimeSeconds,
          approvalSuggested: view.approvalSuggested,
        }),
      });
    } catch {
      return render(ctx, req, {
        title: 'Authorize access',
        body: renderError('This authorization request is unknown or expired.'),
        status: 404,
      });
    }
  });

  router.post('/tg/consent', async (req) => {
    if (req.session === undefined || req.user === undefined) {
      return redirect('/login');
    }
    const form = parseForm(req);
    const values = parseFormValues(req);
    requireCsrf(req, form);
    const requestId = form.request_id ?? '';
    const decision = form.decision === 'approve' ? 'approve' : 'deny';
    try {
      // Tri-state consent posts `mode_<permission>` fields; a legacy `perm`
      // checkbox post narrows permissions without approval marks.
      const modes = parsePermissionModes(form, PERMISSIONS);
      const picked = modes?.permissions ?? values.perm ?? [];
      if (decision === 'approve' && picked.length === 0) {
        throw new Error('select at least one permission, or decline the request');
      }
      const narrow =
        decision === 'approve'
          ? {
              permissions: picked,
              ...(modes !== undefined ? { approvalPermissions: modes.approvalPermissions } : {}),
            }
          : undefined;
      const outcome = await ctx.tg.tg.decideConsent(requestId, decision, req.user.id, narrow);
      if (outcome.redirectTo !== undefined) {
        return { status: 302, headers: { location: outcome.redirectTo } };
      }
      return render(ctx, req, {
        title: decision === 'approve' ? 'Access granted' : 'Access declined',
        context: 'workspace',
        body: `<section class="empty-state"><h1>${
          decision === 'approve' ? 'Access granted' : 'Access declined'
        }</h1><p>${
          decision === 'approve'
            ? 'The agent can now redeem its grant and act within the approved permissions.'
            : 'The request was declined. No grant was issued.'
        }</p><p><a href="/workspace/access">Manage agent access</a></p></section>`,
      });
    } catch (e) {
      try {
        const view = await ctx.tg.tg.getConsent(requestId);
        if (view === undefined) {
          throw new Error('unknown request');
        }
        return render(ctx, req, {
          title: 'Authorize access',
          context: 'workspace',
          body: renderConsent({
            requestId,
            csrf: req.session?.csrfToken ?? '',
            permissions: view.effective.permissions,
            resources: view.effective.resources,
            approvalSuggested: view.approvalSuggested,
            error: e instanceof Error ? e.message : 'authorization failed',
          }),
          status: 422,
        });
      } catch {
        return render(ctx, req, {
          title: 'Authorize access',
          body: renderError('This authorization request is unknown or expired.'),
          status: 404,
        });
      }
    }
  });

  return router;
}
