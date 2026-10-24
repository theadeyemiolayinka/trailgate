import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { HttpTransport } from '@trailgate/agent';
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';
import { type BlogApp, createBlogApp } from './app.ts';
import { loadConfig } from './config.ts';
import { openDatabase } from './db/database.ts';
import { seedIfEmpty } from './db/seed.ts';
import { getComment } from './domain/comments.ts';
import { listNotifications } from './domain/notifications.ts';
import { getPostBySlug, setCommentsEnabled } from './domain/posts.ts';
import { getUserByUsername } from './domain/users.ts';

const ISSUER = 'https://localhost:3444';
const DEMO = { email: 'demo@blogarithm.dev', password: 'demo-password-1' };

function makeApp(): BlogApp {
  const db = openDatabase(':memory:');
  seedIfEmpty(db);
  return createBlogApp(db, { ...loadConfig(), issuer: ISSUER });
}

/** In-process transport: the agent signs issuer-absolute URLs; the app rebuilds them. */
function directTransport(app: BlogApp): HttpTransport {
  return {
    send: async (req) => {
      const url = new URL(req.url);
      const res = await app.handle({
        method: req.method,
        url: url.pathname + url.search,
        headers: req.headers ?? {},
        ...(req.body !== undefined ? { body: req.body } : {}),
      });
      const text = res.body ?? '';
      return {
        status: res.status,
        headers: res.headers ?? {},
        body: typeof text === 'string' ? new TextEncoder().encode(text) : text,
      };
    },
  };
}

async function req(
  app: BlogApp,
  method: string,
  path: string,
  options: { cookie?: string; form?: Record<string, string>; followRedirect?: boolean } = {},
) {
  const res = await app.handle({
    method,
    url: path,
    headers: {
      ...(options.cookie !== undefined ? { cookie: options.cookie } : {}),
      ...(options.form !== undefined
        ? { 'content-type': 'application/x-www-form-urlencoded' }
        : {}),
    },
    ...(options.form !== undefined
      ? { body: new TextEncoder().encode(new URLSearchParams(options.form).toString()) }
      : {}),
  });
  return res;
}

async function login(app: BlogApp): Promise<string> {
  const res = await req(app, 'POST', '/login', { form: { ...DEMO, next: '/workspace' } });
  assert.equal(res.status, 303);
  const cookie = String(res.headers?.['set-cookie']).split(';')[0] as string;
  assert.ok(cookie.includes('blog_session='));
  return cookie;
}

async function csrfOf(app: BlogApp, cookie: string, path: string): Promise<string> {
  const page = await req(app, 'GET', path, { cookie });
  const csrf = String(page.body).match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf !== undefined, `no csrf token on ${path}`);
  return csrf;
}

test('publishing workflow: draft hidden publicly, publish exposes it, edits persist', async () => {
  const app = makeApp();
  const cookie = await login(app);
  const csrf = await csrfOf(app, cookie, '/workspace/posts/new');

  const created = await req(app, 'POST', '/workspace/posts/new/save', {
    cookie,
    form: {
      _csrf: csrf,
      title: 'Acceptance test post',
      excerpt: 'written by the test suite',
      body: '## Hello\n\nBody text.',
      tags: 'testing',
      comments_enabled: '1',
    },
  });
  assert.equal(created.status, 303);
  const location = String(created.headers?.location);
  const postId = location.match(/posts\/(post_[A-Za-z0-9_-]+)\/edit/)?.[1];
  assert.ok(postId !== undefined);

  const home = await req(app, 'GET', '/');
  assert.ok(!String(home.body).includes('Acceptance test post'), 'draft leaked to public home');

  const list = await req(app, 'GET', '/workspace/posts', { cookie });
  assert.ok(String(list.body).includes('Acceptance test post'), 'draft missing from workspace');

  const pub = await req(app, 'POST', `/workspace/posts/${postId}/publish`, {
    cookie,
    form: { _csrf: csrf },
  });
  assert.equal(pub.status, 303);

  const home2 = await req(app, 'GET', '/');
  assert.ok(String(home2.body).includes('Acceptance test post'), 'published post missing publicly');

  const csrf2 = await csrfOf(app, cookie, `/workspace/posts/${postId}/edit`);
  const edited = await req(app, 'POST', `/workspace/posts/${postId}/save`, {
    cookie,
    form: {
      _csrf: csrf2,
      title: 'Acceptance test post (edited)',
      excerpt: 'written by the test suite',
      body: '## Edited\n\nNew body.',
      tags: 'testing',
      comments_enabled: '1',
    },
  });
  assert.equal(edited.status, 303);
  const home3 = await req(app, 'GET', '/');
  assert.ok(String(home3.body).includes('(edited)'), 'edit did not persist');
});

test('comments: enabled accepts, disabled rejects server-side and keeps existing', async () => {
  const app = makeApp();
  const post = getPostBySlug(app.db, 'why-delegated-authority-beats-shared-credentials');
  assert.ok(post !== undefined);

  const res1 = await req(app, 'POST', `/post/${post.slug}/comments`, {
    form: { name: 'Tester', body: 'First comment' },
  });
  assert.equal(res1.status, 303);

  setCommentsEnabled(app.db, post.id, post.authorId, false);
  const res2 = await req(app, 'POST', `/post/${post.slug}/comments`, {
    form: { name: 'Tester', body: 'Second comment' },
  });
  assert.equal(res2.status, 422, 'closed comments must reject server-side');

  const article = await req(app, 'GET', `/post/${post.slug}`);
  assert.ok(String(article.body).includes('First comment'), 'existing comments must be preserved');
  assert.ok(!String(article.body).includes('Post comment'), 'form should not render when closed');
});

test('private drafts are not readable by other accounts', async () => {
  const app = makeApp();
  // register a second user
  const reg = await req(app, 'POST', '/register', {
    form: {
      name: 'Eve',
      username: 'eve',
      email: 'eve@example.dev',
      password: 'eve-password-9',
    },
  });
  assert.equal(reg.status, 303);
  const eveCookie = String(reg.headers?.['set-cookie']).split(';')[0] as string;

  const draft = app.db.prepare("SELECT id FROM posts WHERE status = 'draft' LIMIT 1").get() as {
    id: string;
  };
  const view = await req(app, 'GET', `/workspace/posts/${draft.id}/edit`, { cookie: eveCookie });
  assert.equal(view.status, 404, "another user's draft must not be readable");
});

async function approveConsent(
  app: BlogApp,
  cookie: string,
  requestId: string,
  perms: string[],
): Promise<void> {
  const page = await req(app, 'GET', `/tg/consent?request_id=${requestId}`, { cookie });
  const csrf = String(page.body).match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf !== undefined);
  const form: Record<string, string> = { _csrf: csrf, request_id: requestId, decision: 'approve' };
  const res = await app.handle({
    method: 'POST',
    url: '/tg/consent',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new TextEncoder().encode(
      new URLSearchParams([
        ...Object.entries(form),
        ...perms.map((p) => ['perm', p] as [string, string]),
      ]).toString(),
    ),
  });
  assert.ok(
    res.status === 200 || res.status === 303 || res.status === 302,
    `consent failed: ${res.status}`,
  );
}

test('trailgate: draft permission cannot publish; second grant can; revocation denies', async () => {
  const app = makeApp();
  const transport = directTransport(app);
  const client = createAgentClient({ transport });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);
  assert.equal(site.issuer, ISSUER);

  const cookie = await login(app);

  const session1 = await client.requestGrant(site, {
    permissions: ['tg.posts.read', 'tg.posts.create', 'tg.posts.update'],
  });
  await approveConsent(app, cookie, session1.requestId, [
    'tg.posts.read',
    'tg.posts.create',
    'tg.posts.update',
  ]);
  const grant1 = await client.awaitApproval(session1.requestId, { intervalMs: 20 });

  const created = await client.fetchProtected(site, {
    method: 'POST',
    grantId: grant1.jti,
    target: '/api/posts',
    body: JSON.stringify({ title: 'Agent draft', body: '## Body\n\nBy the agent.' }),
  });
  assert.equal(created.status, 201);
  const draft = JSON.parse(new TextDecoder().decode(created.body)) as {
    post: { id: string; status: string };
  };
  assert.equal(draft.post.status, 'draft');
  assert.equal(created.receipt?.verified, true, 'expected a verified receipt');

  const deniedPublish = await client.fetchProtected(site, {
    method: 'POST',
    grantId: grant1.jti,
    target: `/api/posts/${draft.post.id}/publish`,
  });
  assert.equal(deniedPublish.status, 403);
  assert.equal(deniedPublish.error?.code, 'tg.request.permission_denied');

  const session2 = await client.requestGrant(site, {
    permissions: [
      'tg.posts.read',
      'tg.posts.create',
      'tg.posts.update',
      'tg.posts.publish',
      'tg.posts.settings',
    ],
    resources: ['post:{user}'],
  });
  await approveConsent(app, cookie, session2.requestId, [
    'tg.posts.read',
    'tg.posts.create',
    'tg.posts.update',
    'tg.posts.publish',
    'tg.posts.settings',
  ]);
  const grant2 = await client.awaitApproval(session2.requestId, { intervalMs: 20 });

  const published = await client.fetchProtected(site, {
    method: 'POST',
    grantId: grant2.jti,
    target: `/api/posts/${draft.post.id}/publish`,
  });
  // Publishing is approval-gated (spec section 12.5): the call queues a
  // pending action and the post stays a draft until the user decides.
  assert.equal(published.status, 202);
  assert.equal(published.pending?.status, 'pending');
  const actionId = published.pending?.id as string;
  assert.ok(actionId.startsWith('pact_'));
  const stillDraft = app.db.prepare('SELECT status FROM posts WHERE id = ?').get(draft.post.id) as {
    status: string;
  };
  assert.equal(stillDraft.status, 'draft');

  const approveCsrf = await csrfOf(app, cookie, `/workspace/approvals/${actionId}`);
  const approve = await req(app, 'POST', '/workspace/approvals/decide', {
    cookie,
    form: { _csrf: approveCsrf, action_id: actionId, decision: 'approve' },
  });
  assert.equal(approve.status, 303);

  const actionStatus = await client.actionStatus(site, actionId, { grantId: grant2.jti });
  assert.equal(actionStatus.status, 'succeeded');
  const nowPublished = app.db
    .prepare('SELECT status FROM posts WHERE id = ?')
    .get(draft.post.id) as { status: string };
  assert.equal(nowPublished.status, 'published');

  const deniedDelete = await client.fetchProtected(site, {
    method: 'DELETE',
    grantId: grant2.jti,
    target: `/api/posts/${draft.post.id}`,
  });
  assert.equal(deniedDelete.status, 403);
  assert.equal(deniedDelete.error?.code, 'tg.request.permission_denied');

  // revoke through the workspace access page
  const csrf = await csrfOf(app, cookie, '/workspace/access');
  const revoke = await req(app, 'POST', `/workspace/access/${grant2.jti}/revoke`, {
    cookie,
    form: { _csrf: csrf },
  });
  assert.equal(revoke.status, 303);

  const afterRevoke = await client.fetchProtected(site, {
    method: 'GET',
    grantId: grant2.jti,
    target: '/api/posts',
  });
  assert.equal(afterRevoke.status, 403);
  assert.equal(afterRevoke.error?.code, 'tg.grant.revoked');
});

test("trailgate: agent cannot reach another user's posts", async () => {
  const app = makeApp();
  // second user with a draft
  const reg = await req(app, 'POST', '/register', {
    form: { name: 'Eve', username: 'eve', email: 'eve@example.dev', password: 'eve-password-9' },
  });
  assert.equal(reg.status, 303);
  const eveCookie = String(reg.headers?.['set-cookie']).split(';')[0] as string;
  const eveCsrf = await csrfOf(app, eveCookie, '/workspace/posts/new');
  await req(app, 'POST', '/workspace/posts/new/save', {
    cookie: eveCookie,
    form: { _csrf: eveCsrf, title: 'Eve private draft', body: 'secret' },
  });
  const eveDraft = app.db
    .prepare("SELECT p.id FROM posts p JOIN users u ON u.id = p.author_id WHERE u.username = 'eve'")
    .get() as { id: string };

  // demo user's agent gets post read + the user's own posts in scope
  const transport = directTransport(app);
  const client = createAgentClient({ transport });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);
  const cookie = await login(app);
  const session = await client.requestGrant(site, {
    permissions: ['tg.posts.read'],
    resources: ['post:{user}'],
  });
  await approveConsent(app, cookie, session.requestId, ['tg.posts.read']);
  const grant = await client.awaitApproval(session.requestId, { intervalMs: 20 });

  // eve's post is outside the bound scope AND owned by another subject
  const res = await client.fetchProtected(site, {
    method: 'GET',
    grantId: grant.jti,
    target: `/api/posts/${eveDraft.id}`,
  });
  assert.equal(res.status, 403);
  assert.equal(res.error?.code, 'tg.request.resource_denied');
});

test('persistence: posts, comments, notifications survive a restart', () => {
  const dbPath = join(
    tmpdir(),
    `blogarithm-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
  );
  try {
    const db1 = openDatabase(dbPath);
    seedIfEmpty(db1);
    const app1 = createBlogApp(db1, { ...loadConfig(), issuer: ISSUER });
    assert.ok(app1 !== undefined);
    const post = getPostBySlug(db1, 'why-delegated-authority-beats-shared-credentials');
    assert.ok(post !== undefined);
    const commentId = (
      db1.prepare('SELECT id FROM comments WHERE post_id = ? LIMIT 1').get(post.id) as {
        id: string;
      }
    ).id;
    const noteCount = listNotifications(db1, post.authorId).length;
    db1.close();

    const db2 = openDatabase(dbPath);
    const app2 = createBlogApp(db2, { ...loadConfig(), issuer: ISSUER });
    const post2 = getPostBySlug(db2, post.slug);
    assert.ok(post2 !== undefined, 'post did not survive restart');
    assert.ok(getComment(db2, commentId) !== undefined, 'comment did not survive restart');
    assert.equal(listNotifications(db2, post.authorId).length, noteCount, 'notifications lost');
    assert.ok(app2 !== undefined);
    db2.close();
  } finally {
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        rmSync(dbPath + suffix);
      } catch {
        // best effort cleanup
      }
    }
  }
});

test('demo account exists and profile is complete', async () => {
  const app = makeApp();
  const user = getUserByUsername(app.db, 'ada');
  assert.ok(user !== undefined);
  assert.equal(user.email, DEMO.email);
  const cookie = await login(app);
  const page = await req(app, 'GET', '/workspace', { cookie });
  assert.equal(page.status, 200);
});

test('tri-state: consent marks queue actions; the access editor changes them live', async () => {
  const app = makeApp();
  const transport = directTransport(app);
  const client = createAgentClient({ transport });
  client.useKey(SoftwareKeyProvider.generate());
  const site = await client.discover(ISSUER);
  const cookie = await login(app);

  const session = await client.requestGrant(site, {
    permissions: ['tg.posts.read', 'tg.posts.create', 'tg.posts.update', 'tg.comments.read'],
  });

  // The consent page renders a tri-state selector per requested permission.
  const consentPage = await req(app, 'GET', `/tg/consent?request_id=${session.requestId}`, {
    cookie,
  });
  assert.ok(String(consentPage.body).includes('name="mode_tg.posts.create"'));
  const csrf = String(consentPage.body).match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf !== undefined);

  // allow reads, require approval on creates, deny updates and comments.
  const decided = await app.handle({
    method: 'POST',
    url: '/tg/consent',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new TextEncoder().encode(
      new URLSearchParams([
        ['_csrf', csrf],
        ['request_id', session.requestId],
        ['decision', 'approve'],
        ['mode_tg.posts.read', 'allow'],
        ['mode_tg.posts.create', 'approval'],
        ['mode_tg.posts.update', 'deny'],
        ['mode_tg.comments.read', 'deny'],
      ]).toString(),
    ),
  });
  assert.ok(decided.status === 200 || decided.status === 303, `consent: ${decided.status}`);
  const grant = await client.awaitApproval(session.requestId, { intervalMs: 20 });

  // The marks persisted into the grant's effective scope.
  const scope = await app.tg.tg.config.stores.grants.currentScope(grant.jti);
  assert.deepEqual(scope?.permissions.sort(), ['tg.posts.create', 'tg.posts.read']);
  const marked = (scope?.constraints ?? []).find((c) => c.type === 'require_approval');
  assert.deepEqual(marked?.params?.permissions, ['tg.posts.create']);

  // allow: reads execute immediately.
  const list = await client.fetchProtected(site, {
    method: 'GET',
    grantId: grant.jti,
    target: '/api/posts',
  });
  assert.equal(list.status, 200);

  // require approval: creates queue a pending action instead of running.
  const queued = await client.fetchProtected(site, {
    method: 'POST',
    grantId: grant.jti,
    target: '/api/posts',
    body: JSON.stringify({ title: 'Tri-state draft', body: 'queued for review' }),
  });
  assert.equal(queued.status, 202);
  assert.equal(queued.pending?.status, 'pending');
  const actionId = queued.pending?.id as string;
  assert.ok(actionId.startsWith('pact_'));

  // deny: updates are refused outright without a pending record.
  const denied = await client.fetchProtected(site, {
    method: 'PATCH',
    grantId: grant.jti,
    target: '/api/posts/post_nonexistent',
    body: JSON.stringify({ title: 'x' }),
  });
  assert.equal(denied.status, 403);
  assert.equal(denied.error?.code, 'tg.request.permission_denied');

  // The human approves the queued create and it executes.
  const approveCsrf = await csrfOf(app, cookie, `/workspace/approvals/${actionId}`);
  const approve = await req(app, 'POST', '/workspace/approvals/decide', {
    cookie,
    form: { _csrf: approveCsrf, action_id: actionId, decision: 'approve' },
  });
  assert.equal(approve.status, 303);
  const done = await client.actionStatus(site, actionId, { grantId: grant.jti });
  assert.equal(done.status, 'succeeded');

  // The access page editor flips reads to approval-only and frees creates.
  const editCsrf = await csrfOf(app, cookie, '/workspace/access');
  const edit = new URLSearchParams({ _csrf: editCsrf });
  for (const perm of [
    'tg.posts.read',
    'tg.posts.create',
    'tg.posts.update',
    'tg.posts.publish',
    'tg.posts.delete',
    'tg.posts.settings',
    'tg.comments.read',
    'tg.comments.delete',
    'tg.notifications.read',
    'tg.notifications.write',
    'tg.profile.read',
  ]) {
    edit.append(
      `mode_${perm}`,
      perm === 'tg.posts.read' ? 'approval' : perm === 'tg.posts.create' ? 'allow' : 'deny',
    );
  }
  const scoped = await app.handle({
    method: 'POST',
    url: `/workspace/access/${grant.jti}/scope`,
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new TextEncoder().encode(edit.toString()),
  });
  assert.equal(scoped.status, 303);

  // reads now queue; creates run immediately.
  const readQueued = await client.fetchProtected(site, {
    method: 'GET',
    grantId: grant.jti,
    target: '/api/posts',
  });
  assert.equal(readQueued.status, 202);
  const readActionId = readQueued.pending?.id as string;

  const createNow = await client.fetchProtected(site, {
    method: 'POST',
    grantId: grant.jti,
    target: '/api/posts',
    body: JSON.stringify({ title: 'Now allowed', body: 'no review needed' }),
  });
  assert.equal(createNow.status, 201);

  const readApproveCsrf = await csrfOf(app, cookie, `/workspace/approvals/${readActionId}`);
  const readApprove = await req(app, 'POST', '/workspace/approvals/decide', {
    cookie,
    form: { _csrf: readApproveCsrf, action_id: readActionId, decision: 'approve' },
  });
  assert.equal(readApprove.status, 303);
  const readDone = await client.actionStatus(site, readActionId, { grantId: grant.jti });
  assert.equal(readDone.status, 'succeeded');
});
