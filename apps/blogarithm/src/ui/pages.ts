import type { Comment } from '../domain/comments.ts';
import type { Notification } from '../domain/notifications.ts';
import type { Post } from '../domain/posts.ts';
import type { User } from '../domain/users.ts';
import { PERMISSION_LABELS } from '../tg/vocabulary.ts';
import { esc, formatDate, formatTime } from './html.ts';
import { renderMarkdown } from './markdown.ts';

const AVATAR_COLORS = ['#2563eb', '#7c3aed', '#0891b2', '#be185d', '#b45309', '#15803d'];

function avatar(name: string, image: string, size = 36): string {
  if (image !== '') {
    return `<span class="avatar" style="width:${size}px;height:${size}px"><img src="${esc(image)}" alt=""></span>`;
  }
  const color = AVATAR_COLORS[name.length % AVATAR_COLORS.length];
  const initial = esc(name.trim().charAt(0).toUpperCase() || '?');
  return `<span class="avatar avatar-initial" style="width:${size}px;height:${size}px;background:${color}">${initial}</span>`;
}

function tagList(tags: string[]): string {
  return tags
    .map((t) => `<a class="tag" href="/search?tag=${encodeURIComponent(t)}">${esc(t)}</a>`)
    .join('');
}

export function postCard(post: Post, author?: User, featured = false): string {
  const cover =
    post.coverImage !== ''
      ? `<div class="card-cover"><img src="${esc(post.coverImage)}" alt=""></div>`
      : '';
  return `
  <article class="post-card${featured ? ' post-card-featured' : ''}">
    ${cover}
    <div class="card-body">
      <div class="card-tags">${tagList(post.tags)}</div>
      <h${featured ? '1' : '2'} class="card-title"><a href="/post/${esc(post.slug)}">${esc(post.title)}</a></h${featured ? '1' : '2'}>
      ${post.excerpt !== '' ? `<p class="card-excerpt">${esc(post.excerpt)}</p>` : ''}
      <div class="card-meta">
        ${author !== undefined ? `${avatar(author.name, author.avatar, 28)}<span>${esc(author.name)}</span>` : ''}
        <span>${post.publishedAt !== undefined ? formatDate(post.publishedAt) : ''}</span>
      </div>
    </div>
  </article>`;
}

export function renderHome(
  posts: Post[],
  authors: Map<string, User>,
  q?: string,
  tag?: string,
): string {
  const featured = posts[0];
  const rest = posts.slice(1);
  const heading =
    tag !== undefined
      ? `<p class="listing-note">Posts tagged <strong>${esc(tag)}</strong>. <a href="/">Clear</a></p>`
      : q !== undefined && q !== ''
        ? `<p class="listing-note">Results for <strong>${esc(q)}</strong>. <a href="/">Clear</a></p>`
        : '';
  if (posts.length === 0) {
    return `<section class="empty-state"><h1>Nothing published here yet</h1>
      <p>When authors publish posts they will appear on this page.</p></section>`;
  }
  return `
  ${heading}
  ${featured !== undefined && q === undefined && tag === undefined ? postCard(featured, authors.get(featured.authorId), true) : ''}
  <section class="post-grid">
    ${(q !== undefined || tag !== undefined ? posts : rest).map((p) => postCard(p, authors.get(p.authorId))).join('')}
  </section>`;
}

export function renderArticle(
  post: Post,
  author: User | undefined,
  comments: Comment[],
  canComment: boolean,
): string {
  const cover =
    post.coverImage !== ''
      ? `<div class="article-cover"><img src="${esc(post.coverImage)}" alt=""></div>`
      : '';
  const commentSection = post.commentsEnabled
    ? `
    <section class="comments">
      <h2>Comments (${comments.length})</h2>
      ${comments
        .map(
          (c) => `<div class="comment">
            <div class="comment-head">${avatar(c.authorName, '', 28)}<strong>${esc(c.authorName)}</strong><span class="muted">${formatTime(c.createdAt)}</span></div>
            <p>${esc(c.body)}</p>
          </div>`,
        )
        .join('')}
      ${
        canComment
          ? `<form method="post" action="/post/${esc(post.slug)}/comments" class="comment-form">
            <h3>Leave a comment</h3>
            <label>Name <input name="name" maxlength="80" required></label>
            <label>Comment <textarea name="body" rows="4" maxlength="2000" required></textarea></label>
            <button class="btn btn-primary" type="submit">Post comment</button>
          </form>`
          : ''
      }
    </section>`
    : `<section class="comments"><p class="muted">Comments are closed on this post.</p>
       ${comments.map((c) => `<div class="comment"><div class="comment-head"><strong>${esc(c.authorName)}</strong></div><p>${esc(c.body)}</p></div>`).join('')}
       </section>`;
  return `
  <article class="article">
    <header class="article-head">
      <div class="card-tags">${tagList(post.tags)}</div>
      <h1>${esc(post.title)}</h1>
      ${post.excerpt !== '' ? `<p class="article-excerpt">${esc(post.excerpt)}</p>` : ''}
      <div class="article-meta">
        ${author !== undefined ? `${avatar(author.name, author.avatar, 36)}<div><strong>${esc(author.name)}</strong><br><span class="muted">${post.publishedAt !== undefined ? formatDate(post.publishedAt) : ''}</span></div>` : ''}
      </div>
    </header>
    ${cover}
    <div class="article-body">${renderMarkdown(post.body)}</div>
    ${commentSection}
  </article>`;
}

export function renderAuth(
  kind: 'login' | 'register',
  error?: string,
  next = '/workspace',
): string {
  const isLogin = kind === 'login';
  return `
  <section class="auth-card">
    <h1>${isLogin ? 'Welcome back' : 'Create your account'}</h1>
    <p class="muted">${isLogin ? 'Sign in to your writing workspace.' : 'Start publishing on Blogarithm.'}</p>
    ${error !== undefined ? `<div class="flash flash-error">${esc(error)}</div>` : ''}
    <form method="post" action="/${kind}" class="form">
      <input type="hidden" name="next" value="${esc(next)}">
      ${
        isLogin
          ? ''
          : `<label>Display name <input name="name" maxlength="120" required></label>
             <label>Username <input name="username" maxlength="30" required pattern="[a-z0-9][a-z0-9_-]{2,29}" title="lowercase letters, digits, dash or underscore"></label>`
      }
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" minlength="10" required></label>
      <button class="btn btn-primary btn-block" type="submit">${isLogin ? 'Sign in' : 'Create account'}</button>
    </form>
    <p class="muted auth-switch">${
      isLogin
        ? 'New here? <a href="/register">Create an account</a>. Demo account: demo@blogarithm.dev / demo-password-1'
        : 'Already have an account? <a href="/login">Sign in</a>.'
    }</p>
  </section>`;
}

export function renderOverview(
  user: User,
  stats: { published: number; drafts: number; comments: number },
  recentPosts: Post[],
  recentNotifications: Notification[],
): string {
  return `
  <div class="page-head">
    <div><h1>Good ${new Date().getUTCHours() < 12 ? 'morning' : new Date().getUTCHours() < 18 ? 'afternoon' : 'evening'}, ${esc(user.name.split(' ')[0] ?? user.name)}</h1>
    <p class="muted">Here is what is happening on your blog.</p></div>
    <a class="btn btn-primary" href="/workspace/posts/new">New post</a>
  </div>
  <section class="stat-row">
    <div class="stat"><span class="stat-num">${stats.published}</span><span class="stat-label">Published</span></div>
    <div class="stat"><span class="stat-num">${stats.drafts}</span><span class="stat-label">Drafts</span></div>
    <div class="stat"><span class="stat-num">${stats.comments}</span><span class="stat-label">Comments</span></div>
  </section>
  <div class="two-col">
    <section>
      <h2 class="section-title">Recent posts</h2>
      ${
        recentPosts.length === 0
          ? '<p class="muted">No posts yet. <a href="/workspace/posts/new">Write your first post</a>.</p>'
          : `<ul class="row-list">${recentPosts.map((p) => postRow(p)).join('')}</ul>`
      }
    </section>
    <section>
      <h2 class="section-title">Recent activity</h2>
      ${
        recentNotifications.length === 0
          ? '<p class="muted">Nothing yet.</p>'
          : `<ul class="row-list">${recentNotifications
              .map(
                (n) =>
                  `<li class="row"><span>${esc(n.title)} <span class="muted">${esc(n.message)}</span></span><span class="muted">${formatTime(n.createdAt)}</span></li>`,
              )
              .join('')}</ul>`
      }
    </section>
  </div>`;
}

function statusBadge(status: string): string {
  return `<span class="status status-${status}">${status}</span>`;
}

function postRow(p: Post): string {
  const when =
    p.status === 'published' && p.publishedAt !== undefined
      ? `published ${formatDate(p.publishedAt)}`
      : `updated ${formatTime(p.updatedAt)}`;
  return `<li class="row">
    <span><a href="/workspace/posts/${esc(p.id)}/edit"><strong>${esc(p.title)}</strong></a>
    <span class="muted">${when}</span></span>
    ${statusBadge(p.status)}
  </li>`;
}

export function renderPostsList(
  posts: Post[],
  filter: { status?: string; q?: string },
  csrf: string,
): string {
  const tabs = ['', 'draft', 'published', 'deleted']
    .map((s) => {
      const label = s === '' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1);
      const active = (filter.status ?? '') === s ? ' tab-active' : '';
      const href = s === '' ? '/workspace/posts' : `/workspace/posts?status=${s}`;
      return `<a class="tab${active}" href="${href}">${label}</a>`;
    })
    .join('');
  return `
  <div class="page-head"><h1>Posts</h1><a class="btn btn-primary" href="/workspace/posts/new">New post</a></div>
  <div class="toolbar">
    <div class="tabs">${tabs}</div>
    <form method="get" action="/workspace/posts" class="search-form">
      <input name="q" placeholder="Search posts" value="${esc(filter.q ?? '')}">
    </form>
  </div>
  ${
    posts.length === 0
      ? '<p class="muted">No posts match.</p>'
      : `<ul class="row-list">${posts
          .map(
            (p) => `<li class="row row-actions">
        <span><a href="/workspace/posts/${esc(p.id)}/edit"><strong>${esc(p.title)}</strong></a>
        <span class="muted">updated ${formatTime(p.updatedAt)}</span></span>
        <span class="row-ops">
          ${statusBadge(p.status)}
          ${
            p.status === 'draft'
              ? `<form method="post" action="/workspace/posts/${esc(p.id)}/publish" class="inline-form"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn btn-small" type="submit">Publish</button></form>`
              : ''
          }
          ${
            p.status === 'published'
              ? `<a class="btn btn-small" href="/post/${esc(p.slug)}" target="_blank">View</a>
                 <form method="post" action="/workspace/posts/${esc(p.id)}/unpublish" class="inline-form"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn btn-small" type="submit">Unpublish</button></form>`
              : ''
          }
          ${
            p.status === 'deleted'
              ? `<form method="post" action="/workspace/posts/${esc(p.id)}/restore" class="inline-form"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn btn-small" type="submit">Restore</button></form>`
              : `<form method="post" action="/workspace/posts/${esc(p.id)}/delete" class="inline-form" onsubmit="return confirm('Move this post to trash?')"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn btn-small btn-danger" type="submit">Delete</button></form>`
          }
        </span>
      </li>`,
          )
          .join('')}</ul>`
  }`;
}

export function renderEditor(post: Post | undefined, csrf: string): string {
  const p: Partial<Post> = post ?? {};
  const id = p.id ?? 'new';
  const isNew = post === undefined;
  const body = p.body ?? '';
  return `
  <div class="page-head">
    <div><a class="muted" href="/workspace/posts">&larr; Posts</a>
    <h1>${isNew ? 'New post' : 'Edit post'}</h1></div>
    <div class="row-ops">
      ${!isNew && post.status === 'draft' ? `<form method="post" action="/workspace/posts/${esc(id)}/publish" class="inline-form"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn btn-primary" type="submit">Publish</button></form>` : ''}
      ${!isNew && post.status === 'published' ? `<a class="btn" href="/post/${esc(p.slug ?? '')}" target="_blank">View live</a>` : ''}
    </div>
  </div>
  <form method="post" action="/workspace/posts/${esc(id)}/save" class="editor-form">
    <input type="hidden" name="_csrf" value="${esc(csrf)}">
    <input class="title-input" name="title" placeholder="Post title" maxlength="200" required value="${esc(p.title ?? '')}">
    <div class="editor-grid">
      <div class="editor-main">
        <label class="field-label">Body <span class="muted">(Markdown: **bold**, *italic*, # headings, - lists, &gt; quotes, \`\`\` code)</span></label>
        <textarea name="body" rows="18" class="body-input" placeholder="Write your post...">${esc(body)}</textarea>
      </div>
      <aside class="editor-side">
        ${!isNew ? `<p class="muted">Status: ${statusBadge(p.status ?? 'draft')}</p>` : ''}
        <label class="field-label">Excerpt
          <textarea name="excerpt" rows="3" maxlength="500">${esc(p.excerpt ?? '')}</textarea></label>
        <label class="field-label">Cover image URL
          <input name="cover_image" maxlength="500" value="${esc(p.coverImage ?? '')}"></label>
        <label class="field-label">Tags <span class="muted">(comma separated)</span>
          <input name="tags" value="${esc((p.tags ?? []).join(', '))}"></label>
        <label class="check"><input type="checkbox" name="comments_enabled" value="1"${p.commentsEnabled !== false ? ' checked' : ''}> Enable comments</label>
        <button class="btn btn-primary btn-block" type="submit">${isNew ? 'Save draft' : 'Save changes'}</button>
        ${!isNew ? `<a class="btn btn-block" href="/workspace/posts/${esc(id)}/preview" target="_blank">Preview</a>` : ''}
      </aside>
    </div>
  </form>`;
}

export function renderCommentsPage(
  items: { comment: Comment; post: Post }[],
  csrf: string,
): string {
  return `
  <div class="page-head"><h1>Comments</h1></div>
  ${
    items.length === 0
      ? '<p class="muted">No comments on your posts yet.</p>'
      : `<ul class="row-list">${items
          .map(
            ({ comment: c, post }) => `<li class="row row-actions">
        <span><strong>${esc(c.authorName)}</strong> on <a href="/post/${esc(post.slug)}">${esc(post.title)}</a>
          <span class="muted">${formatTime(c.createdAt)}</span>
          <p class="comment-body">${esc(c.body)}</p></span>
        <form method="post" action="/workspace/comments/${esc(c.id)}/delete" class="inline-form" onsubmit="return confirm('Delete this comment?')">
          <input type="hidden" name="_csrf" value="${esc(csrf)}">
          <button class="btn btn-small btn-danger" type="submit">Delete</button></form>
      </li>`,
          )
          .join('')}</ul>`
  }`;
}

export function renderNotificationsPage(notifications: Notification[], csrf: string): string {
  return `
  <div class="page-head"><h1>Notifications</h1>
    <form method="post" action="/workspace/notifications/read-all" class="inline-form">
      <input type="hidden" name="_csrf" value="${esc(csrf)}">
      <button class="btn" type="submit">Mark all read</button></form></div>
  ${
    notifications.length === 0
      ? '<p class="muted">No notifications.</p>'
      : `<ul class="row-list">${notifications
          .map(
            (n) => `<li class="row${n.readAt === undefined ? ' row-unread' : ''}">
        <span><strong>${esc(n.title)}</strong> <span class="muted">${esc(n.message)}</span>
          <span class="muted">${formatTime(n.createdAt)}</span></span>
        ${
          n.readAt === undefined
            ? `<form method="post" action="/workspace/notifications/${esc(n.id)}/read" class="inline-form">
              <input type="hidden" name="_csrf" value="${esc(csrf)}">
              <button class="btn btn-small" type="submit">Mark read</button></form>`
            : ''
        }
      </li>`,
          )
          .join('')}</ul>`
  }`;
}

export function renderSettings(user: User, csrf: string): string {
  return `
  <div class="page-head"><h1>Settings</h1></div>
  <section class="settings-card">
    <h2 class="section-title">Profile</h2>
    <form method="post" action="/workspace/settings" class="form">
      <input type="hidden" name="_csrf" value="${esc(csrf)}">
      <label>Display name <input name="name" maxlength="120" required value="${esc(user.name)}"></label>
      <label>Username <input name="username" maxlength="30" required value="${esc(user.username)}"></label>
      <label>Avatar image URL <input name="avatar" maxlength="500" value="${esc(user.avatar)}"></label>
      <label>Bio <textarea name="bio" rows="3" maxlength="500">${esc(user.bio)}</textarea></label>
      <button class="btn btn-primary" type="submit">Save profile</button>
    </form>
  </section>`;
}

interface GrantView {
  jti: string;
  agentJkt: string;
  permissions: string[];
  issuedAt: number;
  expiresAt: number;
  status: string;
}

export function renderAccessPage(grants: GrantView[], csrf: string, now: number): string {
  const rows = grants.map((g) => {
    const expired = g.expiresAt <= now;
    const status = g.status === 'revoked' ? 'revoked' : expired ? 'expired' : 'active';
    return `<li class="row row-actions">
      <span>
        <strong>Agent ${esc(g.agentJkt.slice(0, 12))}&hellip;</strong>
        <span class="muted">granted ${formatTime(g.issuedAt)} &middot; expires ${formatTime(g.expiresAt)}</span>
        <span class="perm-list">${g.permissions
          .map((p) => `<span class="perm">${esc(PERMISSION_LABELS[p]?.label ?? p)}</span>`)
          .join('')}</span>
      </span>
      <span class="row-ops">
        ${statusBadge(status)}
        ${
          status === 'active'
            ? `<form method="post" action="/workspace/access/${esc(g.jti)}/revoke" class="inline-form" onsubmit="return confirm('Revoke this agent access?')">
              <input type="hidden" name="_csrf" value="${esc(csrf)}">
              <button class="btn btn-small btn-danger" type="submit">Revoke</button></form>`
            : ''
        }
      </span>
    </li>`;
  });
  return `
  <div class="page-head"><h1>Agent access</h1></div>
  <p class="muted">Agents connect through <a href="/.well-known/trailgate">TrailGate</a> and act only within the permissions shown here.</p>
  ${grants.length === 0 ? '<p class="muted">No agent grants yet. When an agent requests access, you will approve it on the consent screen.</p>' : `<ul class="row-list">${rows.join('')}</ul>`}`;
}

export function renderConsent(options: {
  requestId: string;
  csrf: string;
  permissions: string[];
  resources: string[];
  agentHint?: string;
  requestedSeconds?: number;
  error?: string;
}): string {
  const granted = options.permissions;
  const known = Object.keys(PERMISSION_LABELS);
  const notRequested = known.filter((p) => !granted.includes(p));
  const minutes =
    options.requestedSeconds !== undefined ? Math.round(options.requestedSeconds / 60) : undefined;
  const permItem = (p: string) => {
    const info = PERMISSION_LABELS[p];
    return `<li class="perm-item perm-${info?.risk ?? 'read'}">
      <label class="check"><input type="checkbox" name="perm" value="${esc(p)}" checked>
      <span>${esc(info?.label ?? p)}</span></label></li>`;
  };
  return `
  <section class="consent-card">
    <p class="consent-kicker">Access request</p>
    <h1>An agent is asking for access to your blog</h1>
    ${options.error !== undefined ? `<div class="flash flash-error">${esc(options.error)}</div>` : ''}
    ${options.agentHint !== undefined ? `<p class="muted">Requested by <strong>${esc(options.agentHint)}</strong></p>` : ''}
    <form method="post" action="/tg/consent" class="form">
      <input type="hidden" name="_csrf" value="${esc(options.csrf)}">
      <input type="hidden" name="request_id" value="${esc(options.requestId)}">
      <h2 class="section-title">Requested permissions</h2>
      <ul class="perm-items">${granted.map(permItem).join('')}</ul>
      ${
        options.resources.length > 0
          ? `<h2 class="section-title">Limited to resources</h2>
             <ul class="perm-items">${options.resources.map((r) => `<li class="perm-item"><span>${esc(r)}</span></li>`).join('')}</ul>`
          : ''
      }
      ${minutes !== undefined ? `<p class="muted">Grant duration: ${minutes} minutes</p>` : ''}
      <h2 class="section-title">Not requested</h2>
      <p class="muted">${notRequested.map((p) => esc(PERMISSION_LABELS[p]?.label ?? p)).join(' &middot; ') || 'none'}</p>
      <div class="row-ops">
        <button class="btn" type="submit" name="decision" value="deny">Decline</button>
        <button class="btn btn-primary" type="submit" name="decision" value="approve">Authorize access</button>
      </div>
    </form>
  </section>`;
}

export function renderNotFound(): string {
  return '<section class="empty-state"><h1>Not found</h1><p>The page you asked for does not exist.</p></section>';
}

export function renderError(message: string): string {
  return `<section class="empty-state"><h1>Something went wrong</h1><p>${esc(message)}</p></section>`;
}
