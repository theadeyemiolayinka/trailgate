import type { User } from '../domain/users.ts';
import { esc } from './html.ts';

export interface PageOptions {
  title: string;
  user?: User;
  csrf?: string;
  unreadCount?: number;
  flash?: { kind: 'info' | 'error' | 'ok'; text: string };
  /** 'public' renders the site nav; 'workspace' renders the workspace nav. */
  context: 'public' | 'workspace';
  /** Current nav section, for example 'posts' or 'search'. */
  section?: string;
  body: string;
}

const BRAND_MARK = `<svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="4" fill="var(--accent)"/><text x="16" y="22.5" text-anchor="middle" font-family="Iowan Old Style, Palatino, Georgia, serif" font-size="18" fill="#f6f3ea">B</text></svg>`;

function navLink(
  href: string,
  label: string,
  section: string | undefined,
  key: string,
  suffix = '',
): string {
  const current = section === key ? ' aria-current="page"' : '';
  return `<a href="${href}"${current}>${esc(label)}${suffix}</a>`;
}

function publicNav(user: User | undefined, section: string | undefined): string {
  return `
  <header class="site-nav">
    <div class="nav-inner">
      <a class="brand" href="/" aria-label="Blogarithm home">${BRAND_MARK}<span>Blogarithm</span></a>
      <nav class="nav-links" aria-label="Primary">
        ${navLink('/', 'Articles', section, 'articles')}
        ${navLink('/search', 'Search', section, 'search')}
      </nav>
      <div class="nav-actions">
        ${
          user !== undefined
            ? `<a class="btn btn-primary" href="/workspace">Workspace</a>`
            : `<a class="nav-link" href="/login">Sign in</a>
               <a class="btn btn-primary" href="/register">Start writing</a>`
        }
      </div>
    </div>
  </header>`;
}

function workspaceNav(
  user: User,
  unread: number,
  csrf: string,
  section: string | undefined,
): string {
  const badge = unread > 0 ? ` <span class="badge">${unread}</span>` : '';
  return `
  <header class="site-nav">
    <div class="nav-inner">
      <a class="brand" href="/" aria-label="Blogarithm home">${BRAND_MARK}<span>Blogarithm</span></a>
      <nav class="nav-links" aria-label="Workspace">
        ${navLink('/workspace', 'Overview', section, 'overview')}
        ${navLink('/workspace/posts', 'Posts', section, 'posts')}
        ${navLink('/workspace/comments', 'Comments', section, 'comments')}
        ${navLink('/workspace/notifications', 'Notifications', section, 'notifications', badge)}
        ${navLink('/workspace/settings', 'Settings', section, 'settings')}
        ${navLink('/workspace/access', 'Agent access', section, 'access')}
        ${navLink('/workspace/approvals', 'Approvals', section, 'approvals')}
      </nav>
      <div class="nav-actions">
        <a class="btn btn-primary" href="/workspace/posts/new">New post</a>
        <span class="nav-user">${esc(user.name)}</span>
        <form method="post" action="/logout" class="inline-form">
          <input type="hidden" name="_csrf" value="${esc(csrf)}">
          <button class="nav-link" type="submit">Sign out</button>
        </form>
      </div>
    </div>
  </header>`;
}

export function page(options: PageOptions): string {
  const nav =
    options.context === 'workspace' && options.user !== undefined
      ? workspaceNav(options.user, options.unreadCount ?? 0, options.csrf ?? '', options.section)
      : publicNav(options.user, options.section);
  const flash =
    options.flash !== undefined
      ? `<div class="flash flash-${options.flash.kind}" role="status">${esc(options.flash.text)}</div>`
      : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(options.title === 'Blogarithm' ? options.title : `${options.title} · Blogarithm`)}</title>
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
${nav}
${flash}
<main id="main" class="${options.context === 'workspace' ? 'workspace-main' : 'site-main'}">
${options.body}
</main>
<footer class="site-footer">
  <div class="footer-inner">
    <span class="brand">${BRAND_MARK}<span>Blogarithm</span></span>
    <span>An editorial demo for the <a href="/.well-known/trailgate">TrailGate</a> delegated-authorization protocol.</span>
    <span><a href="/">Articles</a> &middot; <a href="/search">Search</a> &middot; <a href="/workspace">Workspace</a></span>
  </div>
</footer>
</body>
</html>`;
}
