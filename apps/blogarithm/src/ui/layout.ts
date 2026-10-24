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
  body: string;
}

function publicNav(user?: User): string {
  return `
  <header class="site-nav">
    <div class="nav-inner">
      <a class="brand" href="/">Blogarithm</a>
      <nav class="nav-links">
        <a href="/">Articles</a>
        <a href="/search">Search</a>
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

function workspaceNav(user: User, unread: number, csrf: string): string {
  const badge = unread > 0 ? `<span class="badge">${unread}</span>` : '';
  return `
  <header class="site-nav">
    <div class="nav-inner">
      <a class="brand" href="/">Blogarithm</a>
      <nav class="nav-links">
        <a href="/workspace">Overview</a>
        <a href="/workspace/posts">Posts</a>
        <a href="/workspace/comments">Comments</a>
        <a href="/workspace/notifications">Notifications ${badge}</a>
        <a href="/workspace/settings">Settings</a>
        <a href="/workspace/access">Agent access</a>
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
      ? workspaceNav(options.user, options.unreadCount ?? 0, options.csrf ?? '')
      : publicNav(options.user);
  const flash =
    options.flash !== undefined
      ? `<div class="flash flash-${options.flash.kind}">${esc(options.flash.text)}</div>`
      : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(options.title)} · Blogarithm</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
${nav}
${flash}
<main class="${options.context === 'workspace' ? 'workspace-main' : 'site-main'}">
${options.body}
</main>
<footer class="site-footer">
  <div class="footer-inner">
    <span>Blogarithm, a TrailGate demonstration application.</span>
    <a href="/.well-known/trailgate">Protocol discovery</a>
  </div>
</footer>
</body>
</html>`;
}
