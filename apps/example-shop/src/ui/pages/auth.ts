import { esc } from '../html.ts';
import type { RenderCtx } from '../render.ts';

export function renderLogin(_ctx: RenderCtx, next: string, error?: string): string {
  const errorBlock =
    error !== undefined ? `<div class="flash flash-error" role="alert">${esc(error)}</div>` : '';
  return `
<div class="auth-layout">
  <div class="panel">
    <span class="eyebrow">Welcome back</span>
    <h1>Sign in</h1>
    ${errorBlock}
    <form method="post" action="/login">
      <input type="hidden" name="next" value="${esc(next)}">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="email" required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button class="button" type="submit">Sign in</button>
    </form>
  </div>
  <p class="auth-alt">New to ExampleShop? <a href="/register?next=${encodeURIComponent(next)}">Create an account</a></p>
</div>`;
}

export function renderRegister(_ctx: RenderCtx, next: string, error?: string): string {
  const errorBlock =
    error !== undefined ? `<div class="flash flash-error" role="alert">${esc(error)}</div>` : '';
  return `
<div class="auth-layout">
  <div class="panel">
    <span class="eyebrow">Join ExampleShop</span>
    <h1>Create your account</h1>
    ${errorBlock}
    <form method="post" action="/register">
      <input type="hidden" name="next" value="${esc(next)}">
      <div class="field">
        <label for="name">Full name</label>
        <input id="name" name="name" autocomplete="name" required maxlength="120">
      </div>
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="email" required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" minlength="10" required>
        <p class="hint">At least 10 characters.</p>
      </div>
      <button class="button" type="submit">Create account</button>
    </form>
  </div>
  <p class="auth-alt">Already have an account? <a href="/login?next=${encodeURIComponent(next)}">Sign in</a></p>
</div>`;
}

export function renderNotFound(): string {
  return `
<div class="empty-state">
  <h2>Page not found</h2>
  <p>The page you asked for does not exist.</p>
  <p><a class="button" href="/">Back to the shop</a></p>
</div>`;
}

export function renderError(message?: string): string {
  return `
<div class="empty-state">
  <h2>Something went wrong</h2>
  <p>${esc(message ?? 'An unexpected error occurred.')}</p>
  <p><a class="button" href="/">Back to the shop</a></p>
</div>`;
}
