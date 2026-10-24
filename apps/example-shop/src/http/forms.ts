import type { AppRequest } from './router.ts';

/**
 * Parses an `application/x-www-form-urlencoded` body into a string map.
 * Multi-value fields keep their first value; the shop's forms never rely on
 * repeats.
 */
export function parseForm(req: AppRequest): Record<string, string> {
  const body = req.body;
  if (body === undefined) {
    return {};
  }
  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.includes('application/x-www-form-urlencoded')) {
    return {};
  }
  const params = new URLSearchParams(new TextDecoder().decode(body));
  const out: Record<string, string> = {};
  for (const [key, value] of params) {
    if (!(key in out)) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Same input as `parseForm` but keeps every repeated field as an array.
 * Used for checkbox groups such as the consent scope editor.
 */
export function parseFormValues(req: AppRequest): Record<string, string[]> {
  const body = req.body;
  if (body === undefined) {
    return {};
  }
  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.includes('application/x-www-form-urlencoded')) {
    return {};
  }
  const params = new URLSearchParams(new TextDecoder().decode(body));
  const out: Record<string, string[]> = {};
  for (const [key, value] of params) {
    const list = out[key];
    if (list === undefined) {
      out[key] = [value];
    } else {
      list.push(value);
    }
  }
  return out;
}

/** Parses a JSON body for the agent-facing API. Returns undefined on failure. */
export function parseJsonBody(req: AppRequest): unknown {
  const body = req.body;
  if (body === undefined || body.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    return undefined;
  }
}

export class CsrfError extends Error {
  constructor() {
    super('form token is missing or does not match the session');
    this.name = 'CsrfError';
  }
}

/**
 * Synchronizer-token CSRF check for browser form posts. The token is bound
 * to the session row; SameSite=Lax on the cookie is the second layer.
 */
export function requireCsrf(req: AppRequest, form: Record<string, string>): void {
  const token = req.session?.csrfToken;
  const supplied = form._csrf;
  if (token === undefined || supplied === undefined || supplied !== token) {
    throw new CsrfError();
  }
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (header === undefined) {
    return out;
  }
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) {
      continue;
    }
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}
