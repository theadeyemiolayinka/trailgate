import type { AppResponse } from './router.ts';

export function html(
  body: string,
  status = 200,
  headers: Record<string, string> = {},
): AppResponse {
  return {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', ...headers },
    body,
  };
}

export function json(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
): AppResponse {
  return {
    status,
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(value),
  };
}

export function redirect(location: string, status = 303): AppResponse {
  return { status, headers: { location } };
}

export function text(body: string, status = 200): AppResponse {
  return { status, headers: { 'content-type': 'text/plain; charset=utf-8' }, body };
}
