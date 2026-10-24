import type { Session, User } from '../domain/users.ts';

/** Cookie jar parsed from the request's Cookie header. */
export type Cookies = Record<string, string>;

/**
 * Application-level request for blog pages and the agent JSON API. For
 * protocol endpoints the adapter builds a `HostRequest` instead; this type
 * is for the site's own surface.
 */
export interface AppRequest {
  method: string;
  /** Path only, for example `/orders/ord_1`. */
  path: string;
  /** Parsed URL including raw query. */
  url: URL;
  params: Record<string, string>;
  query: URLSearchParams;
  headers: Record<string, string>;
  cookies: Cookies;
  /** Raw request body bytes, when present. */
  body?: Uint8Array;
  /** Authenticated session/user when a valid `blog_session` cookie exists. */
  session?: Session;
  user?: User;
}

export interface AppResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

export type AppHandler = (req: AppRequest) => Promise<AppResponse> | AppResponse;

interface Route {
  method: string;
  segments: string[];
  handler: AppHandler;
}

/**
 * Minimal router supporting `:param` segments. Used for the site's own UI
 * and JSON API. Protocol endpoints (`/.well-known/trailgate`, `/tg/*`)
 * bypass it and go straight to the SDK.
 */
export class Router {
  readonly #routes: Route[] = [];

  add(method: string, pattern: string, handler: AppHandler): void {
    this.#routes.push({
      method: method.toUpperCase(),
      segments: pattern.split('/').filter((s) => s !== ''),
      handler,
    });
  }

  get(pattern: string, handler: AppHandler): void {
    this.add('GET', pattern, handler);
  }

  post(pattern: string, handler: AppHandler): void {
    this.add('POST', pattern, handler);
  }

  match(
    method: string,
    path: string,
  ): { handler: AppHandler; params: Record<string, string> } | undefined {
    const wanted = path.split('/').filter((s) => s !== '');
    for (const route of this.#routes) {
      if (route.method !== method.toUpperCase() || route.segments.length !== wanted.length) {
        continue;
      }
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < route.segments.length; i++) {
        const segment = route.segments[i] as string;
        const actual = wanted[i] as string;
        if (segment.startsWith(':')) {
          params[segment.slice(1)] = decodeURIComponent(actual);
        } else if (segment !== actual) {
          ok = false;
          break;
        }
      }
      if (ok) {
        return { handler: route.handler, params };
      }
    }
    return undefined;
  }
}
