import { Codes, TrailGateError } from '@trailgate/core';

/**
 * Framework-neutral HTTP request the SDK sends. `url` is the absolute
 * request URI; `headers` uses lowercased field names; `body` is the exact
 * bytes that become the `Content-Digest` input.
 */
export interface AgentHttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
}

/** Framework-neutral HTTP response. `headers` uses lowercased field names. */
export interface AgentHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

/**
 * Transport port. The default implementation is `fetchTransport`; tests and
 * non-fetch runtimes inject their own. Implementations MUST NOT follow
 * redirects: the spec forbids redirect chasing on the discovery fetch
 * (spec section 5.3), and a followed redirect would change the signed
 * target out from under a request signature.
 */
export interface HttpTransport {
  send(req: AgentHttpRequest): Promise<AgentHttpResponse>;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

function collectHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * `fetch`-based transport (Node 22+). Never follows redirects and applies a
 * hard timeout. Transport failures surface as `tg.internal.unavailable` so
 * callers can fail closed uniformly.
 */
export function fetchTransport(options?: { timeoutMs?: number }): HttpTransport {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return {
    send: async (req) => {
      let res: Response;
      try {
        const init: RequestInit = {
          method: req.method,
          headers: req.headers ?? {},
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
        };
        if (req.body !== undefined && req.body.byteLength > 0) {
          init.body = req.body;
        }
        res = await fetch(req.url, init);
      } catch (err) {
        throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'transport request failed', {
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      const body = new Uint8Array(await res.arrayBuffer());
      return { status: res.status, headers: collectHeaders(res.headers), body };
    },
  };
}
