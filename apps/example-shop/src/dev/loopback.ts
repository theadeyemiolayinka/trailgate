import type { AgentHttpRequest, AgentHttpResponse, HttpTransport } from '@trailgate/agent';

/**
 * Development transport: maps the site's https issuer identity onto the
 * plain-HTTP dev listener. The agent still signs `https://issuer` URIs;
 * the server rebuilds `HostRequest.url` from the same issuer, so request
 * signatures verify exactly as they would over real TLS. This exercises
 * the full protocol against a live server without needing local certs.
 *
 * For real-TLS end-to-end runs, generate dev certs (`pnpm certs`) and use
 * the default `fetchTransport` with `NODE_EXTRA_CA_CERTS` set.
 */
export function loopbackTransport(
  issuer: string,
  httpBase: string,
): HttpTransport & { mapUrl: (url: string) => string } {
  const mapUrl = (url: string): string =>
    url.startsWith(issuer) ? `${httpBase}${url.slice(issuer.length)}` : url;
  return {
    mapUrl,
    send: async (req: AgentHttpRequest): Promise<AgentHttpResponse> => {
      const res = await fetch(mapUrl(req.url), {
        method: req.method,
        headers: req.headers ?? {},
        redirect: 'manual',
        // undici rejects any body field on GET/HEAD, even zero-length; the
        // signed Content-Digest is identical either way (digest of empty).
        ...(req.body !== undefined && req.body.length > 0 ? { body: req.body } : {}),
      });
      const body = new Uint8Array(await res.arrayBuffer());
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      return { status: res.status, headers, body };
    },
  };
}
