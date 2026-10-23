import type { Clock, DiscoveryDocument, Jwk, KeyResolver } from '@trailgate/core';
import {
  Codes,
  DISCOVERY_PATH,
  jwkThumbprint,
  negotiateProtocolVersion,
  SUPPORTED_PROTOCOL_VERSIONS,
  systemClock,
  TrailGateError,
  validateDiscoveryDocument,
} from '@trailgate/core';
import type { HttpTransport } from './transport.ts';
import { fetchTransport } from './transport.ts';

/** Maximum discovery document size this SDK will parse (64 KiB). */
export const MAX_DISCOVERY_BODY_BYTES = 65_536;
/** Spec section 5.4: cache discovery documents at most 24 hours. */
export const MAX_DISCOVERY_CACHE_SECONDS = 86_400;

/**
 * A validated discovery result bound to one site origin. `origin` is the
 * only authority the SDK will send protocol traffic to for this site; it
 * equals `document.issuer` and every endpoint's origin (spec section 5.3).
 */
export interface SiteContext {
  /** Bare `https://host[:port]` origin. All protected traffic is pinned here. */
  readonly origin: string;
  /** Grant `iss`/`aud`: the issuer identifier, equal to `origin` in draft 0.1. */
  readonly issuer: string;
  /** Protocol version negotiated per spec section 4. */
  readonly protocolVersion: string;
  /** The validated discovery document. Still untrusted input: validate before acting on it. */
  readonly document: DiscoveryDocument;
  /** Unix seconds when the document was fetched (for cache bookkeeping). */
  readonly fetchedAt: number;
  /**
   * Seconds the document may be cached: the smaller of the spec's 24 hour
   * ceiling (section 5.4) and any `Cache-Control: max-age` the site sent.
   * Zero when the site sent `no-store`/`no-cache`.
   */
  readonly cacheMaxAgeSeconds: number;
}

export interface DiscoverOptions {
  transport?: HttpTransport;
  clock?: Clock;
  supportedProtocolVersions?: readonly string[];
  knownCriticalFields?: readonly string[];
  /** Abort document parsing above this many bytes. Defaults to 64 KiB. */
  maxBodyBytes?: number;
}

/**
 * Normalizes a user-supplied target to an `https://` origin. Any path,
 * query, or credentials in the input are discarded; discovery always reads
 * `/.well-known/trailgate` on the origin.
 */
export function originOf(target: string): string {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'site target is not a valid url');
  }
  if (url.protocol !== 'https:') {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'site target must use https');
  }
  return url.origin;
}

/**
 * `GET /.well-known/trailgate` plus spec section 5 validation: HTTPS only,
 * redirects never followed (the transport contract; a 3xx response is a
 * validation failure), schema check, same-origin endpoints, `critical`
 * handling, and version negotiation per section 4.
 */
export async function discoverSite(
  target: string,
  options: DiscoverOptions = {},
): Promise<SiteContext> {
  const origin = originOf(target);
  const transport = options.transport ?? fetchTransport();
  const clock = options.clock ?? systemClock;
  const versions = options.supportedProtocolVersions ?? SUPPORTED_PROTOCOL_VERSIONS;

  const res = await transport.send({ method: 'GET', url: `${origin}${DISCOVERY_PATH}` });
  if (res.status >= 300 && res.status < 400) {
    throw new TrailGateError(
      Codes.DISCOVERY_INVALID,
      'discovery endpoint returned a redirect; redirects are not followed',
    );
  }
  if (res.status !== 200) {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'discovery endpoint did not return 200', {
      status: res.status,
    });
  }
  const contentType = res.headers['content-type'];
  if (contentType !== undefined && !contentType.toLowerCase().includes('json')) {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'discovery document is not json', {
      contentType,
    });
  }
  const maxBody = options.maxBodyBytes ?? MAX_DISCOVERY_BODY_BYTES;
  if (res.body.length > maxBody) {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'discovery document exceeds size limit');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(res.body));
  } catch {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'discovery document is not valid json');
  }
  const document = validateDiscoveryDocument(parsed, {
    expectedOrigin: origin,
    supportedProtocolVersions: [...versions],
    ...(options.knownCriticalFields !== undefined
      ? { knownCriticalFields: options.knownCriticalFields }
      : {}),
  });
  return {
    origin,
    issuer: document.issuer,
    protocolVersion: negotiateProtocolVersion(document.protocol_versions),
    document,
    fetchedAt: clock.now(),
    cacheMaxAgeSeconds: cacheMaxAge(res.headers),
  };
}

/**
 * Caching rule per spec section 5.4: honor HTTP caching when it is shorter
 * than the 24 hour ceiling; `no-store`/`no-cache` means zero. Absent
 * headers get the full ceiling.
 */
function cacheMaxAge(headers: Record<string, string>): number {
  const value = headers['cache-control'];
  if (value === undefined) {
    return MAX_DISCOVERY_CACHE_SECONDS;
  }
  if (/\b(no-store|no-cache)\b/i.test(value)) {
    return 0;
  }
  const match = /\bmax-age=(\d+)/i.exec(value);
  if (match === null) {
    return MAX_DISCOVERY_CACHE_SECONDS;
  }
  return Math.min(MAX_DISCOVERY_CACHE_SECONDS, Number.parseInt(match[1] as string, 10));
}

/** Advertised `capabilities` member, or `{}` when absent (spec section 5.2). */
export function siteCapabilities(
  site: SiteContext,
): NonNullable<DiscoveryDocument['capabilities']> {
  return site.document.capabilities ?? {};
}

/**
 * Resolves a site signing key by `kid`. Grant and receipt `kid` values are
 * the key's SHA-256 JWK thumbprint (spec section 6.1), so the resolver maps
 * each published key's thumbprint to the JWK.
 */
export function siteKeyResolver(document: DiscoveryDocument): KeyResolver {
  const byKid = new Map<string, Jwk>();
  for (const key of document.signing_keys.keys) {
    try {
      byKid.set(jwkThumbprint(key), key);
    } catch {
      // A key without a computable thumbprint is unusable; skip it.
    }
    if (typeof key.kid === 'string' && !byKid.has(key.kid)) {
      byKid.set(key.kid, key);
    }
  }
  return { resolve: async (kid) => byKid.get(kid) };
}

/**
 * Rejects any URL outside the site origin. This is the guard that keeps
 * `fetchProtected` from being usable as an arbitrary URL-fetching tool:
 * every protected request is pinned to the discovered site origin.
 */
export function resolveSiteUrl(site: SiteContext, input: string): string {
  const url = new URL(input, site.origin);
  if (url.origin !== site.origin) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request target is outside the site origin');
  }
  return url.toString();
}
