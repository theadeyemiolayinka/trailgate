import { createHash, randomBytes } from 'node:crypto';
import type { Constraint, GrantRequestBody } from '@trailgate/core';
import { base64urlEncode, Codes, TrailGateError } from '@trailgate/core';
import type { SiteContext } from './discovery.ts';
import { errorFromResponse, parseJsonBytes } from './errors.ts';
import type { AgentSigner } from './keys.ts';
import type { HttpTransport } from './transport.ts';

/** Scope the agent asks the user to approve (spec section 10.2). */
export interface GrantScope {
  permissions: string[];
  resources?: string[];
  constraints?: Constraint[];
  requestedSeconds?: number;
}

export interface GrantRequestOptions extends GrantScope {
  /** Exact HTTPS URI for the post-consent redirect (spec section 10.3). */
  redirectUri?: string;
  /** Opaque agent state echoed back on the redirect. */
  state?: string;
}

/**
 * What the agent runtime and the user-facing surface see after a grant
 * request is accepted. The `code_verifier` is intentionally absent: it is
 * held inside the client until redemption and is not part of this shape.
 */
export interface ConsentSession {
  requestId: string;
  consentUrl: string;
  expiresAt: number;
  redirectUri?: string;
  state?: string;
}

/** Internal pending-request record; never returned to callers as-is. */
export interface PendingGrantRequest extends ConsentSession {
  siteOrigin: string;
  keyId: string;
  codeVerifier: string;
}

/** Generates a PKCE code verifier: 32 random bytes, base64url (RFC 7636). */
export function generateCodeVerifier(): string {
  return base64urlEncode(randomBytes(32));
}

/** S256 challenge: `BASE64URL(SHA256(verifier))` (spec section 10.2). */
export function codeChallengeFor(verifier: string): string {
  return base64urlEncode(createHash('sha256').update(verifier, 'utf8').digest());
}

/**
 * Builds the `grant_request` POST body (spec section 10.2,
 * `grant-request.schema.json`). `agent_key` carries the public JWK only.
 */
export function buildGrantRequestBody(
  protocolVersion: string,
  scope: GrantRequestOptions,
  signer: AgentSigner,
  codeVerifier: string,
): GrantRequestBody {
  const body: GrantRequestBody = {
    version: protocolVersion,
    permissions: [...scope.permissions],
    resources: [...(scope.resources ?? [])],
    constraints: [...(scope.constraints ?? [])],
    agent_key: signer.publicJwk,
    code_challenge: codeChallengeFor(codeVerifier),
    code_challenge_method: 'S256',
  };
  if (scope.redirectUri !== undefined) {
    body.redirect_uri = scope.redirectUri;
  }
  if (scope.state !== undefined) {
    body.state = scope.state;
  }
  if (scope.requestedSeconds !== undefined) {
    body.requested_seconds = scope.requestedSeconds;
  }
  return body;
}

function requireResponseString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} missing in site response`);
  }
  return value;
}

function requireResponseInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} missing in site response`);
  }
  return value;
}

/**
 * `POST <endpoints.grant_request>` (spec section 10.2). Validates the 201
 * response shape and enforces that `consent_url` stays on the site origin
 * (section 10.3); anything else is rejected as malformed.
 */
export async function submitGrantRequest(
  site: SiteContext,
  body: GrantRequestBody,
  transport: HttpTransport,
): Promise<ConsentSession> {
  const res = await transport.send({
    method: 'POST',
    url: site.document.endpoints.grant_request,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(JSON.stringify(body)),
  });
  if (res.status !== 201) {
    throw errorFromResponse(res.status, res.body);
  }
  const parsed = parseJsonBytes(res.body);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'grant request response is not an object');
  }
  const record = parsed as Record<string, unknown>;
  const requestId = requireResponseString(record.request_id, 'request_id');
  const consentUrl = requireResponseString(record.consent_url, 'consent_url');
  const expiresAt = requireResponseInteger(record.expires_at, 'expires_at');
  let consent: URL;
  try {
    consent = new URL(consentUrl);
  } catch {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'consent_url is not a valid url');
  }
  if (consent.origin !== site.origin) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'consent_url is outside the site origin');
  }
  const session: ConsentSession = { requestId, consentUrl, expiresAt };
  if (body.redirect_uri !== undefined) {
    session.redirectUri = body.redirect_uri;
  }
  if (body.state !== undefined) {
    session.state = body.state;
  }
  return session;
}

export interface RedeemGrantResult {
  /** The compact JWS grant, verified and stored by the caller. */
  grant: string;
}

/**
 * `POST <endpoints.grant_redemption>` (spec section 10.4). The site checks
 * the S256 challenge, the single-use rule, and approval state; error codes
 * (`tg.grant.redeemed`, `tg.grant.consent_denied`, `tg.grant.expired`,
 * `tg.authorization.denied`) propagate as `TrailGateError`s.
 */
export async function redeemGrantRequest(
  site: SiteContext,
  requestId: string,
  codeVerifier: string,
  transport: HttpTransport,
): Promise<RedeemGrantResult> {
  const res = await transport.send({
    method: 'POST',
    url: site.document.endpoints.grant_redemption,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(
      JSON.stringify({ request_id: requestId, code_verifier: codeVerifier }),
    ),
  });
  if (res.status !== 200) {
    throw errorFromResponse(res.status, res.body);
  }
  const parsed = parseJsonBytes(res.body);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'redemption response is not an object');
  }
  const grant = requireResponseString((parsed as Record<string, unknown>).grant, 'grant');
  return { grant };
}

export type GrantRequestStatus =
  | 'pending'
  | 'approved'
  | 'denied'
  | 'expired'
  | 'active'
  | 'revoked';

const KNOWN_STATUSES: readonly string[] = [
  'pending',
  'approved',
  'denied',
  'expired',
  'active',
  'revoked',
];

export interface GrantStatusResponse {
  status: GrantRequestStatus;
  issued_at?: number;
  expires_at?: number;
  /**
   * The site's current effective scope for the grant (grant_id lookups).
   * Reflects post-issuance scope changes the user or site made; advisory
   * like the rest of status — enforcement remains authoritative.
   */
  permissions?: string[];
  resources?: string[];
}

/**
 * `GET <endpoints.grant_status>?request_id=|grant_id=` (spec section 10.5).
 * Status responses are informational only in draft 0.1: they are unsigned,
 * may be cached up to 60 seconds by the site, and MUST NOT be treated as
 * proof of authorization. Enforcement-time checks are authoritative.
 */
export async function fetchGrantStatus(
  site: SiteContext,
  query: { requestId?: string; grantId?: string },
  transport: HttpTransport,
): Promise<GrantStatusResponse> {
  const url = new URL(site.document.endpoints.grant_status);
  if (query.requestId !== undefined) {
    url.searchParams.set('request_id', query.requestId);
  }
  if (query.grantId !== undefined) {
    url.searchParams.set('grant_id', query.grantId);
  }
  if (query.requestId === undefined && query.grantId === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'requestId or grantId is required');
  }
  const res = await transport.send({ method: 'GET', url: url.toString() });
  if (res.status !== 200) {
    throw errorFromResponse(res.status, res.body);
  }
  const parsed = parseJsonBytes(res.body);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'status response is not an object');
  }
  const record = parsed as Record<string, unknown>;
  const status = record.status;
  if (typeof status !== 'string' || !KNOWN_STATUSES.includes(status)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'status response has unknown status', {
      status,
    });
  }
  const out: GrantStatusResponse = { status: status as GrantRequestStatus };
  for (const name of ['issued_at', 'expires_at'] as const) {
    const value = record[name];
    if (value !== undefined) {
      if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} is not an integer`);
      }
      out[name] = value;
    }
  }
  for (const name of ['permissions', 'resources'] as const) {
    const value = record[name];
    if (value !== undefined) {
      if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
        throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} is not a string array`);
      }
      out[name] = value;
    }
  }
  return out;
}

export interface PollApprovalOptions {
  /** Interval between status polls. Default 2000 ms. */
  intervalMs?: number;
  /** Overall timeout. Default: the request's own `expires_at`. */
  timeoutMs?: number;
  /** Injectable sleep for tests. */
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Polls `grant_status` until the request leaves `pending` (spec section
 * 10.5). Resolves on `approved`; throws `tg.grant.consent_denied` on
 * `denied`, `tg.grant.expired` on `expired` or timeout. Used when no
 * `redirect_uri` was registered; redirect-mode callers use
 * `validateConsentCallback` then `redeemGrant` instead.
 */
export async function awaitConsentDecision(
  site: SiteContext,
  requestId: string,
  transport: HttpTransport,
  options: PollApprovalOptions = {},
): Promise<void> {
  const interval = options.intervalMs ?? 2000;
  const sleep = options.sleep ?? defaultSleep;
  const started = Date.now();
  const deadline = options.timeoutMs !== undefined ? started + options.timeoutMs : undefined;
  for (;;) {
    const status = await fetchGrantStatus(site, { requestId }, transport);
    if (status.status === 'approved' || status.status === 'active') {
      // 'active' means the request was already redeemed elsewhere; the
      // subsequent redemption surfaces tg.grant.redeemed as specified.
      return;
    }
    if (status.status === 'denied') {
      throw new TrailGateError(Codes.GRANT_CONSENT_DENIED, 'consent was denied');
    }
    if (status.status === 'expired') {
      throw new TrailGateError(Codes.GRANT_EXPIRED, 'grant request expired before approval');
    }
    if (deadline !== undefined && Date.now() >= deadline) {
      throw new TrailGateError(Codes.GRANT_EXPIRED, 'timed out waiting for consent');
    }
    await sleep(interval);
  }
}
