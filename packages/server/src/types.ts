import type { Constraint, GrantPayload, Money, VerifiedRequestContext } from '@trailgate/core';

/**
 * Framework-neutral HTTP request the SDK operates on. The host application
 * adapts its framework's request object into this shape.
 *
 * `url` is the absolute request URI exactly as received (scheme, authority,
 * path, raw query). The request signature covers `@method`, `@authority`,
 * `@path`, and `@query`, so reconstructing a different string than the client
 * signed produces a signature failure.
 *
 * `headers` uses lowercased field names. `body` is the exact received body
 * bytes; `Content-Digest` verification fails on any re-encoding.
 */
export interface HostRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array | string;
}

/**
 * Framework-neutral HTTP response produced by SDK handlers and by host
 * handlers running under `protect`. `body` is JSON-serialized by the host.
 */
export interface HostResponse {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
}

/** Requested scope, verbatim from the stored grant request (spec section 10.3). */
export interface RequestedScope {
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  requestedSeconds?: number;
}

/** Effective scope the site will actually issue. May be narrower than requested, never wider. */
export interface EffectiveScope {
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  lifetimeSeconds: number;
}

/**
 * The terms a consent page renders (spec section 10.3). `requested` is the
 * verbatim agent request; `effective` is what the grant will carry after the
 * site's scope refinement. Sites MUST NOT alter the terms at render time and
 * MUST show the effective values.
 */
export interface ConsentView {
  requestId: string;
  agentJkt: string;
  expiresAt: number;
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'issued';
  requested: RequestedScope;
  effective: EffectiveScope;
  redirectUri?: string;
}

export type ConsentDecision = 'approve' | 'deny';

export interface ConsentOutcome {
  requestId: string;
  decision: 'approved' | 'denied';
  /**
   * Set when the grant request registered a `redirect_uri`: the exact target
   * the host's consent endpoint should 302 to (spec section 10.3). Absent
   * when the agent polls `grant_status` instead.
   */
  redirectTo?: string;
}

/** Grant-status response body (spec section 10.5). */
export type GrantStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'active' | 'revoked';

export interface GrantStatusResponse {
  status: GrantStatus;
  issued_at?: number;
  expires_at?: number;
}

/**
 * Per-route protection declaration. `permission` is the `tg.*` identifier the
 * grant must carry. `resource` is the selector this request touches
 * (spec section 8). `amount` is the metered amount this request will spend,
 * in integer units (spec section 3: ISO 4217 for money, site-defined codes
 * for other meters), used for `max_amount`/`cumulative_budget`
 * evaluation and the reservation lifecycle (spec sections 9 and 12).
 */
/**
 * Advertisement of this route in the discovery document's `actions` catalog
 * (spec section 5.2). The SDK derives `permission` and `mutates` from the
 * same `RouteProtection` that drives enforcement, so the advertisement can
 * never drift from what the pipeline actually requires.
 */
export interface ActionAdvertisement {
  /** Stable action identifier, unique within the site's catalog. */
  id: string;
  /** Uppercase HTTP method of the protected route. */
  method: string;
  /** Absolute path template; `{name}` marks a path parameter. */
  path: string;
  /**
   * Short statement of what the action does, for humans and models.
   * Required: it is the primary signal an agent uses to match intent.
   */
  description: string;
  /** Resource selector template, e.g. `cart:{user}`; names structure, never data. */
  resource?: string;
  /** When true, the action may charge money and spend constraints apply. */
  spend?: boolean;
}

/**
 * Verified context handed to `resource` and `amount` resolvers. Populated
 * from the verified grant payload inside the enforcement pipeline, so
 * resolvers derive selectors and amounts from claims the pipeline already
 * authenticated rather than re-parsing the raw `trailgate-grant` header.
 */
export interface SelectorContext {
  /** `sub` of the verified grant; undefined when the grant carries none. */
  subject?: string;
  /** The verified grant payload. */
  grant: GrantPayload;
}

export interface RouteProtection {
  permission: string;
  resource?: string | ((req: HostRequest, ctx: SelectorContext) => string | undefined);
  amount?: Money | ((req: HostRequest, ctx: SelectorContext) => Money | undefined);
  /**
   * Whether this endpoint stores an idempotency record (spec section 11.4).
   * Mutating endpoints MUST set or leave this at the default `true`. Read-only
   * endpoints may set `false` to skip dedupe storage.
   */
  mutating?: boolean;
  /** When set, the route is advertised in discovery `actions`. */
  action?: ActionAdvertisement;
}

/** Request context passed to the host handler after a request verifies. */
export interface EnforcementContext extends VerifiedRequestContext {
  grant: GrantPayload;
}

/** Host business logic executed after the grant and its constraints pass. */
export type ProtectedHandler = (
  req: HostRequest,
  ctx: EnforcementContext,
) => Promise<HostResponse> | HostResponse;
