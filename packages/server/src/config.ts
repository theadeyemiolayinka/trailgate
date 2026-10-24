import type {
  Clock,
  DiscoveryAction,
  DiscoveryCapabilities,
  NonceStore,
  ResourceOwnerResolver,
  SitePolicy,
} from '@trailgate/core';
import {
  Codes,
  MAX_CLOCK_TOLERANCE_SECONDS,
  REGISTERED_CONSTRAINT_TYPES,
  SUPPORTED_PROTOCOL_VERSIONS,
  systemClock,
  TrailGateError,
} from '@trailgate/core';
import {
  createInMemoryAgentKeyDirectory,
  createInMemoryApprovalStore,
  createInMemoryAuditSink,
  createInMemoryGrantRegistry,
  createInMemoryGrantRequestStore,
  createInMemoryIdempotencyStore,
  createInMemoryLedger,
  createInMemoryNonceStore,
  createInMemoryRateLimiter,
} from './memory.ts';
import type {
  AgentKeyDirectory,
  AuditSink,
  GrantRegistry,
  GrantRequestStore,
  RequestApprovalStore,
  RequestIdempotencyStore,
  RequestRateLimiter,
  ResourceScopePolicy,
  RevocationAuthorizer,
  SpendingLedger,
} from './ports.ts';
import type { SiteSigningKey, SiteSigningKeyInput } from './signing.ts';
import { assertSigningKeysPresent, siteSigningKey } from './signing.ts';
import type { EffectiveScope, RequestedScope } from './types.ts';

export const DEFAULT_GRANT_REQUEST_TTL_SECONDS = 900;
export const DEFAULT_GRANT_LIFETIME_SECONDS = 3600;
export const DEFAULT_RESERVATION_TTL_SECONDS = 300;
export const DEFAULT_REQUEST_APPROVAL_TTL_SECONDS = 600;
export const DEFAULT_MAX_BODY_BYTES = 65_536;
export const DEFAULT_MAX_HEADERS_BYTES = 16_384;

/** Storage and accounting adapters backing the SDK. All default to in-memory. */
export interface ServerStores {
  grantRequests: GrantRequestStore;
  agentKeys: AgentKeyDirectory;
  grants: GrantRegistry;
  nonces: NonceStore;
  idempotency: RequestIdempotencyStore;
  ledger: SpendingLedger;
  rateLimiter: RequestRateLimiter;
  audit: AuditSink;
  approvals: RequestApprovalStore;
}

/**
 * Narrows (never widens) a requested scope at grant-request intake. The
 * returned effective scope is what consent displays and the grant carries.
 * The SDK enforces that effective permissions and resources are subsets of
 * the requested sets; sites MUST NOT loosen constraint params
 * (spec section 9.3).
 */
export type ScopeRefiner = (requested: RequestedScope) => Promise<EffectiveScope> | EffectiveScope;

export interface TrailGateServerOptions {
  /**
   * The site's origin (`https://host[:port]`). Used as the grant `iss`, the
   * grant/receipt `aud`, and the discovery `issuer`. Must equal the origin
   * the discovery document is served from (spec section 5.3).
   */
  issuer: string;
  /** Private signing keys for grants and receipts; public halves are published in discovery. */
  signingKeys: SiteSigningKeyInput[];
  /** Permission identifiers this site honors (`tg.<domain>.<action>`), advertised in discovery. */
  permissions: readonly string[];
  /** Constraint types this site evaluates; defaults to all registered types. */
  constraintTypes?: readonly string[];
  /**
   * Protocol versions this deployment serves; advertised in discovery and
   * enforced at grant-request intake and request verification. Must be a
   * subset of the versions this SDK implements. Defaults to `["0.1"]`.
   */
  protocolVersions?: readonly string[];
  /** Endpoint paths relative to `issuer`. Defaults shown in the integration guide. */
  paths?: Partial<{
    grantRequest: string;
    grantRedemption: string;
    grantStatus: string;
    grantRevocation: string;
    consent: string;
    /** Human-facing path for `approval_threshold` per-request decisions. */
    requestApproval: string;
  }>;
  /** Discovery `capabilities` members to advertise. */
  capabilities?: DiscoveryCapabilities;
  /** Extra discovery members merged into the document (extensions are ignored by agents). */
  discoveryExtensions?: Record<string, unknown>;
  stores?: Partial<ServerStores>;
  /**
   * Maps the host's authenticated user identifier to the grant's `sub`
   * (a pseudonymous user-context identifier, spec section 6.2). The result is
   * what `ResourceOwnerResolver.ownerOf` results are compared against, so it
   * must live in the same namespace. Defaults to identity.
   */
  subjectFor?: (siteUserId: string) => string;
  /** Site rules applied after every protocol check passes (stage 13). Throw `tg.authorization.denied` to deny. */
  policy?: SitePolicy;
  /** Resolves a resource selector to its owning user context for cross-user isolation checks. */
  resourceOwners?: ResourceOwnerResolver;
  /** Host check that requested resource selectors are inside the site's namespace. */
  resourcePolicy?: ResourceScopePolicy;
  /** Optional scope narrowing applied at grant-request intake. */
  refineScope?: ScopeRefiner;
  /**
   * Optional binding of templated resource selectors at consent approval
   * (spec section 8). Called only when the decision is `approve`, with the
   * grant's `sub`. Use it to resolve placeholders such as `cart:{user}` to
   * the subject's concrete selector (for example `cart:cart_usr_1`). The
   * result MUST derive from the requested selectors: a concrete requested
   * selector may only reappear verbatim, and a requested template may only
   * produce selectors matching its static prefix and suffix. Violations
   * raise `tg.internal.error` and the request is not approved.
   */
  bindSubjectResources?: (
    resources: readonly string[],
    subject: string,
  ) => readonly string[] | Promise<readonly string[]>;
  /**
   * Authorizes callers of the provisional revocation endpoint.
   * @provisional The endpoint body and caller model are not yet specified in draft 0.1.
   */
  revocationAuthorizer?: RevocationAuthorizer;
  clock?: Clock;
  /** Signature clock tolerance; must not exceed 120 (spec section 11.2). */
  toleranceSeconds?: number;
  /** Grant-request lifetime; must not exceed 900 (spec section 10.2). */
  grantRequestTtlSeconds?: number;
  /** Grant lifetime used when the agent does not request one. */
  defaultGrantSeconds?: number;
  /** Ceiling on grant lifetime, advertised as `capabilities.max_grant_seconds`. */
  maxGrantSeconds?: number;
  /** Reservation TTL; recommended 300 (spec section 12). */
  reservationTtlSeconds?: number;
  /** Per-request approval record TTL; how long a pending or approved decision stays valid. */
  requestApprovalTtlSeconds?: number;
  /**
   * Maximum protected-request body bytes accepted before denial with
   * `tg.request.too_large` (spec section 17). Default 64 KiB.
   */
  maxBodyBytes?: number;
  /** Maximum total header name+value bytes. Default 16 KiB. */
  maxHeadersBytes?: number;
  /**
   * Maximum grant requests a single agent key may have open at once;
   * excess is denied with `tg.request.rate_limited`. Default 5.
   */
  maxPendingRequestsPerAgent?: number;
  /**
   * Maximum grant requests a single agent key may create per rolling
   * 60-second window; excess is denied with `tg.request.rate_limited`.
   * Default 10.
   */
  maxGrantRequestsPerMinute?: number;
}

export interface ResolvedServerConfig {
  issuer: string;
  audience: string;
  /** The key used to sign grants and receipts; the first configured key. */
  signingKey: SiteSigningKey;
  signingKeys: SiteSigningKey[];
  permissions: readonly string[];
  constraintTypes: readonly string[];
  paths: {
    grantRequest: string;
    grantRedemption: string;
    grantStatus: string;
    grantRevocation: string;
    consent: string;
    requestApproval: string;
  };
  capabilities: DiscoveryCapabilities;
  discoveryExtensions: Record<string, unknown>;
  /**
   * Action catalog assembled from `RouteProtection.action` declarations as
   * routes are wrapped with `protect()`; published in discovery `actions`.
   */
  actions: Map<string, DiscoveryAction>;
  stores: ServerStores;
  subjectFor: (siteUserId: string) => string;
  policy?: SitePolicy;
  resourceOwners?: ResourceOwnerResolver;
  resourcePolicy?: ResourceScopePolicy;
  refineScope?: ScopeRefiner;
  bindSubjectResources?: (
    resources: readonly string[],
    subject: string,
  ) => readonly string[] | Promise<readonly string[]>;
  revocationAuthorizer?: RevocationAuthorizer;
  clock: Clock;
  toleranceSeconds: number;
  grantRequestTtlSeconds: number;
  defaultGrantSeconds: number;
  maxGrantSeconds?: number;
  reservationTtlSeconds: number;
  requestApprovalTtlSeconds: number;
  maxBodyBytes: number;
  maxHeadersBytes: number;
  maxPendingRequestsPerAgent: number;
  maxGrantRequestsPerMinute: number;
  supportedProtocolVersions: readonly string[];
}

const DEFAULT_PATHS = {
  grantRequest: '/tg/grant-request',
  grantRedemption: '/tg/grant-redemption',
  grantStatus: '/tg/grant-status',
  grantRevocation: '/tg/grant-revocation',
  consent: '/tg/consent',
  requestApproval: '/tg/request-approval',
};

export function resolveConfig(options: TrailGateServerOptions): ResolvedServerConfig {
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(options.issuer);
  } catch {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'issuer is not a valid url');
  }
  if (issuerUrl.protocol !== 'https:' || issuerUrl.pathname !== '/' || issuerUrl.search !== '') {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'issuer must be a bare https origin (scheme, host, optional port)',
    );
  }
  const issuer = issuerUrl.origin;

  const signingKeys = options.signingKeys.map(siteSigningKey);
  assertSigningKeysPresent(signingKeys);

  const tolerance = options.toleranceSeconds ?? 60;
  if (tolerance > MAX_CLOCK_TOLERANCE_SECONDS || tolerance < 0) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'toleranceSeconds must be between 0 and the spec maximum of 120',
    );
  }
  const grantRequestTtl = options.grantRequestTtlSeconds ?? DEFAULT_GRANT_REQUEST_TTL_SECONDS;
  if (grantRequestTtl > DEFAULT_GRANT_REQUEST_TTL_SECONDS || grantRequestTtl < 1) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'grantRequestTtlSeconds must be between 1 and the spec maximum of 900',
    );
  }

  const protocolVersions = options.protocolVersions ?? SUPPORTED_PROTOCOL_VERSIONS;
  if (
    protocolVersions.length === 0 ||
    protocolVersions.some((v) => !(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(v))
  ) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'protocolVersions must be a non-empty subset of the versions this SDK implements',
    );
  }

  const paths = { ...DEFAULT_PATHS, ...(options.paths ?? {}) };
  for (const [name, path] of Object.entries(paths)) {
    if (!path.startsWith('/') || path.includes('://') || path.includes(' ')) {
      throw new TrailGateError(
        Codes.INTERNAL_ERROR,
        `paths.${name} must be a path on the issuer origin (start with /)`,
      );
    }
  }

  const clock = options.clock ?? systemClock;
  const stores: ServerStores = {
    grantRequests: options.stores?.grantRequests ?? createInMemoryGrantRequestStore(),
    agentKeys: options.stores?.agentKeys ?? createInMemoryAgentKeyDirectory(),
    grants: options.stores?.grants ?? createInMemoryGrantRegistry(),
    nonces: options.stores?.nonces ?? createInMemoryNonceStore(),
    idempotency: options.stores?.idempotency ?? createInMemoryIdempotencyStore(),
    ledger: options.stores?.ledger ?? createInMemoryLedger(clock.now),
    rateLimiter: options.stores?.rateLimiter ?? createInMemoryRateLimiter(),
    audit: options.stores?.audit ?? createInMemoryAuditSink(),
    approvals: options.stores?.approvals ?? createInMemoryApprovalStore(),
  };

  const capabilities: DiscoveryCapabilities = { ...(options.capabilities ?? {}) };
  if (options.maxGrantSeconds !== undefined) {
    capabilities.max_grant_seconds = options.maxGrantSeconds;
  }

  const config: ResolvedServerConfig = {
    issuer,
    audience: issuer,
    signingKey: signingKeys[0] as SiteSigningKey,
    signingKeys,
    permissions: options.permissions,
    constraintTypes: options.constraintTypes ?? REGISTERED_CONSTRAINT_TYPES,
    paths,
    capabilities,
    discoveryExtensions: options.discoveryExtensions ?? {},
    actions: new Map(),
    stores,
    subjectFor: options.subjectFor ?? ((siteUserId) => siteUserId),
    clock,
    toleranceSeconds: tolerance,
    grantRequestTtlSeconds: grantRequestTtl,
    defaultGrantSeconds: options.defaultGrantSeconds ?? DEFAULT_GRANT_LIFETIME_SECONDS,
    reservationTtlSeconds: options.reservationTtlSeconds ?? DEFAULT_RESERVATION_TTL_SECONDS,
    requestApprovalTtlSeconds:
      options.requestApprovalTtlSeconds ?? DEFAULT_REQUEST_APPROVAL_TTL_SECONDS,
    maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    maxHeadersBytes: options.maxHeadersBytes ?? DEFAULT_MAX_HEADERS_BYTES,
    maxPendingRequestsPerAgent: options.maxPendingRequestsPerAgent ?? 5,
    maxGrantRequestsPerMinute: options.maxGrantRequestsPerMinute ?? 10,
    supportedProtocolVersions: protocolVersions,
    ...(options.policy !== undefined ? { policy: options.policy } : {}),
    ...(options.resourceOwners !== undefined ? { resourceOwners: options.resourceOwners } : {}),
    ...(options.resourcePolicy !== undefined ? { resourcePolicy: options.resourcePolicy } : {}),
    ...(options.bindSubjectResources !== undefined
      ? { bindSubjectResources: options.bindSubjectResources }
      : {}),
    ...(options.refineScope !== undefined ? { refineScope: options.refineScope } : {}),
    ...(options.revocationAuthorizer !== undefined
      ? { revocationAuthorizer: options.revocationAuthorizer }
      : {}),
    ...(options.maxGrantSeconds !== undefined ? { maxGrantSeconds: options.maxGrantSeconds } : {}),
  };
  return config;
}
