import { createHash } from 'node:crypto';
import { evaluateConstraints, requireApprovalPermissions } from './constraints.ts';
import { requestDigestOf, verifyContentDigest } from './digest.ts';
import { Codes, TrailGateError } from './errors.ts';
import { verifyGrant } from './grant.ts';
import { signatureAlgorithmFor } from './jwk.ts';
import { assertPermissionGranted } from './permissions.ts';
import type {
  Clock,
  GrantScopeChecker,
  IdempotencyStore,
  KeyResolver,
  Ledger,
  NonceStore,
  RateLimiter,
  ResourceOwnerResolver,
  RevocationChecker,
  SitePolicy,
  VerifiedRequestContext,
} from './ports.ts';
import { callPort, type RequestApprovalChecker, systemClock } from './ports.ts';
import { assertResourceAllowed } from './resources.ts';
import {
  buildSignatureBase,
  checkNonceShape,
  checkSignatureWindow,
  getHeader,
  getSignatureBytes,
  MAX_CLOCK_TOLERANCE_SECONDS,
  MAX_SIGNATURE_WINDOW_SECONDS,
  parseTgSignatureInput,
  publicKeyFromJwk,
  verifySignatureBytes,
} from './signature.ts';
import type { GrantPayload, Money } from './types.ts';

export interface ProtectedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array | string;
}

export interface RequestVerificationDeps {
  issuer: string;
  audience: string;
  resolveSiteKey: KeyResolver;
  resolveAgentKey: KeyResolver;
  revocation: RevocationChecker;
  nonceStore: NonceStore;
  clock?: Clock;
  idempotency?: IdempotencyStore;
  ledger?: Ledger;
  rateLimiter?: RateLimiter;
  approvals?: RequestApprovalChecker;
  resourceOwners?: ResourceOwnerResolver;
  policy?: SitePolicy;
  toleranceSeconds?: number;
  supportedProtocolVersions?: readonly string[];
  permissionVocabulary?: readonly string[];
  /**
   * Optional post-issuance scope hook. When present, it is consulted at
   * every request for the site's current effective scope for a grant, so
   * the site can tighten a grant after issuance (spec section 13). The
   * result is intersected with the signed grant: it can only narrow, never
   * widen what the grant JWT carries.
   */
  grantScope?: GrantScopeChecker;
  knownCriticalFields?: readonly string[];
  requiredPermission?: string;
  requestAmount?: Money;
  /**
   * Resolves the request amount from the verified grant, evaluated after
   * grant verification. Takes precedence over a static `requestAmount`.
   */
  resolveRequestAmount?: (grant: GrantPayload) => Money | undefined;
  touchedResource?: string;
  /**
   * Resolves the touched resource selector from the verified grant, so host
   * resolvers derive selectors from verified claims rather than re-parsing
   * the raw `trailgate-grant` header. Takes precedence over a static
   * `touchedResource`.
   */
  resolveTouchedResource?: (grant: GrantPayload) => string | undefined;
  /**
   * Set when the request is being queued through the pending-action flow
   * (spec section 12.5) or executed from an approved pending action. The
   * queued human decision covers `approval_threshold`, so those constraints
   * are treated as satisfied.
   */
  skipApprovalThreshold?: boolean;
}

export interface RequestVerificationResult {
  grant: GrantPayload;
  requestDigest: string;
  /**
   * SHA-256 operation digest of (method, url, content-digest, grant jti):
   * the identity an approved pending action must still produce when its
   * stored proposal is replayed (spec sections 11.4, 12.5).
   */
  operationDigest: string;
  signatureBase: string;
  idempotentReplay: boolean;
  context: VerifiedRequestContext;
  /** The amount the request was evaluated against, when the route declared one. */
  requestAmount?: Money;
  /** The resource selector the request was checked against, when resolved. */
  touchedResource?: string;
  /**
   * Set when the site policy returned 'require_approval': the request may
   * be submitted as a pending action but must not execute before a human
   * decision (spec section 12.5).
   */
  policyDecision?: 'require_approval';
}

const REQUIRED_HEADERS = [
  'trailgate-grant',
  'signature-input',
  'signature',
  'content-digest',
  'idempotency-key',
];

function bodyBytes(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) {
    return new Uint8Array();
  }
  if (typeof body === 'string') {
    return new TextEncoder().encode(body);
  }
  return body;
}

/**
 * Idempotency operation digest per spec section 11.4 / ADR 0008: method,
 * target URI, `Content-Digest` header value, and grant `jti`. Exported so
 * callers that store idempotency outcomes compute the identical digest the
 * verification pipeline compares against.
 */
export function operationDigestOf(req: ProtectedRequest, grantId: string): string {
  return createHash('sha256')
    .update(
      `${req.method.toUpperCase()} ${req.url} ${getHeader(req, 'content-digest')} ${grantId}`,
      'utf8',
    )
    .digest('base64url');
}

export async function verifyProtectedRequest(
  req: ProtectedRequest,
  deps: RequestVerificationDeps,
): Promise<RequestVerificationResult> {
  const clock = deps.clock ?? systemClock;
  const tolerance = deps.toleranceSeconds ?? 60;
  if (tolerance > MAX_CLOCK_TOLERANCE_SECONDS) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'clock tolerance exceeds the allowed maximum');
  }

  for (const name of REQUIRED_HEADERS) {
    if (getHeader(req, name) === undefined) {
      throw new TrailGateError(Codes.REQUEST_MALFORMED, `missing required header: ${name}`);
    }
  }

  const body = bodyBytes(req.body);
  verifyContentDigest(getHeader(req, 'content-digest'), body);

  const signatureInput = parseTgSignatureInput(getHeader(req, 'signature-input') as string);
  checkNonceShape(signatureInput.params.nonce);
  checkSignatureWindow(
    signatureInput.params.created,
    signatureInput.params.expires,
    clock.now(),
    tolerance,
  );

  const grantToken = getHeader(req, 'trailgate-grant') as string;
  const grant = await verifyGrant(grantToken, {
    resolveSiteKey: deps.resolveSiteKey,
    issuer: deps.issuer,
    audience: deps.audience,
    now: clock.now(),
    ...(deps.knownCriticalFields !== undefined
      ? { knownCriticalFields: deps.knownCriticalFields }
      : {}),
  });

  const supported = deps.supportedProtocolVersions ?? ['0.1'];
  if (!supported.includes(grant.tg.version)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'unsupported grant protocol version');
  }

  if (deps.permissionVocabulary !== undefined) {
    const vocabulary = new Set(deps.permissionVocabulary);
    const unknown = grant.tg.permissions.filter((permission) => !vocabulary.has(permission));
    if (unknown.length > 0) {
      throw new TrailGateError(
        Codes.GRANT_MALFORMED,
        'grant carries permissions outside the site vocabulary',
        { unknown },
      );
    }
  }

  const revoked = await callPort(
    () => deps.revocation.isRevoked(grant.jti),
    'revocation state is unavailable',
  );
  if (revoked) {
    throw new TrailGateError(Codes.GRANT_REVOKED, 'grant is revoked');
  }

  // Post-issuance scope: the site's stored effective scope replaces the
  // signed set when present. Only the site can write it; the JWT remains
  // evidence of the original consent and the key binding.
  let effectivePermissions = grant.tg.permissions;
  let effectiveResources = grant.tg.resources;
  let effectiveConstraints = grant.tg.constraints;
  if (deps.grantScope !== undefined) {
    const scope = await callPort(
      () => deps.grantScope?.currentScope(grant.jti) ?? Promise.resolve(undefined),
      'grant scope state is unavailable',
    );
    if (scope?.permissions !== undefined) {
      effectivePermissions = [...scope.permissions];
    }
    if (scope?.resources !== undefined) {
      effectiveResources = [...scope.resources];
    }
    if (scope?.constraints !== undefined) {
      effectiveConstraints = [...scope.constraints];
    }
  }

  if (signatureInput.params.keyid !== grant.cnf.jkt) {
    throw new TrailGateError(
      Codes.REQUEST_KEY_MISMATCH,
      'signature keyid does not match grant key binding',
    );
  }
  const agentJwk = await callPort(
    () => deps.resolveAgentKey.resolve(grant.cnf.jkt),
    'agent key resolution is unavailable',
  );
  if (agentJwk === undefined) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, 'agent key is unresolvable');
  }
  const agentAlg = signatureAlgorithmFor(agentJwk);
  if (agentAlg === undefined || agentAlg !== signatureInput.params.alg) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      'signature algorithm does not match the agent key',
    );
  }
  const signatureBase = buildSignatureBase(req, signatureInput.components, signatureInput.entry);
  const signatureBytes = getSignatureBytes(getHeader(req, 'signature') as string);
  const signatureOk = verifySignatureBytes(
    signatureInput.params.alg,
    publicKeyFromJwk(agentJwk),
    signatureBytes,
    signatureBase,
  );
  if (!signatureOk) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, 'signature verification failed');
  }

  const signatureWindowTtl = MAX_SIGNATURE_WINDOW_SECONDS + tolerance;
  const nonceIsFresh = await callPort(
    () => deps.nonceStore.claim(grant.jti, signatureInput.params.nonce, signatureWindowTtl),
    'nonce store is unavailable',
  );
  if (!nonceIsFresh) {
    throw new TrailGateError(Codes.REQUEST_REPLAY_DETECTED, 'nonce already seen for this grant');
  }

  const requestDigest = requestDigestOf(signatureBase);
  const operationDigest = operationDigestOf(req, grant.jti);
  let idempotentReplay = false;
  const idempotencyKey = getHeader(req, 'idempotency-key');
  const idempotencyStore = deps.idempotency;
  if (idempotencyStore !== undefined && idempotencyKey !== undefined) {
    const record = await callPort(
      () => idempotencyStore.lookup(grant.jti, idempotencyKey),
      'idempotency store is unavailable',
    );
    if (record !== undefined) {
      if (record.requestDigest !== operationDigest) {
        throw new TrailGateError(
          Codes.REQUEST_IDEMPOTENCY_CONFLICT,
          'idempotency-key reused with a different request',
        );
      }
      idempotentReplay = true;
    }
  }

  if (deps.requiredPermission !== undefined) {
    assertPermissionGranted(effectivePermissions, deps.requiredPermission);
  }

  const touchedResource = deps.resolveTouchedResource?.(grant) ?? deps.touchedResource;
  if (touchedResource !== undefined) {
    if (deps.resourceOwners === undefined) {
      throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'resource ownership cannot be checked');
    }
    await assertResourceAllowed(
      effectiveResources,
      touchedResource,
      deps.resourceOwners,
      grant.sub,
    );
  }

  // Per-permission tri-state (spec section 9): a `require_approval`
  // constraint naming the required permission queues the operation for a
  // human decision instead of executing. The queued approval covers
  // `approval_threshold` for this request as well, so the threshold check
  // is skipped the same way an approval-required route skips it.
  const permissionRequiresApproval =
    deps.requiredPermission !== undefined &&
    effectiveConstraints.some((c) =>
      requireApprovalPermissions(c).includes(deps.requiredPermission as string),
    );

  const requestAmount = deps.resolveRequestAmount?.(grant) ?? deps.requestAmount;
  await evaluateConstraints(effectiveConstraints, {
    grantId: grant.jti,
    now: clock.now(),
    operationDigest,
    idempotentReplay,
    ...(deps.skipApprovalThreshold === true || permissionRequiresApproval
      ? { skipApprovalThreshold: true }
      : {}),
    ...(deps.ledger !== undefined ? { ledger: deps.ledger } : {}),
    ...(deps.rateLimiter !== undefined ? { rateLimiter: deps.rateLimiter } : {}),
    ...(deps.approvals !== undefined ? { approvals: deps.approvals } : {}),
    ...(requestAmount !== undefined ? { requestAmount } : {}),
  });

  const context: VerifiedRequestContext = {
    grantId: grant.jti,
    permissions: effectivePermissions,
    resources: effectiveResources,
    constraints: effectiveConstraints,
    method: req.method,
    url: req.url,
    requestDigest,
    ...(grant.sub !== undefined ? { subject: grant.sub } : {}),
  };
  let policyDecision: 'require_approval' | undefined = permissionRequiresApproval
    ? 'require_approval'
    : undefined;
  if (deps.policy !== undefined) {
    try {
      const decision = await deps.policy.authorize(context);
      if (decision === 'deny') {
        throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'site policy denied the request');
      }
      if (decision === 'require_approval') {
        policyDecision = 'require_approval';
      }
    } catch (err) {
      if (err instanceof TrailGateError) {
        throw err;
      }
      throw new TrailGateError(Codes.INTERNAL_ERROR, 'site policy check failed');
    }
  }

  return {
    grant,
    requestDigest,
    operationDigest,
    signatureBase,
    idempotentReplay,
    context,
    ...(requestAmount !== undefined ? { requestAmount } : {}),
    ...(touchedResource !== undefined ? { touchedResource } : {}),
    ...(policyDecision !== undefined ? { policyDecision } : {}),
  };
}
