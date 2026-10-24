import { createHash, timingSafeEqual } from 'node:crypto';
import type { Constraint, GrantPayload, GrantRequestBody } from '@trailgate/core';
import {
  assertRequestedPermissionsKnown,
  base64urlEncode,
  Codes,
  isAgentKeyShape,
  jwkThumbprint,
  SCHEMA_IDS,
  schemaRegistry,
  TrailGateError,
} from '@trailgate/core';
import type { ResolvedServerConfig } from './config.ts';
import { assertRequestLimits, verifyAgentRequest } from './enforcement.ts';
import { randomId } from './ids.ts';
import { cancelPendingActionsForGrant } from './pending-actions.ts';
import type { GrantRequestRecord, IssuedGrantRecord } from './ports.ts';
import { signGrantJwt } from './signing.ts';
import type {
  ConsentDecision,
  ConsentOutcome,
  ConsentView,
  EffectiveScope,
  GrantStatusResponse,
  HostRequest,
  HostResponse,
  RequestedScope,
} from './types.ts';

/**
 * Grant lifecycle flows: request intake, consent decision, redemption,
 * status, and revocation (spec section 10). These return domain results and
 * throw `TrailGateError`; the HTTP handlers in `server.ts` translate them.
 */

export interface GrantRequestAccepted {
  request_id: string;
  consent_url: string;
  expires_at: number;
}

function parseJsonBody(body: HostRequest['body']): unknown {
  const text =
    body === undefined ? '' : typeof body === 'string' ? body : new TextDecoder().decode(body);
  if (text === '') {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request body is not valid json');
  }
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} must be a non-empty string`);
  }
  return value;
}

async function computeEffectiveScope(
  requested: RequestedScope,
  config: ResolvedServerConfig,
): Promise<EffectiveScope> {
  const fallback: EffectiveScope = {
    permissions: [...requested.permissions],
    resources: [...requested.resources],
    constraints: [...requested.constraints],
    lifetimeSeconds: requested.requestedSeconds ?? config.defaultGrantSeconds,
  };
  const effective =
    config.refineScope !== undefined ? await config.refineScope(requested) : fallback;
  const requestedPermissions = new Set(requested.permissions);
  const requestedResources = new Set(requested.resources);
  if (effective.permissions.some((p) => !requestedPermissions.has(p))) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'refineScope returned permissions outside the requested set',
    );
  }
  if (effective.resources.some((r) => !requestedResources.has(r))) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      'refineScope returned resources outside the requested set',
    );
  }
  const supported = new Set(config.constraintTypes);
  if (effective.constraints.some((c) => !supported.has(c.type))) {
    throw new TrailGateError(
      Codes.GRANT_SCOPE_REJECTED,
      'refined constraints use a type this site does not evaluate',
    );
  }
  const refinedLifetime =
    effective.lifetimeSeconds ?? requested.requestedSeconds ?? config.defaultGrantSeconds;
  const lifetime =
    config.maxGrantSeconds !== undefined
      ? Math.min(refinedLifetime, config.maxGrantSeconds)
      : refinedLifetime;
  if (!Number.isInteger(lifetime) || lifetime < 1) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'refineScope returned an invalid lifetime');
  }
  return { ...effective, lifetimeSeconds: lifetime };
}

/**
 * Guards `bindSubjectResources`: every bound selector must derive from a
 * requested one. A requested selector containing `{...}` is a template; a
 * bound selector derives from it when it shares the template's static
 * prefix and suffix (the placeholder region is exactly what the subject
 * binding may fill). Concrete requested selectors may only reappear
 * verbatim. Dropping a selector is allowed (consent narrows scope).
 */
export function assertBoundResourcesDeriveFrom(
  requested: readonly string[],
  bound: readonly string[],
): void {
  const concrete = new Set(requested.filter((r) => !r.includes('{')));
  const templates = requested
    .filter((r) => r.includes('{'))
    .map((r) => {
      const open = r.indexOf('{');
      const close = r.indexOf('}', open);
      return { prefix: r.slice(0, open), suffix: close === -1 ? '' : r.slice(close + 1) };
    });
  for (const b of bound) {
    const derived =
      concrete.has(b) ||
      templates.some(
        (t) =>
          b.startsWith(t.prefix) &&
          b.endsWith(t.suffix) &&
          b.length > t.prefix.length + t.suffix.length,
      );
    if (!derived) {
      throw new TrailGateError(
        Codes.INTERNAL_ERROR,
        'bindSubjectResources returned a selector outside the requested scope',
        { selector: b },
      );
    }
  }
}

/** Returns `subset` unchanged when every entry is in `base`; throws otherwise. */
function assertSubset(
  subset: readonly string[] | undefined,
  base: readonly string[],
  field: string,
): string[] | undefined {
  if (subset === undefined) {
    return undefined;
  }
  const allowed = new Set(base);
  const extra = subset.filter((s) => !allowed.has(s));
  if (extra.length > 0) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      `consent narrowing for ${field} must be a subset of the requested scope`,
      { rejected: extra },
    );
  }
  return [...subset];
}

export async function submitGrantRequest(
  body: unknown,
  config: ResolvedServerConfig,
): Promise<GrantRequestAccepted> {
  if (!schemaRegistry().validate(SCHEMA_IDS.grantRequest, body)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'grant request failed schema validation', {
      schema: schemaRegistry().errors(SCHEMA_IDS.grantRequest),
    });
  }
  const request = body as GrantRequestBody;
  if (!config.supportedProtocolVersions.includes(request.version)) {
    throw new TrailGateError(Codes.GRANT_SCOPE_REJECTED, 'unsupported protocol version', {
      version: request.version,
    });
  }
  assertRequestedPermissionsKnown(request.permissions, config.permissions);
  const supportedConstraints = new Set(config.constraintTypes);
  const unsupported = request.constraints.filter((c) => !supportedConstraints.has(c.type));
  if (unsupported.length > 0) {
    throw new TrailGateError(
      Codes.GRANT_SCOPE_REJECTED,
      'requested constraint type is not supported by this site',
      { unsupported: unsupported.map((c) => c.type) },
    );
  }
  if (!isAgentKeyShape(request.agent_key)) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      'agent_key is not an Ed25519 or P-256 public JWK',
    );
  }
  if (config.resourcePolicy !== undefined) {
    await config.resourcePolicy(request.resources);
  }

  const agentJkt = jwkThumbprint(request.agent_key);

  // Intake rate limiting: one agent key may hold a bounded number of open
  // requests and create a bounded number per minute. Denied requests still
  // count against the minute window so retry floods cannot bypass it.
  const now0 = config.clock.now();
  const [pending, recent] = await Promise.all([
    config.stores.grantRequests.countByAgent(agentJkt, 0, ['pending', 'approved']),
    config.stores.grantRequests.countByAgent(agentJkt, now0 - 60),
  ]);
  if (pending >= config.maxPendingRequestsPerAgent || recent >= config.maxGrantRequestsPerMinute) {
    throw new TrailGateError(
      Codes.REQUEST_RATE_LIMITED,
      'too many open grant requests; wait for existing requests to be decided or expire',
    );
  }

  const requestedScope: RequestedScope = {
    permissions: request.permissions,
    resources: request.resources,
    constraints: request.constraints,
    ...(request.requested_seconds !== undefined
      ? { requestedSeconds: request.requested_seconds }
      : {}),
  };
  const effective = await computeEffectiveScope(requestedScope, config);

  const now = config.clock.now();
  const record: GrantRequestRecord = {
    requestId: randomId('req'),
    createdAt: now,
    expiresAt: now + config.grantRequestTtlSeconds,
    status: 'pending',
    body: request,
    agentJkt,
    effectivePermissions: effective.permissions,
    effectiveResources: effective.resources,
    effectiveConstraints: effective.constraints,
    effectiveLifetimeSeconds: effective.lifetimeSeconds,
  };
  await config.stores.grantRequests.insert(record);
  await config.stores.agentKeys.register(agentJkt, request.agent_key);
  await config.stores.audit.record({
    event: 'grant.requested',
    at: now,
    request_id: record.requestId,
    jkt: agentJkt,
    permissions: effective.permissions,
    constraints: effective.constraints,
  });

  return {
    request_id: record.requestId,
    consent_url: `${config.issuer}${config.paths.consent}?request_id=${encodeURIComponent(record.requestId)}`,
    expires_at: record.expiresAt,
  };
}

export async function getConsentView(
  requestId: string,
  config: ResolvedServerConfig,
): Promise<ConsentView | undefined> {
  const record = await config.stores.grantRequests.get(requestId);
  if (record === undefined) {
    return undefined;
  }
  return {
    requestId: record.requestId,
    agentJkt: record.agentJkt,
    expiresAt: record.expiresAt,
    status: record.status,
    requested: {
      permissions: record.body.permissions,
      resources: record.body.resources,
      constraints: record.body.constraints,
      ...(record.body.requested_seconds !== undefined
        ? { requestedSeconds: record.body.requested_seconds }
        : {}),
    },
    effective: {
      permissions: record.effectivePermissions ?? record.body.permissions,
      resources: record.effectiveResources ?? record.body.resources,
      constraints: record.effectiveConstraints ?? record.body.constraints,
      lifetimeSeconds: record.effectiveLifetimeSeconds ?? config.defaultGrantSeconds,
    },
    lifetimeCapSeconds: config.maxConsentLifetimeSeconds,
    approvalSuggested: [
      ...new Set(
        [...config.actions.values()]
          .filter((a) => a.approval_required === true)
          .map((a) => a.permission),
      ),
    ].filter((p) => (record.effectivePermissions ?? record.body.permissions).includes(p)),
    ...(record.body.redirect_uri !== undefined ? { redirectUri: record.body.redirect_uri } : {}),
  };
}

/**
 * Records the user's consent decision. Called by the host's own consent
 * surface after its existing authentication. `siteUserId` is the host's
 * authenticated user identifier, required for approvals; it is mapped to the
 * grant's `sub` via `config.subjectFor`.
 *
 * `narrow` lets the consent surface reduce scope at decision time (for
 * example the user unchecking permissions): every entry must already be in
 * the effective requested set, so consent can only ever narrow, never widen.
 * `lifetimeSeconds` is the exception: the consenting human is the authority
 * on how long the access lasts, so they may pick any duration up to
 * `config.maxConsentLifetimeSeconds`, shorter or longer than requested.
 */
export interface ConsentNarrow {
  permissions?: string[];
  resources?: string[];
  lifetimeSeconds?: number;
  /**
   * The tri-state "require approval" picks (spec section 9): permissions the
   * user granted but wants to review per action. They must be a subset of
   * the granted permissions and are persisted as a `require_approval`
   * constraint on the issued grant. Providing an empty array clears any
   * require_approval constraint the request itself carried; leaving the
   * field undefined keeps the request's constraint untouched.
   */
  approvalPermissions?: string[];
}

export async function decideConsent(
  requestId: string,
  decision: ConsentDecision,
  siteUserId: string | undefined,
  config: ResolvedServerConfig,
  narrow?: ConsentNarrow,
): Promise<ConsentOutcome> {
  const record = await config.stores.grantRequests.get(requestId);
  if (record === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'unknown request_id');
  }
  const now = config.clock.now();
  if (record.status !== 'pending' && record.status !== 'expired') {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'grant request already decided', {
      status: record.status,
    });
  }
  if (record.status === 'expired' || record.expiresAt <= now) {
    await config.stores.grantRequests.transition(requestId, 'pending', { status: 'expired' });
    throw new TrailGateError(Codes.GRANT_EXPIRED, 'grant request has expired');
  }
  if (decision === 'approve' && (siteUserId === undefined || siteUserId === '')) {
    throw new TrailGateError(
      Codes.AUTHORIZATION_DENIED,
      'an authenticated user is required to approve a grant',
    );
  }
  const subject = decision === 'approve' ? config.subjectFor(siteUserId as string) : undefined;
  const basePermissions = record.effectivePermissions ?? record.body.permissions;
  const baseResources = record.effectiveResources ?? record.body.resources;
  const narrowedPermissions = assertSubset(narrow?.permissions, basePermissions, 'permissions');
  const narrowedResources = assertSubset(narrow?.resources, baseResources, 'resources');
  const grantedPermissions = narrowedPermissions ?? basePermissions;
  const approvalPermissions = assertSubset(
    narrow?.approvalPermissions,
    grantedPermissions,
    'approval permissions',
  );
  let effectiveConstraints: Constraint[] | undefined;
  if (approvalPermissions !== undefined) {
    const base = record.effectiveConstraints ?? record.body.constraints;
    effectiveConstraints = [
      ...base.filter((c) => c.type !== 'require_approval'),
      ...(approvalPermissions.length > 0
        ? [{ type: 'require_approval', params: { permissions: [...approvalPermissions] } }]
        : []),
    ];
  }
  let consentLifetime: number | undefined;
  if (narrow?.lifetimeSeconds !== undefined) {
    if (!Number.isInteger(narrow.lifetimeSeconds) || narrow.lifetimeSeconds < 1) {
      throw new TrailGateError(
        Codes.REQUEST_MALFORMED,
        'consent lifetimeSeconds must be a positive integer',
      );
    }
    consentLifetime = Math.min(narrow.lifetimeSeconds, config.maxConsentLifetimeSeconds);
  }
  let boundResources: string[] | undefined;
  if (subject !== undefined && config.bindSubjectResources !== undefined) {
    const requested = narrowedResources ?? baseResources;
    boundResources = [...(await config.bindSubjectResources(requested, subject))];
    assertBoundResourcesDeriveFrom(requested, boundResources);
  }
  const effectiveResources =
    boundResources ?? (narrowedResources !== undefined ? narrowedResources : undefined);
  const decided = await config.stores.grantRequests.transition(requestId, 'pending', {
    status: decision === 'approve' ? 'approved' : 'denied',
    decidedAt: now,
    ...(subject !== undefined ? { subject } : {}),
    ...(narrowedPermissions !== undefined ? { effectivePermissions: narrowedPermissions } : {}),
    ...(effectiveResources !== undefined ? { effectiveResources } : {}),
    ...(effectiveConstraints !== undefined ? { effectiveConstraints } : {}),
    ...(consentLifetime !== undefined ? { effectiveLifetimeSeconds: consentLifetime } : {}),
  });
  if (decided === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'grant request already decided');
  }
  await config.stores.audit.record({
    event: 'grant.consent_decided',
    at: now,
    request_id: requestId,
    decision: decision === 'approve' ? 'approved' : 'denied',
    ...(subject !== undefined ? { sub: subject } : {}),
  });
  const outcome: ConsentOutcome = {
    requestId,
    decision: decision === 'approve' ? 'approved' : 'denied',
  };
  if (record.body.redirect_uri !== undefined) {
    const target = new URL(record.body.redirect_uri);
    target.searchParams.set('request_id', requestId);
    if (record.body.state !== undefined) {
      target.searchParams.set('state', record.body.state);
    }
    outcome.redirectTo = target.toString();
  }
  return outcome;
}

export interface RedeemGrantInput {
  request_id: string;
  code_verifier: string;
}

export async function redeemGrant(
  body: unknown,
  config: ResolvedServerConfig,
): Promise<{ grant: string }> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'redemption body must be a json object');
  }
  const input = body as Partial<RedeemGrantInput>;
  const requestId = requireString(input.request_id, 'request_id');
  const verifier = requireString(input.code_verifier, 'code_verifier');

  const record = await config.stores.grantRequests.get(requestId);
  if (record === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'unknown request_id');
  }
  const now = config.clock.now();
  if (record.status === 'issued') {
    throw new TrailGateError(Codes.GRANT_REDEEMED, 'grant request was already redeemed');
  }
  if (record.status === 'denied') {
    throw new TrailGateError(Codes.GRANT_CONSENT_DENIED, 'consent was denied for this request');
  }
  if (record.expiresAt <= now) {
    if (record.status === 'pending' || record.status === 'approved') {
      await config.stores.grantRequests.transition(requestId, record.status, {
        status: 'expired',
      });
    }
    throw new TrailGateError(Codes.GRANT_EXPIRED, 'grant request has expired');
  }
  if (record.status !== 'approved') {
    throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'grant request is not approved');
  }
  const challenge = base64urlEncode(createHash('sha256').update(verifier, 'utf8').digest());
  const expected = Buffer.from(record.body.code_challenge, 'utf8');
  const actual = Buffer.from(challenge, 'utf8');
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'code_verifier does not match');
  }
  const jti = randomId('grt');
  const issued = await config.stores.grantRequests.transition(requestId, 'approved', {
    status: 'issued',
    grantId: jti,
  });
  if (issued === undefined) {
    throw new TrailGateError(Codes.GRANT_REDEEMED, 'grant request was already redeemed');
  }

  const lifetimeSeconds = record.effectiveLifetimeSeconds ?? config.defaultGrantSeconds;
  const payload: GrantPayload = {
    iss: config.issuer,
    aud: config.audience,
    iat: now,
    exp: now + lifetimeSeconds,
    jti,
    cnf: { jkt: record.agentJkt },
    tg: {
      version: record.body.version,
      permissions: record.effectivePermissions ?? record.body.permissions,
      resources: record.effectiveResources ?? record.body.resources,
      constraints: record.effectiveConstraints ?? record.body.constraints,
      request_id: record.requestId,
    },
    ...(record.subject !== undefined ? { sub: record.subject } : {}),
  };
  if (!schemaRegistry().validate(SCHEMA_IDS.grant, payload)) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'issued grant failed schema validation');
  }
  const token = await signGrantJwt(payload as unknown as GrantPayload, config.signingKey);
  await config.stores.grants.insert({
    jti,
    issuedAt: now,
    expiresAt: payload.exp,
    agentJkt: record.agentJkt,
    requestId: record.requestId,
    status: 'active',
    permissions: [...(payload.tg.permissions as string[])],
    // Record the decided scope as the current effective scope so status
    // surfaces and the tri-state editor reflect consent-time marks (such as
    // a require_approval constraint) before any post-issuance edit.
    effectivePermissions: [...(payload.tg.permissions as string[])],
    effectiveResources: [...payload.tg.resources],
    effectiveConstraints: [...payload.tg.constraints],
    ...(record.subject !== undefined ? { subject: record.subject } : {}),
  });
  await config.stores.audit.record({
    event: 'grant.issued',
    at: now,
    request_id: record.requestId,
    grant_id: jti,
    jkt: record.agentJkt,
    exp: payload.exp,
    ...(record.subject !== undefined ? { sub: record.subject } : {}),
  });
  return { grant: token };
}

/**
 * Grant status query (spec section 10.5). Accepts `request_id` before
 * issuance or `grant_id` after. Status responses are plainly informational
 * in this draft; signed status is an open spec question (section 19).
 */
export async function grantStatus(
  query: { request_id?: string; grant_id?: string },
  config: ResolvedServerConfig,
): Promise<GrantStatusResponse> {
  const now = config.clock.now();
  if (query.request_id !== undefined) {
    const record = await config.stores.grantRequests.get(query.request_id);
    if (record === undefined) {
      throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown request_id');
    }
    if ((record.status === 'pending' || record.status === 'approved') && record.expiresAt <= now) {
      await config.stores.grantRequests.transition(record.requestId, record.status, {
        status: 'expired',
      });
      return { status: 'expired', expires_at: record.expiresAt };
    }
    if (record.status === 'issued') {
      if (record.grantId !== undefined) {
        return grantStatus({ grant_id: record.grantId }, config);
      }
      throw new TrailGateError(Codes.INTERNAL_ERROR, 'issued request has no linked grant');
    }
    return { status: record.status, expires_at: record.expiresAt };
  }
  if (query.grant_id !== undefined) {
    const grant = await config.stores.grants.get(query.grant_id);
    if (grant === undefined) {
      throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown grant_id');
    }
    const status =
      grant.status === 'revoked' ? 'revoked' : grant.expiresAt <= now ? 'expired' : 'active';
    return {
      status,
      issued_at: grant.issuedAt,
      expires_at: grant.expiresAt,
      // The site's current effective scope, so agents can learn
      // post-issuance changes (permissions the site later allowed or
      // removed) without a fresh consent flow.
      permissions: grant.effectivePermissions ?? grant.permissions,
      ...(grant.effectiveResources !== undefined ? { resources: grant.effectiveResources } : {}),
      ...(grant.effectiveConstraints !== undefined
        ? { constraints: grant.effectiveConstraints }
        : {}),
    };
  }
  throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request_id or grant_id is required');
}

/**
 * Host-initiated revocation (spec section 13): called from the site's own
 * authenticated surfaces (user settings, admin tooling, risk signals). Takes
 * effect at the next enforcement check.
 */
export async function revokeGrant(
  jti: string,
  input: { reason: string; actor: string },
  config: ResolvedServerConfig,
): Promise<void> {
  const revoked = await config.stores.grants.revoke(jti, {
    reason: input.reason,
    actor: input.actor,
    at: config.clock.now(),
  });
  if (revoked === undefined) {
    throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown or already revoked grant');
  }
  // Revocation cancels queued and approved-not-yet-executed actions; the
  // execution path re-checks grant status as well, so an action claimed in
  // between still cannot run under the revoked grant (spec section 12.5).
  await cancelPendingActionsForGrant(jti, 'grant was revoked', config);
  await config.stores.audit.record({
    event: 'grant.revoked',
    at: revoked.revokedAt ?? config.clock.now(),
    grant_id: jti,
    reason: input.reason,
    actor: input.actor,
  });
}

/**
 * Host-initiated post-issuance scope change (spec section 13): the site
 * replaces the grant's effective permission (and optionally resource) set.
 * Only the site can do this; agents can never modify their own scope. The
 * set must stay inside the site's advertised permission vocabulary, and an
 * empty set is refused — removing every permission is a revocation.
 * Enforcement treats the stored scope as live state; it takes effect on
 * the next request without reissuing a JWT.
 */
export async function updateGrantScope(
  jti: string,
  input: {
    permissions: string[];
    resources?: string[];
    constraints?: Constraint[];
    actor: string;
  },
  config: ResolvedServerConfig,
): Promise<IssuedGrantRecord> {
  const record = await config.stores.grants.get(jti);
  if (record === undefined) {
    throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown grant');
  }
  if (input.permissions.length === 0) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      'removing every permission is a revocation; use revokeGrant',
    );
  }
  const vocabulary = new Set(config.permissions);
  const unknown = input.permissions.filter((permission) => !vocabulary.has(permission));
  if (unknown.length > 0) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      'scope may only contain permissions the site advertises',
      { unknown },
    );
  }
  if (input.constraints !== undefined) {
    const supported = new Set(config.constraintTypes);
    const bad = input.constraints.filter((c) => !supported.has(c.type));
    if (bad.length > 0) {
      throw new TrailGateError(
        Codes.REQUEST_MALFORMED,
        'constraints may only use types the site evaluates',
        { rejected: bad.map((c) => c.type) },
      );
    }
  }
  if (input.resources !== undefined) {
    if (
      !Array.isArray(input.resources) ||
      input.resources.some((r) => typeof r !== 'string' || r === '')
    ) {
      throw new TrailGateError(Codes.REQUEST_MALFORMED, 'resources must be a list of selectors');
    }
    if (config.resourcePolicy !== undefined) {
      await config.resourcePolicy(input.resources);
    }
  }
  const updated = await config.stores.grants.updateScope(jti, {
    permissions: input.permissions,
    ...(input.resources !== undefined ? { resources: input.resources } : {}),
    ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
    actor: input.actor,
    at: config.clock.now(),
  });
  if (updated === undefined) {
    throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown or already revoked grant');
  }
  await config.stores.audit.record({
    event: 'grant.scope_changed',
    at: config.clock.now(),
    grant_id: jti,
    actor: input.actor,
    permissions: input.permissions,
    ...(record.subject !== undefined ? { sub: record.subject } : {}),
  });
  return updated;
}

/**
 * POST handler for the discovery `grant_revocation` endpoint (spec section
 * 13). Two caller models: agent self-revocation via a section 11 signed
 * request presenting the same grant, or a site-configured
 * `revocationAuthorizer` for other callers. Denies when neither applies.
 */
export async function handleRevocationRequest(
  req: HostRequest,
  config: ResolvedServerConfig,
): Promise<HostResponse> {
  assertRequestLimits(req, config);
  const body = parseJsonBody(req.body);
  if (!schemaRegistry().validate(SCHEMA_IDS.grantRevocation, body)) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'revocation body failed schema validation', {
      schema: schemaRegistry().errors(SCHEMA_IDS.grantRevocation),
    });
  }
  const { grant_id: grantId, reason } = body as { grant_id: string; reason?: string };
  const grant = await config.stores.grants.get(grantId);
  if (grant === undefined) {
    throw new TrailGateError(Codes.GRANT_UNKNOWN, 'unknown grant_id');
  }
  if (req.headers['trailgate-grant'] !== undefined) {
    // Agent self-revocation: the request must verify as a protected request
    // presenting the grant being revoked. A failed verification denies.
    const verified = await verifyAgentRequest(req, config);
    if (verified.grant.jti !== grantId) {
      throw new TrailGateError(
        Codes.AUTHORIZATION_DENIED,
        'the presented grant does not match grant_id',
      );
    }
    await revokeGrant(
      grantId,
      { actor: `agent:${verified.grant.cnf.jkt}`, reason: reason ?? 'agent-initiated' },
      config,
    );
    return { status: 200, body: { grant_id: grantId, status: 'revoked' } };
  }
  if (config.revocationAuthorizer === undefined) {
    throw new TrailGateError(
      Codes.AUTHORIZATION_DENIED,
      'revocation endpoint requires a signed request or a configured revocationAuthorizer',
    );
  }
  const actor = await config.revocationAuthorizer(req, grant);
  if (actor === undefined) {
    throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'caller may not revoke this grant');
  }
  await revokeGrant(
    grantId,
    {
      actor: actor.actor,
      reason: actor.reason ?? (reason !== undefined && reason !== '' ? reason : 'unspecified'),
    },
    config,
  );
  return { status: 200, body: { grant_id: grantId, status: 'revoked' } };
}
