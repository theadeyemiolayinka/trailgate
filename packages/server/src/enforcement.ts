import type {
  DiscoveryAction,
  GrantPayload,
  Jwk,
  KeyResolver,
  Money,
  RequestVerificationResult,
  VerifiedRequestContext,
} from '@trailgate/core';
import {
  assertPermissionGranted,
  assertResourceAllowed,
  buildSignatureBase,
  Codes,
  decodeCompactJws,
  evaluateConstraints,
  getHeader,
  isTrailGateError,
  operationDigestOf,
  parseTgSignatureInput,
  TrailGateError,
  toErrorResponse,
  verifyProtectedRequest,
} from '@trailgate/core';
import { issueRequestApproval } from './approvals.ts';
import type { ResolvedServerConfig } from './config.ts';
import { randomId } from './ids.ts';
import {
  pendingActionDigest,
  pendingActionRequest,
  pendingActionView,
  queuePendingAction,
} from './pending-actions.ts';
import type {
  PendingActionRecord,
  RequestApprovalRecord,
  Reservation,
  StoredOutcome,
} from './ports.ts';
import { issueReceipt } from './signing.ts';
import type {
  EnforcementContext,
  HostRequest,
  HostResponse,
  ProtectedHandler,
  RouteProtection,
  SelectorContext,
} from './types.ts';

/** Response header carrying the receipt JWS (spec section 14.1). */
export const RECEIPT_HEADER = 'trailgate-receipt';

/** Maps verification failure codes to the spec section 11.3 stage for audit. */
const CODE_TO_STAGE: Record<string, number> = {
  [Codes.REQUEST_MALFORMED]: 1,
  [Codes.REQUEST_BODY_DIGEST_MISMATCH]: 2,
  [Codes.REQUEST_SIGNATURE_INVALID]: 3,
  [Codes.REQUEST_EXPIRED]: 4,
  [Codes.GRANT_MALFORMED]: 5,
  [Codes.REQUEST_AUDIENCE_MISMATCH]: 5,
  [Codes.GRANT_EXPIRED]: 5,
  [Codes.GRANT_REVOKED]: 6,
  [Codes.REQUEST_KEY_MISMATCH]: 7,
  [Codes.REQUEST_REPLAY_DETECTED]: 8,
  [Codes.REQUEST_IDEMPOTENCY_CONFLICT]: 9,
  [Codes.REQUEST_PERMISSION_DENIED]: 10,
  [Codes.REQUEST_RESOURCE_DENIED]: 11,
  [Codes.CONSTRAINT_VIOLATED]: 12,
  [Codes.CONSTRAINT_UNKNOWN_TYPE]: 12,
  [Codes.CONSTRAINT_APPROVAL_REQUIRED]: 12,
  [Codes.AUTHORIZATION_DENIED]: 13,
};

/** Operation digest is computed by core's `operationDigestOf` (spec section 11.4). */

/** Best-effort recovery of the receipt binding inputs from a failed request. */
function receiptBasis(req: HostRequest): { grantId?: string; signatureBase?: string } {
  const basis: { grantId?: string; signatureBase?: string } = {};
  try {
    const grantHeader = getHeader(req, 'trailgate-grant');
    if (grantHeader !== undefined) {
      const decoded = decodeCompactJws(grantHeader);
      const jti = (decoded.payload as Partial<GrantPayload>).jti;
      if (typeof jti === 'string') {
        basis.grantId = jti;
      }
    }
  } catch {
    // Grant was malformed or unsigned; no reliable jti for the receipt.
  }
  try {
    const inputHeader = getHeader(req, 'signature-input');
    if (inputHeader !== undefined) {
      const parsed = parseTgSignatureInput(inputHeader);
      basis.signatureBase = buildSignatureBase(req, parsed.components, parsed.entry);
    }
  } catch {
    // Signature-Input was unparseable; no signature base to bind a receipt to.
  }
  return basis;
}

/**
 * Renders a denial: error envelope, `request.denied` audit event, and a
 * signed receipt when the request was parseable enough to bind one
 * (spec section 14.4). Failures while denying never mask the denial itself.
 */
async function denialResponse(
  err: unknown,
  req: HostRequest,
  config: ResolvedServerConfig,
  extra?: { grantId?: string; signatureBase?: string; released?: Money },
): Promise<HostResponse> {
  const error = isTrailGateError(err)
    ? err
    : new TrailGateError(Codes.INTERNAL_ERROR, 'internal error');
  const basis = { ...receiptBasis(req), ...extra };
  let auditId: string | undefined;
  try {
    auditId = await config.stores.audit.record({
      event: 'request.denied',
      at: config.clock.now(),
      code: error.code,
      stage: String(CODE_TO_STAGE[error.code] ?? 0),
      ...(basis.grantId !== undefined ? { grant_id: basis.grantId } : {}),
    });
  } catch {
    // Audit failure on an already-denied path must not mask the denial.
  }
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (basis.grantId !== undefined && basis.signatureBase !== undefined && auditId !== undefined) {
    try {
      const { token } = await issueReceipt(
        {
          issuer: config.issuer,
          audience: config.audience,
          grantId: basis.grantId,
          signatureBase: basis.signatureBase,
          decision: 'denied',
          code: error.code,
          auditId,
          now: config.clock.now(),
          ...(extra?.released !== undefined ? { amounts: { released: extra.released } } : {}),
        },
        config.signingKey,
      );
      headers[RECEIPT_HEADER] = token;
    } catch {
      // A receipt that cannot be signed is omitted; the error body still stands.
    }
  }
  return { status: error.httpStatus, headers, body: toErrorResponse(error) };
}

/**
 * Cheap request-size bounds checked before any cryptographic or storage
 * work (spec section 17). Oversized requests deny with
 * `tg.request.too_large`.
 */
export function assertRequestLimits(
  req: HostRequest,
  config: { maxBodyBytes: number; maxHeadersBytes: number },
): void {
  const bodyBytes = typeof req.body === 'string' ? req.body.length : (req.body?.byteLength ?? 0);
  if (bodyBytes > config.maxBodyBytes) {
    throw new TrailGateError(Codes.REQUEST_TOO_LARGE, 'request body exceeds the site limit', {
      limit: config.maxBodyBytes,
    });
  }
  let headerBytes = 0;
  for (const [name, value] of Object.entries(req.headers)) {
    headerBytes += name.length + value.length;
    if (headerBytes > config.maxHeadersBytes) {
      throw new TrailGateError(Codes.REQUEST_TOO_LARGE, 'request headers exceed the site limit', {
        limit: config.maxHeadersBytes,
      });
    }
  }
}

/**
 * Runs the spec section 11 verification pipeline for endpoints that accept
 * a signed agent request outside `protect` (grant self-revocation, spec
 * section 13). Returns the verified result or throws.
 */
export async function verifyAgentRequest(
  req: HostRequest,
  config: ResolvedServerConfig,
): Promise<RequestVerificationResult> {
  return verifyProtectedRequest(req, {
    issuer: config.issuer,
    audience: config.audience,
    resolveSiteKey: siteKeyResolver(config),
    resolveAgentKey: config.stores.agentKeys,
    revocation: config.stores.grants,
    nonceStore: config.stores.nonces,
    idempotency: config.stores.idempotency,
    ledger: config.stores.ledger,
    rateLimiter: config.stores.rateLimiter,
    clock: config.clock,
    toleranceSeconds: config.toleranceSeconds,
    supportedProtocolVersions: config.supportedProtocolVersions,
    permissionVocabulary: config.permissions,
    ...(config.resourceOwners !== undefined ? { resourceOwners: config.resourceOwners } : {}),
  });
}

/** Verified selector context handed to route resolvers (spec section 11). */
function selectorContext(grant: GrantPayload): SelectorContext {
  return {
    grant,
    ...(grant.sub !== undefined ? { subject: grant.sub } : {}),
  };
}

function resolveAmount(
  route: RouteProtection,
  req: HostRequest,
  ctx: SelectorContext,
): Money | undefined {
  return typeof route.amount === 'function' ? route.amount(req, ctx) : route.amount;
}

function resolveResource(
  route: RouteProtection,
  req: HostRequest,
  ctx: SelectorContext,
): string | undefined {
  return typeof route.resource === 'function' ? route.resource(req, ctx) : route.resource;
}

function requestNonce(req: HostRequest): string | undefined {
  try {
    const header = getHeader(req, 'signature-input');
    if (header === undefined) {
      return undefined;
    }
    return parseTgSignatureInput(header).params.nonce;
  } catch {
    return undefined;
  }
}

function siteKeyResolver(config: ResolvedServerConfig): KeyResolver {
  const keys = new Map<string, Jwk>(config.signingKeys.map((key) => [key.kid, key.publicJwk]));
  return { resolve: async (kid) => keys.get(kid) };
}

/**
 * Registers the route's action advertisement (spec section 5.2) in the
 * catalog published by discovery. `permission` and `mutates` are derived
 * from the same `RouteProtection` that enforcement uses, so the catalog
 * cannot drift from what the pipeline actually requires. Throws for
 * malformed or conflicting declarations; protect() is host startup code,
 * so failing fast is correct.
 */
function registerAction(route: RouteProtection, config: ResolvedServerConfig): void {
  const advertised = route.action;
  if (advertised === undefined) {
    return;
  }
  if (
    advertised.id === '' ||
    advertised.description === '' ||
    !/^[A-Z]+$/.test(advertised.method)
  ) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      `action '${advertised.id}' must declare a non-empty id, description, and an uppercase method`,
    );
  }
  if (!advertised.path.startsWith('/') || advertised.path.includes('://')) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      `action '${advertised.id}' path must be a path template on the issuer origin`,
    );
  }
  if (!config.permissions.includes(route.permission)) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      `action '${advertised.id}' permission '${route.permission}' is not in the site vocabulary`,
    );
  }
  const action: DiscoveryAction = {
    id: advertised.id,
    method: advertised.method,
    path: advertised.path,
    permission: route.permission,
    description: advertised.description,
    mutates: route.mutating ?? true,
    ...(advertised.resource !== undefined ? { resource: advertised.resource } : {}),
    ...(advertised.spend !== undefined ? { spend: advertised.spend } : {}),
    ...(route.approval === 'required' ? { approval_required: true } : {}),
  };
  const existing = config.actions.get(action.id);
  if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(action)) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      `action id '${action.id}' is registered twice with different declarations`,
    );
  }
  config.actions.set(action.id, action);
}

/**
 * Registers the trusted handler an approved pending action executes through
 * (spec section 12.5). Every protected route registers so a grant-scoped
 * `require_approval` constraint can queue operations on any of them, not
 * only routes declared `approval: 'required'`. The registry is keyed by the
 * action id when advertised, else by permission. Distinct routes resolving
 * to the same key would make execution ambiguous; the key is marked
 * ambiguous and refused at queue and execute time rather than at startup.
 */
function registerActionHandler(
  route: RouteProtection,
  handler: ProtectedHandler,
  config: ResolvedServerConfig,
): void {
  const id = route.action?.id ?? route.permission;
  const existing = config.actionHandlers.get(id);
  if (existing !== undefined) {
    if (existing.route !== route) {
      config.actionHandlers.delete(id);
      config.ambiguousActionKeys.add(id);
    }
    return;
  }
  config.actionHandlers.set(id, { route, handler });
}

/**
 * Wraps a host handler with the spec section 11 enforcement pipeline:
 * protocol verification via `verifyProtectedRequest`, then reservation,
 * execution, settlement, idempotency recording, audit, and a signed receipt.
 *
 * The returned handler produces complete `HostResponse`s including denials;
 * it never throws for protocol-level failures. Reservations are consumed when
 * the host handler answers with status < 400 and released on throws or
 * higher statuses (spec section 12).
 */
export function createProtectedHandler(
  route: RouteProtection,
  handler: ProtectedHandler,
  config: ResolvedServerConfig,
): (req: HostRequest) => Promise<HostResponse> {
  registerAction(route, config);
  registerActionHandler(route, handler, config);
  return async (req) => {
    try {
      assertRequestLimits(req, config);
    } catch (err) {
      return denialResponse(err, req, config);
    }
    let result: RequestVerificationResult;
    try {
      result = await verifyProtectedRequest(req, {
        issuer: config.issuer,
        audience: config.audience,
        resolveSiteKey: siteKeyResolver(config),
        resolveAgentKey: config.stores.agentKeys,
        revocation: config.stores.grants,
        grantScope: config.stores.grants,
        nonceStore: config.stores.nonces,
        idempotency: config.stores.idempotency,
        ledger: config.stores.ledger,
        rateLimiter: config.stores.rateLimiter,
        approvals: config.stores.approvals,
        clock: config.clock,
        toleranceSeconds: config.toleranceSeconds,
        supportedProtocolVersions: config.supportedProtocolVersions,
        permissionVocabulary: config.permissions,
        // The queued human decision covers approval_threshold; it must not
        // demand a second approval on top of the pending action itself.
        skipApprovalThreshold: route.approval === 'required',
        ...(config.resourceOwners !== undefined ? { resourceOwners: config.resourceOwners } : {}),
        ...(config.policy !== undefined ? { policy: config.policy } : {}),
        requiredPermission: route.permission,
        ...(route.amount !== undefined
          ? {
              resolveRequestAmount: (grant) => resolveAmount(route, req, selectorContext(grant)),
            }
          : {}),
        ...(route.resource !== undefined
          ? {
              resolveTouchedResource: (grant) =>
                resolveResource(route, req, selectorContext(grant)),
            }
          : {}),
      });
    } catch (err) {
      if (isTrailGateError(err) && err.code === Codes.CONSTRAINT_APPROVAL_REQUIRED) {
        return approvalRequiredResponse(err, req, config);
      }
      return denialResponse(err, req, config);
    }
    return runVerifiedOperation(route, handler, config, req, result);
  };
}

/**
 * The post-verification half of the protected pipeline, shared by live
 * requests and by approved pending actions executing later
 * (`pendingAction` set): audit, dedupe, queueing, reservation, execution,
 * settlement, and the signed receipt. Pending executions skip dedupe and
 * queueing (the action record's atomic transitions provide both) and the
 * `approval_threshold` consume (the recorded human decision covers it).
 */
export async function runVerifiedOperation(
  route: RouteProtection,
  handler: ProtectedHandler,
  config: ResolvedServerConfig,
  req: HostRequest,
  result: RequestVerificationResult,
  pendingAction?: PendingActionRecord,
): Promise<HostResponse> {
  const { grant, requestDigest } = result;
  const now = config.clock.now();
  const idempotencyKey = getHeader(req, 'idempotency-key');

  let auditId: string;
  try {
    const nonce = requestNonce(req);
    auditId = await config.stores.audit.record({
      event: 'request.authenticated',
      at: now,
      grant_id: grant.jti,
      request_digest: requestDigest,
      ...(nonce !== undefined ? { nonce } : {}),
      ...(pendingAction !== undefined ? { action_request_id: pendingAction.id } : {}),
    });
  } catch {
    return denialResponse(
      new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'audit sink is unavailable'),
      req,
      config,
      { grantId: grant.jti, signatureBase: result.signatureBase },
    );
  }

  await config.stores.rateLimiter.record(grant.jti, now);

  const mutating = route.mutating !== false;

  if (pendingAction === undefined) {
    if (result.idempotentReplay && idempotencyKey !== undefined) {
      const stored = await config.stores.idempotency.lookup(grant.jti, idempotencyKey);
      if (stored?.outcome === undefined) {
        return denialResponse(
          new TrailGateError(
            Codes.REQUEST_IDEMPOTENCY_IN_FLIGHT,
            'a request with this idempotency key is still executing',
          ),
          req,
          config,
          { grantId: grant.jti, signatureBase: result.signatureBase },
        );
      }
      const outcome = stored.outcome;
      const replayed: HostResponse = { status: outcome.status };
      if (outcome.headers !== undefined) {
        replayed.headers = outcome.headers;
      }
      if (outcome.body !== undefined) {
        replayed.body = outcome.body;
      }
      return replayed;
    }

    if (mutating && idempotencyKey !== undefined) {
      // Claim-at-lookup (spec section 11.4): the pending record stops a
      // concurrent duplicate from executing twice. A record that appeared
      // between verification and claim is replayed or reported in flight.
      const claim = await config.stores.idempotency.claim(
        grant.jti,
        idempotencyKey,
        operationDigestOf(req, grant.jti),
      );
      if (claim.kind === 'conflict') {
        return denialResponse(
          new TrailGateError(
            Codes.REQUEST_IDEMPOTENCY_CONFLICT,
            'idempotency-key reused with a different request',
          ),
          req,
          config,
          { grantId: grant.jti, signatureBase: result.signatureBase },
        );
      }
      if (claim.kind === 'existing') {
        if (claim.record.outcome === undefined) {
          return denialResponse(
            new TrailGateError(
              Codes.REQUEST_IDEMPOTENCY_IN_FLIGHT,
              'a request with this idempotency key is still executing',
            ),
            req,
            config,
            { grantId: grant.jti, signatureBase: result.signatureBase },
          );
        }
        const outcome = claim.record.outcome;
        const replayed: HostResponse = { status: outcome.status };
        if (outcome.headers !== undefined) {
          replayed.headers = outcome.headers;
        }
        if (outcome.body !== undefined) {
          replayed.body = outcome.body;
        }
        return replayed;
      }
    }

    if (route.approval === 'required' || result.policyDecision === 'require_approval') {
      return queueActionResponse(route, config, req, result, grant.jti, auditId, {
        mutating,
        ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
      });
    }
  }

  const amount = result.requestAmount;
  let reservation: Reservation | undefined;
  if (amount !== undefined) {
    const budgets = result.context.constraints
      .filter((c) => c.type === 'cumulative_budget')
      .map((c) => c.params as Money | undefined)
      .filter((p): p is Money => p !== undefined && p.currency === amount.currency);
    const spendWindows = result.context.constraints
      .filter((c) => c.type === 'spend_window')
      .map((c) => c.params as (Money & { window_seconds?: number }) | undefined)
      .filter(
        (p): p is Money & { window_seconds: number } =>
          p !== undefined && p.currency === amount.currency && typeof p.window_seconds === 'number',
      )
      .map((p) => ({
        limit: { amount: p.amount, currency: p.currency },
        windowSeconds: p.window_seconds,
      }));
    try {
      reservation = await config.stores.ledger.reserve({
        reservationId: randomId('rsv'),
        grantId: grant.jti,
        amount,
        budgets,
        spendWindows,
        now,
        ttlSeconds: config.reservationTtlSeconds,
      });
      await config.stores.audit.record({
        event: 'reservation.created',
        at: now,
        grant_id: grant.jti,
        reservation_id: reservation.reservationId,
        amount: amount.amount,
        currency: amount.currency,
      });
    } catch (err) {
      if (reservation !== undefined) {
        try {
          await releaseReservation(config, reservation, grant.jti, now);
        } catch {
          // Releasing also failed; the reservation TTL will reclaim it.
        }
      }
      return denialResponse(err, req, config, {
        grantId: grant.jti,
        signatureBase: result.signatureBase,
      });
    }
  }

  // An approval peeked during constraint evaluation must be consumed
  // atomically before the handler runs: a racing request holding the same
  // operation must not spend the same human decision. Pending actions are
  // exempt: the recorded human decision on the action covers it.
  let approval: RequestApprovalRecord | undefined;
  if (pendingAction === undefined && amount !== undefined && needsApproval(grant, amount)) {
    approval = await config.stores.approvals.consumeApproved(
      grant.jti,
      operationDigestOf(req, grant.jti),
      now,
    );
    if (approval === undefined) {
      if (reservation !== undefined) {
        try {
          await releaseReservation(config, reservation, grant.jti, now);
        } catch {
          // The denial stands regardless; the reservation TTL reclaims it.
        }
      }
      return approvalRequiredResponse(
        new TrailGateError(
          Codes.CONSTRAINT_APPROVAL_REQUIRED,
          'request amount exceeds approval_threshold and requires human approval',
          { type: 'approval_threshold', amount, grant_id: grant.jti },
        ),
        req,
        config,
        { grantId: grant.jti, signatureBase: result.signatureBase },
      );
    }
  }

  const context: EnforcementContext = { ...result.context, grant };
  if (pendingAction !== undefined) {
    context.pendingAction = pendingAction;
  }
  let response: HostResponse;
  try {
    response = await handler(req, context);
  } catch (err) {
    if (reservation !== undefined) {
      try {
        await releaseReservation(config, reservation, grant.jti, now);
      } catch {
        // The handler's error takes precedence; the reservation TTL reclaims it.
      }
    }
    await restoreApproval(config, approval);
    return denialResponse(err, req, config, {
      grantId: grant.jti,
      signatureBase: result.signatureBase,
      ...(reservation !== undefined ? { released: reservation.amount } : {}),
    });
  }

  const amounts: { consumed?: Money; released?: Money } = {};
  if (reservation !== undefined) {
    if (response.status < 400) {
      await config.stores.ledger.consume(reservation.reservationId, now);
      await config.stores.audit.record({
        event: 'reservation.consumed',
        at: now,
        grant_id: grant.jti,
        reservation_id: reservation.reservationId,
        amount: reservation.amount.amount,
        currency: reservation.amount.currency,
      });
      amounts.consumed = reservation.amount;
    } else {
      await releaseReservation(config, reservation, grant.jti, now);
      amounts.released = reservation.amount;
      await restoreApproval(config, approval);
    }
  } else if (response.status >= 400) {
    await restoreApproval(config, approval);
  }

  const { token } = await issueReceipt(
    {
      issuer: config.issuer,
      audience: config.audience,
      grantId: grant.jti,
      signatureBase: result.signatureBase,
      decision: 'allowed',
      auditId,
      now,
      ...(Object.keys(amounts).length > 0 ? { amounts } : {}),
    },
    config.signingKey,
  );
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(response.headers ?? {}),
    [RECEIPT_HEADER]: token,
  };
  const finalResponse: HostResponse = { ...response, headers };

  if (mutating && idempotencyKey !== undefined) {
    try {
      await config.stores.idempotency.record(grant.jti, idempotencyKey, {
        requestDigest: operationDigestOf(req, grant.jti),
        outcome: { status: finalResponse.status, headers, body: finalResponse.body },
      });
    } catch (recordErr) {
      // The response is still returned: a failed outcome write weakens
      // dedupe rather than this request. It MUST be visible operationally
      // though: the orphaned pending claim would answer in_flight to every
      // retry until the site's claim TTL reclaims it. Audit is best-effort
      // for the same reason.
      try {
        await config.stores.audit.record({
          event: 'idempotency.record_failed',
          at: config.clock.now(),
          grant_id: grant.jti,
          detail: {
            key: idempotencyKey,
            error: recordErr instanceof Error ? recordErr.message : String(recordErr),
          },
        });
      } catch {
        // Audit sink failing too cannot change the response.
      }
    }
  }
  return finalResponse;
}

/**
 * Queues a verified request as a pending action and renders the `202`
 * response (spec section 12.5): a structured `pending_action` body, a
 * `pending` receipt bound to the original signature base, and (when the
 * request carried an idempotency key) a stored outcome so byte-identical
 * retries replay the queued answer instead of queueing again.
 */
async function queueActionResponse(
  route: RouteProtection,
  config: ResolvedServerConfig,
  req: HostRequest,
  result: RequestVerificationResult,
  grantId: string,
  auditId: string,
  dedupe: { mutating: boolean; idempotencyKey?: string },
): Promise<HostResponse> {
  let queued: { record: PendingActionRecord; fresh: boolean };
  try {
    queued = await queuePendingAction({ route, req, grant: result.grant, result }, config);
  } catch (err) {
    return denialResponse(err, req, config, {
      grantId,
      signatureBase: result.signatureBase,
    });
  }
  const record = queued.record;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  try {
    const { token } = await issueReceipt(
      {
        issuer: config.issuer,
        audience: config.audience,
        grantId,
        signatureBase: result.signatureBase,
        decision: 'pending',
        code: Codes.CONSTRAINT_APPROVAL_REQUIRED,
        auditId,
        now: config.clock.now(),
      },
      config.signingKey,
    );
    headers[RECEIPT_HEADER] = token;
  } catch {
    // A receipt that cannot be signed is omitted; the pending body stands.
  }
  const response: HostResponse = {
    status: 202,
    headers,
    body: {
      status: 'pending',
      pending_action: pendingActionView(record, config, route),
    },
  };
  if (dedupe.mutating && dedupe.idempotencyKey !== undefined) {
    try {
      await config.stores.idempotency.record(grantId, dedupe.idempotencyKey, {
        requestDigest: operationDigestOf(req, grantId),
        outcome: { status: response.status, headers, body: response.body },
      });
    } catch {
      // A failed outcome write weakens dedupe; the queued action still stands.
    }
  }
  return response;
}

/**
 * Executes an approved pending action through its registered handler
 * (spec section 12.5). Transitions are atomic at every step, so repeated
 * calls are idempotent: terminal records return as-is, and a concurrent
 * winner of the `approved -> executing` claim owns the run.
 *
 * Grant validity is enforced at execution, not just at queue time: a
 * revoked or expired grant cancels the action without running the handler.
 * Post-issuance scope, constraints, and the site policy are re-evaluated
 * against current state before the handler runs.
 */
export async function executePendingAction(
  id: string,
  config: ResolvedServerConfig,
): Promise<PendingActionRecord> {
  const store = config.stores.pendingActions;
  const record = await store.get(id);
  if (record === undefined) {
    throw new TrailGateError(Codes.ACTION_UNKNOWN, 'unknown pending action');
  }
  if (record.state !== 'approved') {
    if (record.state === 'pending' || record.state === 'executing') {
      throw new TrailGateError(
        Codes.ACTION_STATE_INVALID,
        `pending action is '${record.state}' and cannot execute`,
      );
    }
    return record;
  }
  const claimed = await store.transition(id, ['approved'], { state: 'executing' });
  if (claimed === undefined) {
    const current = await store.get(id);
    if (current === undefined) {
      throw new TrailGateError(Codes.ACTION_UNKNOWN, 'unknown pending action');
    }
    if (current.state === 'executing') {
      throw new TrailGateError(Codes.ACTION_STATE_INVALID, 'pending action is already executing');
    }
    return current;
  }
  const now = config.clock.now();
  await config.stores.audit.record({
    event: 'pending_action.executing',
    at: now,
    grant_id: claimed.grantId,
    action_request_id: claimed.id,
    ...(claimed.subject !== undefined ? { sub: claimed.subject } : {}),
  });

  const finish = async (
    state: 'succeeded' | 'failed' | 'cancelled' | 'expired',
    extra: Partial<PendingActionRecord>,
  ): Promise<PendingActionRecord> => {
    const done = await store.transition(claimed.id, ['executing'], { state, ...extra });
    const final = done ?? { ...claimed, state, ...extra };
    await config.stores.audit
      .record({
        event:
          state === 'succeeded'
            ? 'pending_action.succeeded'
            : state === 'failed'
              ? 'pending_action.failed'
              : state === 'expired'
                ? 'pending_action.expired'
                : 'pending_action.cancelled',
        at: config.clock.now(),
        grant_id: claimed.grantId,
        action_request_id: claimed.id,
        ...(extra.reason !== undefined ? { reason: extra.reason } : {}),
        ...(claimed.subject !== undefined ? { sub: claimed.subject } : {}),
      })
      .catch(() => undefined);
    return final;
  };

  // Integrity: the stored proposal must still digest to the request the
  // agent signed for; a store-level mutation makes the action fail closed.
  if (pendingActionDigest(claimed) !== claimed.requestDigest) {
    return finish('failed', { reason: 'stored proposal does not match its request digest' });
  }
  if (claimed.expiresAt <= now) {
    return finish('expired', { reason: 'pending action expired before execution' });
  }

  const grantRecord = await config.stores.grants.get(claimed.grantId);
  if (grantRecord === undefined) {
    return finish('cancelled', { reason: 'grant no longer exists' });
  }
  if (grantRecord.status === 'revoked') {
    return finish('cancelled', { reason: 'grant was revoked' });
  }
  if (grantRecord.expiresAt <= now) {
    return finish('cancelled', { reason: 'grant has expired' });
  }

  const scope = await config.stores.grants.currentScope(claimed.grantId);
  const effectivePermissions = [...(scope?.permissions ?? claimed.scopePermissions)];
  const effectiveResources = [...(scope?.resources ?? claimed.scopeResources)];
  const effectiveConstraints = [...(scope?.constraints ?? claimed.scopeConstraints)];

  const context: VerifiedRequestContext = {
    grantId: claimed.grantId,
    permissions: effectivePermissions,
    resources: effectiveResources,
    constraints: effectiveConstraints,
    method: claimed.method,
    url: claimed.url,
    requestDigest: claimed.requestDigest,
    ...(claimed.subject !== undefined ? { subject: claimed.subject } : {}),
  };

  try {
    assertPermissionGranted(effectivePermissions, claimed.permission);
    if (claimed.resource !== undefined) {
      if (config.resourceOwners === undefined) {
        throw new TrailGateError(
          Codes.INTERNAL_UNAVAILABLE,
          'resource ownership cannot be checked',
        );
      }
      await assertResourceAllowed(
        effectiveResources,
        claimed.resource,
        config.resourceOwners,
        claimed.subject,
      );
    }
    await evaluateConstraints(effectiveConstraints, {
      grantId: claimed.grantId,
      now,
      operationDigest: claimed.requestDigest,
      skipApprovalThreshold: true,
      ...(claimed.amount !== undefined ? { requestAmount: claimed.amount } : {}),
      ledger: config.stores.ledger,
      rateLimiter: config.stores.rateLimiter,
    });
    if (config.policy !== undefined) {
      // 'require_approval' is satisfied: the recorded human decision on this
      // pending action IS the approval. Only an outright denial still stops
      // execution.
      const decision = await config.policy.authorize(context);
      if (decision === 'deny') {
        throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'site policy denied the request');
      }
    }
  } catch (err) {
    return finish('failed', {
      reason: isTrailGateError(err) ? `${err.code}: ${err.message}` : 'execution checks failed',
    });
  }

  const entry = config.actionHandlers.get(claimed.actionId);
  if (entry === undefined || config.ambiguousActionKeys.has(claimed.actionId)) {
    return finish('failed', { reason: 'action handler is not registered or is ambiguous' });
  }

  const grant: GrantPayload = {
    iss: config.issuer,
    aud: config.audience,
    iat: grantRecord.issuedAt,
    exp: grantRecord.expiresAt,
    jti: grantRecord.jti,
    cnf: { jkt: claimed.agentJkt },
    tg: {
      version: '0.1',
      permissions: effectivePermissions,
      resources: effectiveResources,
      constraints: effectiveConstraints,
      request_id: grantRecord.requestId,
    },
    ...(claimed.subject !== undefined ? { sub: claimed.subject } : {}),
  };
  const synthetic: RequestVerificationResult = {
    grant,
    requestDigest: claimed.requestDigest,
    operationDigest: claimed.requestDigest,
    signatureBase: claimed.signatureBase,
    idempotentReplay: false,
    context,
    ...(claimed.amount !== undefined ? { requestAmount: claimed.amount } : {}),
    ...(claimed.resource !== undefined ? { touchedResource: claimed.resource } : {}),
  };

  const response = await runVerifiedOperation(
    entry.route,
    entry.handler,
    config,
    pendingActionRequest(claimed),
    synthetic,
    claimed,
  );

  const executedAt = config.clock.now();
  const outcome: StoredOutcome = {
    status: response.status,
    ...(response.headers !== undefined ? { headers: response.headers } : {}),
    ...(response.body !== undefined ? { body: response.body } : {}),
  };
  if (response.status < 400) {
    return finish('succeeded', { executedAt, outcome });
  }
  return finish('failed', {
    executedAt,
    outcome,
    reason: `handler responded with status ${response.status}`,
  });
}

/**
 * True when the grant's `approval_threshold` constraints require a human
 * approval for this request amount (spec section 9.2): any matching-currency
 * threshold below the amount.
 */
function needsApproval(grant: GrantPayload, amount: Money): boolean {
  return grant.tg.constraints.some((c) => {
    if (c.type !== 'approval_threshold') {
      return false;
    }
    const p = c.params as Partial<Money> | undefined;
    return (
      p !== undefined &&
      p.currency === amount.currency &&
      typeof p.amount === 'number' &&
      amount.amount > p.amount
    );
  });
}

/**
 * Returns a consumed approval to `approved` when the operation it authorized
 * failed to execute, so the human decision survives a retry (spec 12.4).
 */
async function restoreApproval(
  config: ResolvedServerConfig,
  approval: RequestApprovalRecord | undefined,
): Promise<void> {
  if (approval === undefined) {
    return;
  }
  try {
    await config.stores.approvals.restore(approval.id, config.clock.now());
  } catch {
    // The approval simply stays consumed; a retry issues a fresh request.
  }
}

/**
 * Denial for `tg.constraint.approval_required`: issues (or returns the live)
 * pending approval record so the agent can hand the user a concrete URL to
 * decide. When the approval store is unavailable the typed code alone still
 * answers correctly, just without a URL.
 */
async function approvalRequiredResponse(
  err: TrailGateError,
  req: HostRequest,
  config: ResolvedServerConfig,
  basis: { grantId?: string; signatureBase?: string } = {},
): Promise<HostResponse> {
  const detail = { ...(err.detail ?? {}) };
  const grantId = basis.grantId ?? (detail.grant_id as string | undefined);
  const amount = detail.amount as Money | undefined;
  if (grantId !== undefined && amount !== undefined) {
    try {
      const issued = await issueRequestApproval(
        {
          grantId,
          operationDigest: operationDigestOf(req, grantId),
          amount,
        },
        config,
      );
      detail.approval_id = issued.record.id;
      detail.approval_url = issued.approvalUrl;
    } catch {
      // The typed code remains the decision; the URL is best-effort.
    }
  }
  return denialResponse(new TrailGateError(err.code, err.message, detail), req, config, basis);
}

async function releaseReservation(
  config: ResolvedServerConfig,
  reservation: Reservation,
  grantId: string,
  now: number,
): Promise<void> {
  await config.stores.ledger.release(reservation.reservationId, now);
  await config.stores.audit.record({
    event: 'reservation.released',
    at: now,
    grant_id: grantId,
    reservation_id: reservation.reservationId,
    amount: reservation.amount.amount,
    currency: reservation.amount.currency,
  });
}
