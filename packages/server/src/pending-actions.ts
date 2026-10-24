import type { GrantPayload, Money, RequestVerificationResult } from '@trailgate/core';
import { Codes, getHeader, operationDigestOf, TrailGateError } from '@trailgate/core';
import type { ResolvedServerConfig } from './config.ts';
import { randomId } from './ids.ts';
import type { PendingActionRecord, PendingActionState } from './ports.ts';
import type { HostRequest, RouteProtection, SelectorContext } from './types.ts';

/**
 * Pending actions (spec section 12.5): durable, human-decided proposals for
 * approval-gated routes. A submission stores the exact operation the agent
 * signed for — method, URL, body bytes, resolved resource and amount — and
 * answers `202` with a structured `pending_action` body. Nothing executes
 * until the site user approves, and approval replays the stored proposal
 * through the registered handler (see `executePendingAction` in
 * enforcement.ts), never through stored credentials or arbitrary HTTP.
 */

/** JSON view of a pending action returned to agents and rendered for users. */
export interface PendingActionView {
  id: string;
  /** Registered action id (the discovery `actions[].id`). */
  action: string;
  status: PendingActionState;
  method: string;
  url: string;
  permission: string;
  resource?: string;
  amount?: Money;
  /** Human-readable description of the proposed effect. */
  summary: string;
  detail?: Record<string, unknown>;
  request_digest: string;
  grant_id: string;
  created_at: number;
  expires_at: number;
  decided_at?: number;
  decided_by?: string;
  reason?: string;
  executed_at?: number;
  /** The executed handler's response, present on terminal records. */
  result?: { status: number; body?: unknown };
  /** Signed `GET` endpoint the agent polls for this action. */
  status_url: string;
  /** Human-facing page where the site user reviews and decides. */
  review_url: string;
}

export function pendingActionStatusUrl(config: ResolvedServerConfig, id: string): string {
  return `${config.issuer}${config.paths.actionStatus}/${id}`;
}

export function pendingActionReviewUrl(
  config: ResolvedServerConfig,
  id: string,
  route?: RouteProtection,
): string {
  const base = route?.reviewPath ?? config.pendingActionReviewPath;
  return `${config.issuer}${base}/${id}`;
}

export function pendingActionView(
  record: PendingActionRecord,
  config: ResolvedServerConfig,
  route?: RouteProtection,
): PendingActionView {
  const view: PendingActionView = {
    id: record.id,
    action: record.actionId,
    status: record.state,
    method: record.method,
    url: record.url,
    permission: record.permission,
    summary: record.summary,
    request_digest: record.requestDigest,
    grant_id: record.grantId,
    created_at: record.createdAt,
    expires_at: record.expiresAt,
    status_url: pendingActionStatusUrl(config, record.id),
    review_url: pendingActionReviewUrl(config, record.id, route),
  };
  if (record.resource !== undefined) {
    view.resource = record.resource;
  }
  if (record.amount !== undefined) {
    view.amount = record.amount;
  }
  if (record.detail !== undefined) {
    view.detail = record.detail;
  }
  if (record.decidedAt !== undefined) {
    view.decided_at = record.decidedAt;
  }
  if (record.decidedBy !== undefined) {
    view.decided_by = record.decidedBy;
  }
  if (record.reason !== undefined) {
    view.reason = record.reason;
  }
  if (record.executedAt !== undefined) {
    view.executed_at = record.executedAt;
  }
  if (record.outcome !== undefined) {
    view.result = { status: record.outcome.status, body: record.outcome.body };
  }
  return view;
}

export interface QueuePendingActionInput {
  route: RouteProtection;
  req: HostRequest;
  grant: GrantPayload;
  result: RequestVerificationResult;
}

/**
 * Queues the verified request as a pending action and returns the stored
 * record. A byte-identical proposal that is still open returns the existing
 * record (`fresh: false`) rather than a duplicate — the store enforces that
 * atomically on `(grantId, requestDigest)`.
 */
export async function queuePendingAction(
  input: QueuePendingActionInput,
  config: ResolvedServerConfig,
): Promise<{ record: PendingActionRecord; fresh: boolean }> {
  const { route, req, grant, result } = input;
  // The executor key is the advertised action id, else the permission for
  // grants whose require_approval constraint queued a non-advertised route.
  const actionId = route.action?.id ?? route.permission;
  if (config.ambiguousActionKeys.has(actionId)) {
    throw new TrailGateError(
      Codes.INTERNAL_ERROR,
      `action key '${actionId}' maps to more than one route; approval execution would be ambiguous`,
    );
  }
  const now = config.clock.now();
  const open = await config.stores.pendingActions.countOpenByGrant(grant.jti);
  if (open >= config.maxPendingActionsPerGrant) {
    throw new TrailGateError(
      Codes.REQUEST_RATE_LIMITED,
      'too many pending actions under this grant',
      { limit: config.maxPendingActionsPerGrant },
    );
  }
  const selectorCtx: SelectorContext = {
    grant,
    ...(grant.sub !== undefined ? { subject: grant.sub } : {}),
  };
  const described = route.describe?.(req, selectorCtx) ?? {
    summary: `${req.method.toUpperCase()} ${new URL(req.url).pathname}`,
  };
  const contentDigest = getHeader(req, 'content-digest') ?? '';
  const contentType = getHeader(req, 'content-type');
  const record: PendingActionRecord = {
    id: randomId('pact'),
    grantId: grant.jti,
    agentJkt: grant.cnf.jkt,
    actionId,
    permission: route.permission,
    scopePermissions: [...result.context.permissions],
    scopeResources: [...result.context.resources],
    scopeConstraints: [...result.context.constraints],
    method: req.method.toUpperCase(),
    url: req.url,
    signatureBase: result.signatureBase,
    requestDigest: result.operationDigest,
    contentDigest,
    summary: described.summary,
    state: 'pending',
    createdAt: now,
    expiresAt: now + config.pendingActionTtlSeconds,
    ...(grant.sub !== undefined ? { subject: grant.sub } : {}),
    ...(req.body !== undefined
      ? {
          body: typeof req.body === 'string' ? req.body : new TextDecoder().decode(req.body),
        }
      : {}),
    ...(contentType !== undefined ? { contentType } : {}),
    ...(result.touchedResource !== undefined ? { resource: result.touchedResource } : {}),
    ...(result.requestAmount !== undefined ? { amount: result.requestAmount } : {}),
    ...(described.detail !== undefined ? { detail: described.detail } : {}),
  };
  const inserted = await config.stores.pendingActions.insert(record);
  if (inserted.kind === 'existing') {
    return { record: inserted.record, fresh: false };
  }
  await config.stores.audit.record({
    event: 'pending_action.queued',
    at: now,
    grant_id: grant.jti,
    request_digest: record.requestDigest,
    action_request_id: record.id,
    ...(record.subject !== undefined ? { sub: record.subject } : {}),
    detail: { action_id: record.actionId, method: record.method, url: record.url },
  });
  return { record, fresh: true };
}

/**
 * `GET <endpoints.action_status>/{id}` (spec section 12.5). The request
 * verifies as an ordinary signed request; the grant must be the one the
 * action was proposed under — another grant's view of the action is `404`.
 */
export async function actionStatus(
  actionId: string,
  grant: GrantPayload,
  config: ResolvedServerConfig,
): Promise<PendingActionRecord> {
  const record = await config.stores.pendingActions.get(actionId);
  if (record === undefined || record.grantId !== grant.jti) {
    throw new TrailGateError(Codes.ACTION_UNKNOWN, 'unknown pending action');
  }
  return record;
}

export interface DecidePendingActionInput {
  id: string;
  decision: 'approve' | 'reject';
  /** The authenticated site user deciding; must map to the action's subject. */
  siteUserId: string;
  /** Optional human-supplied reason, stored verbatim for the agent to read. */
  reason?: string;
}

/**
 * Records a human decision on a pending action (spec section 12.5). Only
 * `pending` records are decidable and only the grant subject may decide;
 * anything else is `tg.action.state_invalid` / `tg.action.unknown`. An
 * approve decision transitions `pending -> approved` atomically; the caller
 * (the host or `decidePendingAction`'s executor wiring) then invokes
 * `executePendingAction`. Expired records are not decidable: the decision
 * attempt transitions them to `expired` first.
 */
export async function decidePendingAction(
  input: DecidePendingActionInput,
  config: ResolvedServerConfig,
): Promise<PendingActionRecord> {
  const record = await config.stores.pendingActions.get(input.id);
  const subject = config.subjectFor(input.siteUserId);
  if (record === undefined || record.subject !== subject) {
    throw new TrailGateError(Codes.ACTION_UNKNOWN, 'unknown pending action');
  }
  const now = config.clock.now();
  if (record.expiresAt <= now && (record.state === 'pending' || record.state === 'approved')) {
    const expired = await config.stores.pendingActions.transition(
      record.id,
      ['pending', 'approved'],
      { state: 'expired' },
    );
    if (expired !== undefined) {
      await config.stores.audit.record({
        event: 'pending_action.expired',
        at: now,
        grant_id: record.grantId,
        action_request_id: record.id,
        ...(record.subject !== undefined ? { sub: record.subject } : {}),
      });
      throw new TrailGateError(Codes.ACTION_STATE_INVALID, 'pending action has expired');
    }
  }
  const decided = await config.stores.pendingActions.transition(record.id, ['pending'], {
    state: input.decision === 'approve' ? 'approved' : 'rejected',
    decidedAt: now,
    decidedBy: input.siteUserId,
    ...(input.reason !== undefined ? { reason: input.reason } : {}),
  });
  if (decided === undefined) {
    throw new TrailGateError(
      Codes.ACTION_STATE_INVALID,
      `pending action is '${record.state}' and cannot be decided`,
    );
  }
  await config.stores.audit.record({
    event: 'pending_action.decided',
    at: now,
    grant_id: record.grantId,
    action_request_id: record.id,
    actor: input.siteUserId,
    decision: decided.state,
    ...(record.subject !== undefined ? { sub: record.subject } : {}),
  });
  return decided;
}

/**
 * Cancels every open pending action under a grant (spec section 12.5):
 * called when the grant is revoked so queued proposals cannot execute later.
 * `executing` records are left for their in-flight run to finish; the run's
 * own grant check decides the outcome it records.
 */
export async function cancelPendingActionsForGrant(
  grantId: string,
  reason: string,
  config: ResolvedServerConfig,
): Promise<number> {
  const open = await config.stores.pendingActions.listOpenByGrant(grantId);
  let cancelled = 0;
  for (const record of open) {
    const transitioned = await config.stores.pendingActions.transition(
      record.id,
      ['pending', 'approved'],
      { state: 'cancelled', reason },
    );
    if (transitioned !== undefined) {
      cancelled += 1;
      await config.stores.audit.record({
        event: 'pending_action.cancelled',
        at: config.clock.now(),
        grant_id: grantId,
        action_request_id: record.id,
        reason,
        ...(record.subject !== undefined ? { sub: record.subject } : {}),
      });
    }
  }
  return cancelled;
}

/** Reconstructs the HostRequest an approved pending action replays as. */
export function pendingActionRequest(record: PendingActionRecord): HostRequest {
  const headers: Record<string, string> = { 'content-digest': record.contentDigest };
  if (record.contentType !== undefined) {
    headers['content-type'] = record.contentType;
  }
  const req: HostRequest = { method: record.method, url: record.url, headers };
  if (record.body !== undefined) {
    req.body = record.body;
  }
  return req;
}

/** The operation digest a replayed request must still produce (guard check). */
export function pendingActionDigest(record: PendingActionRecord): string {
  return operationDigestOf(pendingActionRequest(record), record.grantId);
}
