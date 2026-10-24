import type { Constraint, DiscoveryDocument } from '@trailgate/core';
import { Codes, isTrailGateError, TrailGateError, toErrorResponse } from '@trailgate/core';
import { decideRequestApproval } from './approvals.ts';
import type { ResolvedServerConfig, TrailGateServerOptions } from './config.ts';
import { resolveConfig } from './config.ts';
import { buildDiscoveryDocument, buildDiscoveryResponse } from './discovery.ts';
import {
  assertRequestLimits,
  createProtectedHandler,
  executePendingAction,
  verifyAgentRequest,
} from './enforcement.ts';
import type { ConsentNarrow } from './lifecycle.ts';
import {
  decideConsent,
  getConsentView,
  grantStatus,
  handleRevocationRequest,
  redeemGrant,
  revokeGrant,
  submitGrantRequest,
  updateGrantScope,
} from './lifecycle.ts';
import { actionStatus, decidePendingAction, pendingActionView } from './pending-actions.ts';
import type { IssuedGrantRecord, PendingActionRecord, RequestApprovalRecord } from './ports.ts';
import type { SiteSigningKey, SiteSigningKeyInput } from './signing.ts';
import { siteSigningKey } from './signing.ts';
import type {
  ConsentDecision,
  ConsentOutcome,
  ConsentView,
  GrantStatusResponse,
  HostRequest,
  HostResponse,
  ProtectedHandler,
  RouteProtection,
} from './types.ts';

/**
 * The configured TrailGate surface for one site. Returned values are
 * framework-neutral `HostResponse`s; the host translates them into its own
 * framework's response type.
 */
export interface TrailGateServer {
  readonly config: ResolvedServerConfig;
  /** Discovery document for `GET /.well-known/trailgate`. Recomputed per call. */
  discoveryDocument(): DiscoveryDocument;
  /**
   * `GET /.well-known/trailgate` response with `trailgate-discovery-signature`
   * headers (spec section 5.5). The body is pre-serialized; hosts MUST send
   * it verbatim for signatures to verify.
   */
  handleDiscovery(): Promise<HostResponse>;
  /** `POST <endpoints.grant_request>` (spec section 10.2). */
  handleGrantRequest(req: HostRequest): Promise<HostResponse>;
  /** Verbatim terms for the host's consent page (spec section 10.3). */
  getConsent(requestId: string): Promise<ConsentView | undefined>;
  /**
   * Records the user's decision after the host's own authentication
   * (spec section 10.3). `siteUserId` is required for approvals.
   */
  decideConsent(
    requestId: string,
    decision: ConsentDecision,
    siteUserId?: string,
    narrow?: ConsentNarrow,
  ): Promise<ConsentOutcome>;
  /** `POST <endpoints.grant_redemption>` (spec section 10.4). */
  handleRedemption(req: HostRequest): Promise<HostResponse>;
  /** `GET <endpoints.grant_status>` (spec section 10.5). */
  handleStatus(req: HostRequest): Promise<HostResponse>;
  /**
   * `POST <endpoints.grant_revocation>` (spec section 13). Agent
   * self-revocation verifies as a protected request; other callers need a
   * configured `revocationAuthorizer`.
   */
  handleRevocation(req: HostRequest): Promise<HostResponse>;
  /** Host-initiated revocation from authenticated site surfaces (spec section 13). */
  revokeGrant(jti: string, input: { reason: string; actor: string }): Promise<void>;
  /**
   * Host-initiated post-issuance scope change (spec section 13): replaces
   * the grant's effective permissions (and optionally resources and
   * constraints) with any set inside the site's advertised vocabulary and
   * registered constraint types. Takes effect at the next enforcement pass
   * without reissuing a JWT.
   */
  updateGrantScope(
    jti: string,
    input: {
      permissions: string[];
      resources?: string[];
      constraints?: Constraint[];
      actor: string;
    },
  ): Promise<IssuedGrantRecord>;
  /**
   * Records the user's decision on a per-request `approval_threshold`
   * approval (spec section 12.4). Only the grant subject may decide.
   */
  decideRequestApproval(
    approvalId: string,
    decision: 'approve' | 'deny',
    siteUserId?: string,
  ): Promise<RequestApprovalRecord>;
  /**
   * `GET <endpoints.action_status>/{id}` (spec section 12.5): a signed
   * request under the proposing grant returns the action's current state
   * and, on terminal states, the recorded outcome.
   */
  handleActionStatus(req: HostRequest): Promise<HostResponse>;
  /**
   * Records a human decision on a pending action (spec section 12.5). Only
   * the grant subject may decide. An approve decision executes the stored
   * proposal synchronously through the registered handler; the returned
   * record carries the final state.
   */
  decidePendingAction(
    actionId: string,
    decision: 'approve' | 'reject',
    siteUserId: string,
    reason?: string,
  ): Promise<PendingActionRecord>;
  /** All pending actions under the site user's grants, newest first. */
  listPendingActions(siteUserId: string): Promise<PendingActionRecord[]>;
  /**
   * Rotates the site signing key (spec section 13.4). The new key becomes the
   * signing key and is published first in `signing_keys`; retired keys remain
   * configured so outstanding grants still verify until they expire. Emits a
   * `key.rotated` audit event.
   */
  rotateSigningKey(input: SiteSigningKeyInput): Promise<SiteSigningKey>;
  /**
   * Enforces the spec section 11 pipeline around a host handler. The returned
   * function yields complete `HostResponse`s (denials and receipts included)
   * and never throws for protocol-level failures.
   */
  protect(
    route: RouteProtection,
    handler: ProtectedHandler,
  ): (req: HostRequest) => Promise<HostResponse>;
}

function json(status: number, body: unknown): HostResponse {
  return { status, headers: { 'content-type': 'application/json' }, body };
}

function errorResponse(err: unknown): HostResponse {
  const error = isTrailGateError(err)
    ? err
    : new TrailGateError(Codes.INTERNAL_ERROR, 'internal error');
  return json(error.httpStatus, toErrorResponse(error));
}

/** Composes storage ports, lifecycle flows, and enforcement into one surface. */
export function createTrailGateServer(options: TrailGateServerOptions): TrailGateServer {
  const config = resolveConfig(options);
  return {
    config,
    discoveryDocument: () => buildDiscoveryDocument(config),
    handleDiscovery: () => buildDiscoveryResponse(config),
    handleGrantRequest: async (req) => {
      try {
        assertRequestLimits(req, config);
        return json(201, await submitGrantRequest(parseJson(req.body), config));
      } catch (err) {
        return errorResponse(err);
      }
    },
    getConsent: (requestId) => getConsentView(requestId, config),
    decideConsent: (requestId, decision, siteUserId, narrow) =>
      decideConsent(requestId, decision, siteUserId, config, narrow),
    handleRedemption: async (req) => {
      try {
        assertRequestLimits(req, config);
        const body = parseJson(req.body);
        return json(200, await redeemGrant(body, config));
      } catch (err) {
        return errorResponse(err);
      }
    },
    handleStatus: async (req) => {
      try {
        const params = new URL(req.url).searchParams;
        const query: { request_id?: string; grant_id?: string } = {};
        const requestId = params.get('request_id');
        const grantId = params.get('grant_id');
        if (requestId !== null) {
          query.request_id = requestId;
        }
        if (grantId !== null) {
          query.grant_id = grantId;
        }
        const status: GrantStatusResponse = await grantStatus(query, config);
        const response = json(200, status);
        response.headers = {
          ...response.headers,
          'cache-control': 'max-age=60', // spec section 13: at most 60s staleness
        };
        return response;
      } catch (err) {
        return errorResponse(err);
      }
    },
    handleRevocation: (req) =>
      handleRevocationRequest(req, config).catch((err) => errorResponse(err)),
    revokeGrant: (jti, input) => revokeGrant(jti, input, config),
    updateGrantScope: (jti, input) => updateGrantScope(jti, input, config),
    decideRequestApproval: (approvalId, decision, siteUserId) =>
      decideRequestApproval(approvalId, decision, siteUserId, config),
    handleActionStatus: async (req) => {
      try {
        assertRequestLimits(req, config);
        const prefix = `${config.paths.actionStatus}/`;
        const id = new URL(req.url).pathname.startsWith(prefix)
          ? new URL(req.url).pathname.slice(prefix.length)
          : '';
        if (id === '') {
          throw new TrailGateError(Codes.REQUEST_MALFORMED, 'missing pending action id');
        }
        const result = await verifyAgentRequest(req, config);
        const record = await actionStatus(id, result.grant, config);
        const route = config.actionHandlers.get(record.actionId)?.route;
        const response = json(200, {
          status: record.state,
          pending_action: pendingActionView(record, config, route),
        });
        response.headers = { ...response.headers, 'cache-control': 'no-store' };
        return response;
      } catch (err) {
        return errorResponse(err);
      }
    },
    decidePendingAction: async (actionId, decision, siteUserId, reason) => {
      const record = await decidePendingAction(
        {
          id: actionId,
          decision,
          siteUserId,
          ...(reason !== undefined ? { reason } : {}),
        },
        config,
      );
      if (record.state === 'approved') {
        return executePendingAction(record.id, config);
      }
      return record;
    },
    listPendingActions: (siteUserId) =>
      config.stores.pendingActions.listBySubject(config.subjectFor(siteUserId)),
    rotateSigningKey: async (input) => {
      const previous = config.signingKey;
      const next = siteSigningKey(input);
      config.signingKeys.unshift(next);
      config.signingKey = next;
      await config.stores.audit.record({
        event: 'key.rotated',
        at: config.clock.now(),
        old_jkt: previous.kid,
        new_jkt: next.kid,
      });
      return next;
    },
    protect: (route, handler) => createProtectedHandler(route, handler, config),
  };
}

function parseJson(body: HostRequest['body']): unknown {
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
