import { isTrailGateError } from '@trailgate/core';
import type { AccessCheck } from './access.ts';
import type { AgentClient } from './client.ts';
import type { SiteContext } from './discovery.ts';
import { isRetryableCode } from './errors.ts';
import type { ConsentSession } from './grants.ts';
import type { ProtectedResponse } from './request.ts';
import type { StoredGrantRecord } from './store.ts';

/**
 * Agent connection experience layer: the structured story a model runtime
 * tells the user, from URL to outcome, without inventing protocol states.
 *
 * Every stage returns typed data the runtime can narrate faithfully:
 * capabilities come from the validated discovery document, gaps come from
 * `AccessCheck`, consent is only ever "confirmed" after `awaitApproval` or
 * a validated callback plus redemption, and receipts are only "verified"
 * when `verifyReceiptHeader` actually passed. Nothing here states or
 * implies approval, access, or verification that did not happen.
 */

/** Plain-language capability summary for the "what can this site do" step. */
export function describeSite(site: SiteContext): Record<string, unknown> {
  return {
    issuer: site.issuer,
    protocolVersion: site.protocolVersion,
    permissions: site.document.permissions,
    constraintTypes: site.document.constraint_types,
    capabilities: site.document.capabilities ?? {},
  };
}

/** Why an action cannot proceed yet, in distinguishable terms. */
export function explainAccessCheck(check: AccessCheck): {
  status: AccessCheck['status'];
  summary: string;
} {
  switch (check.status) {
    case 'ready':
      return { status: check.status, summary: 'a usable grant and key exist locally' };
    case 'no_grant':
      return {
        status: check.status,
        summary: 'no grant is stored for this site; consent is required',
      };
    case 'insufficient_permission':
      return {
        status: check.status,
        summary: `the stored grant lacks permission: ${check.missing.join(', ')}`,
      };
    case 'expired':
      return {
        status: check.status,
        summary: 'the stored grant has expired; consent is required again',
      };
    case 'wrong_key':
      return {
        status: check.status,
        summary: 'the stored grant is bound to a key this runtime does not hold',
      };
    case 'revoked':
      return { status: check.status, summary: 'the site reports this grant revoked' };
    case 'unsupported_version':
      return {
        status: check.status,
        summary: `no shared protocol version (site: ${check.site.join(', ')})`,
      };
  }
}

/** Distinguishable failure of the discovery step itself. */
export type DiscoveryOutcome =
  | { status: 'supported'; site: SiteContext; capabilities: Record<string, unknown> }
  | { status: 'unsupported_version'; site: string[]; client: readonly string[]; summary: string }
  | { status: 'unavailable'; code: string; summary: string };

/**
 * Step 1-2: does the site do TrailGate, and what does it offer. Separates
 * "site is not a TrailGate site / document invalid" (`unavailable`,
 * `tg.discovery.invalid`) from "site exists but shares no version"
 * (`unsupported_version`, `tg.discovery.unsupported_version`).
 */
export async function inspectSite(client: AgentClient, target: string): Promise<DiscoveryOutcome> {
  try {
    const site = await client.discover(target);
    return { status: 'supported', site, capabilities: describeSite(site) };
  } catch (err) {
    if (isTrailGateError(err) && err.code === 'tg.discovery.unsupported_version') {
      const detail = (err.detail ?? {}) as { site?: string[]; client?: string[] };
      return {
        status: 'unsupported_version',
        site: detail.site ?? [],
        client: detail.client ?? [],
        summary: 'the site supports TrailGate but no shared protocol version exists',
      };
    }
    return {
      status: 'unavailable',
      code: isTrailGateError(err) ? err.code : 'agent.error',
      summary: 'the site does not present a valid TrailGate discovery document',
    };
  }
}

/**
 * Steps 3-5 narrated end to end: given a URL and an intended scope, either
 * a usable grant exists, or a consent session starts (or the check explains
 * why action is impossible). `consent_required` means a session was
 * STARTED, never that the user approved; only `awaitApproval` or a
 * validated callback plus `redeemGrant` confirms a decision.
 */
export type AccessPlan =
  | { status: 'ready'; grant: StoredGrantRecord }
  | {
      status: 'consent_required';
      session: ConsentSession;
      reason: ReturnType<typeof explainAccessCheck>;
    }
  | { status: 'blocked'; reason: ReturnType<typeof explainAccessCheck> };

export async function planAccess(
  client: AgentClient,
  target: string | SiteContext,
  scope: {
    permissions: string[];
    resources?: string[];
    constraints?: import('@trailgate/core').Constraint[];
  },
): Promise<AccessPlan> {
  const check = await client.checkAccess(target, { permissions: scope.permissions });
  if (check.status === 'ready') {
    return { status: 'ready', grant: check.grant };
  }
  const reason = explainAccessCheck(check);
  if (
    check.status === 'unsupported_version' ||
    check.status === 'wrong_key' ||
    check.status === 'revoked'
  ) {
    // Asking for consent again cannot fix these three.
    return { status: 'blocked', reason };
  }
  const session = await client.requestGrant(target, scope);
  return { status: 'consent_required', session, reason };
}

/** Step 7: the faithful outcome report for one protected request. */
export interface ActionReport {
  httpStatus: number;
  /** 'allowed' | 'denied' | 'indeterminate' */
  outcome: 'allowed' | 'denied' | 'indeterminate';
  /** The tg.* code when the site denied, so denials stay distinguishable. */
  code?: string;
  /** Retry guidance per spec/errors.md. */
  retryable: boolean;
  /** Receipt evidence: only 'verified' when verification actually passed. */
  receipt: 'verified' | 'unverified' | 'absent';
  auditId?: string;
  body?: unknown;
}

export function reportAction(res: ProtectedResponse): ActionReport {
  const report: ActionReport = {
    httpStatus: res.status,
    outcome: res.error !== undefined ? 'denied' : res.status < 400 ? 'allowed' : 'indeterminate',
    retryable: res.error !== undefined && isRetryableCode(res.error.code),
    receipt:
      res.receipt === undefined ? 'absent' : res.receipt.verified ? 'verified' : 'unverified',
  };
  if (res.error !== undefined) {
    report.code = res.error.code;
  }
  if (res.receipt?.verified === true) {
    report.auditId = res.receipt.payload.tg.audit_id;
  }
  return report;
}
