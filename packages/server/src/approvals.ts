import type { Money } from '@trailgate/core';
import { Codes, TrailGateError } from '@trailgate/core';
import type { ResolvedServerConfig } from './config.ts';
import { randomId } from './ids.ts';
import type { RequestApprovalRecord } from './ports.ts';

/**
 * Issues (or returns the live) pending approval for an operation that hit
 * `approval_threshold` (spec section 12.4). Called by the enforcement denial
 * path; the record binds to the operation digest so an approval can never
 * be swapped onto a different request.
 */
export async function issueRequestApproval(
  input: { grantId: string; operationDigest: string; amount: Money },
  config: ResolvedServerConfig,
): Promise<{ record: RequestApprovalRecord; approvalUrl: string }> {
  const now = config.clock.now();
  const record = await config.stores.approvals.requestApproval({
    id: randomId('rpa'),
    grantId: input.grantId,
    operationDigest: input.operationDigest,
    amount: input.amount,
    now,
    ttlSeconds: config.requestApprovalTtlSeconds,
  });
  await config.stores.audit.record({
    event: 'request_approval.requested',
    at: now,
    grant_id: input.grantId,
    detail: {
      approval_id: record.id,
      amount: input.amount.amount,
      currency: input.amount.currency,
      state: record.state,
    },
  });
  return {
    record,
    approvalUrl: `${config.issuer}${config.paths.requestApproval}?id=${encodeURIComponent(record.id)}`,
  };
}

/**
 * Records the user's per-request decision on an `approval_threshold`
 * operation. Only the user context the grant was issued under may decide,
 * and only while the record is pending and unexpired.
 */
export async function decideRequestApproval(
  approvalId: string,
  decision: 'approve' | 'deny',
  siteUserId: string | undefined,
  config: ResolvedServerConfig,
): Promise<RequestApprovalRecord> {
  if (siteUserId === undefined || siteUserId === '') {
    throw new TrailGateError(
      Codes.AUTHORIZATION_DENIED,
      'an authenticated user is required to decide a request approval',
    );
  }
  const record = await config.stores.approvals.get(approvalId);
  if (record === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'unknown approval id');
  }
  const now = config.clock.now();
  if (record.expiresAt <= now) {
    throw new TrailGateError(Codes.GRANT_EXPIRED, 'request approval has expired');
  }
  const grant = await config.stores.grants.get(record.grantId);
  const subject = config.subjectFor(siteUserId);
  if (grant === undefined || grant.subject !== subject) {
    throw new TrailGateError(
      Codes.AUTHORIZATION_DENIED,
      'only the user the grant was issued under may decide this approval',
    );
  }
  const decided = await config.stores.approvals.decide(approvalId, decision, now);
  if (decided === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request approval already decided');
  }
  await config.stores.audit.record({
    event: 'request_approval.decided',
    at: now,
    grant_id: record.grantId,
    decision: decision === 'approve' ? 'approved' : 'denied',
    sub: subject,
    detail: { approval_id: approvalId },
  });
  return decided;
}
