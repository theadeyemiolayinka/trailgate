import type { RequestApprovalRecord } from '@trailgate/server';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

/**
 * Human decision surface for `approval_threshold` (spec section 12.4). Shows
 * exactly which operation the agent wants the user to authorize: the charge
 * amount and the operation fingerprint it is bound to. Only the grant
 * subject reaches this page with a pending record (routes guard it), and
 * the form posts through the same login + CSRF path as grant consent.
 */
export function renderRequestApproval(
  ctx: RenderCtx,
  view: { record: RequestApprovalRecord; grantJti: string },
): string {
  const { record, grantJti } = view;
  const decided = record.state !== 'pending';
  const expired = record.expiresAt <= Math.floor(Date.now() / 1000);

  const decideBlock = decided
    ? `<div class="consent-term"><p>This approval has already been decided: ${statusBadge(record.state)}</p>
        <p style="margin:0"><a class="button button-secondary" href="/account/connections">View agent connections</a></p></div>`
    : expired
      ? `<div class="consent-term"><p style="margin:0">This approval request expired at ${esc(formatTime(record.expiresAt))}. The agent must ask again.</p></div>`
      : `<form method="post" action="/tg/request-approval/decide">
        ${csrfField(ctx.session?.csrfToken)}
        <input type="hidden" name="approval_id" value="${esc(record.id)}">
        <div class="consent-actions">
          <button class="button" type="submit" name="decision" value="approve">Approve this charge once</button>
          <button class="button button-secondary" type="submit" name="decision" value="deny">Deny</button>
        </div>
      </form>`;

  return `
<div class="consent-frame">
  <div class="consent-agent">
    <div class="consent-agent-mark" aria-hidden="true">A</div>
    <div>
      <h1>An agent needs your approval for one charge</h1>
      <p class="muted" style="margin:0">Signed in as ${esc(ctx.user?.name ?? '')} (${esc(ctx.user?.email ?? '')})</p>
    </div>
  </div>

  <div class="consent-terms">
    <div class="consent-term consent-summary">
      <h3>At a glance</h3>
      <p>An agent operating under one of your grants wants to charge <strong>${esc(formatMoneyWithCurrency(record.amount))}</strong> from your simulated wallet. Approving authorizes this exact charge once.</p>
    </div>
    <div class="consent-term panel-sunken">
      <h3>What is being asked</h3>
      <dl class="dl">
        <dt>Charge</dt><dd><strong>${esc(formatMoneyWithCurrency(record.amount))}</strong></dd>
        <dt>Grant</dt><dd><span class="mono-id">${esc(grantJti)}</span></dd>
        <dt>Operation</dt><dd><span class="mono-id">${esc(record.operationDigest)}</span></dd>
        <dt>Expires</dt><dd>${esc(formatTime(record.expiresAt))}</dd>
      </dl>
      <p class="faint" style="margin:0">The charge exceeds the approval threshold on this grant. Your approval is bound to this exact operation: it cannot be reused for a different request, and it is consumed the moment the charge executes once.</p>
    </div>
    <div class="consent-term">
      <h3>If you deny</h3>
      <p>The agent's request stays denied. It may ask again, which creates a new approval request for you to decide.</p>
    </div>
  </div>

  ${decideBlock}
</div>`;
}
