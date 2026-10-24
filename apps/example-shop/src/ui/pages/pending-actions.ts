import type { PendingActionRecord } from '@trailgate/server';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, emptyState, pageHead, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';

/**
 * Review surface for pending actions (spec section 12.5): the exact,
 * immutable proposal an agent queued. The page renders what the store
 * recorded at queue time — method, target, summary, parameters — and the
 * decide form only carries the action id; the stored proposal cannot be
 * edited through this surface.
 */
function describeDetail(detail: Record<string, unknown> | undefined): string {
  if (detail === undefined) {
    return '';
  }
  const items = Array.isArray(detail.items) ? detail.items : [];
  const lines = items
    .map((item) => {
      const i = item as Record<string, unknown>;
      return `<tr><td>${esc(String(i.name ?? i.sku ?? ''))}</td><td class="num">${esc(String(i.qty ?? ''))}</td><td class="num">${esc(typeof i.line_total === 'object' && i.line_total !== null ? formatMoneyWithCurrency(i.line_total as { amount: number; currency: string }) : '')}</td></tr>`;
    })
    .join('');
  const total = detail.total as { amount: number; currency: string } | undefined;
  const totalRow =
    total !== undefined
      ? `<tr><td><strong>Total</strong></td><td></td><td class="num"><strong>${esc(formatMoneyWithCurrency(total))}</strong></td></tr>`
      : '';
  if (lines === '' && totalRow === '') {
    return `<pre class="mono-id">${esc(JSON.stringify(detail, null, 2))}</pre>`;
  }
  return `<table class="table"><thead><tr><th>Item</th><th class="num">Qty</th><th class="num">Line total</th></tr></thead><tbody>${lines}${totalRow}</tbody></table>`;
}

export function renderPendingActions(records: PendingActionRecord[]): string {
  const rows = records
    .map((record) => {
      const amount = record.amount !== undefined ? formatMoneyWithCurrency(record.amount) : 'n/a';
      return `<tr>
        <td><a href="/account/approvals/${esc(record.id)}"><span class="mono-id">${esc(record.id)}</span></a></td>
        <td>${esc(record.actionId)}</td>
        <td>${esc(record.summary)}</td>
        <td class="num">${esc(amount)}</td>
        <td>${statusBadge(record.state)}</td>
        <td>${esc(formatTime(record.createdAt))}</td>
      </tr>`;
    })
    .join('');
  const table =
    records.length === 0
      ? emptyState(
          'No agent actions are waiting for your decision.',
          'Actions an agent proposes on an approval-gated endpoint appear here.',
        )
      : `<div class="table-wrap"><table class="table"><thead><tr><th>Action</th><th>Type</th><th>Proposal</th><th class="num">Amount</th><th>Status</th><th>Queued</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  return `
${pageHead(
    'Account',
    'Agent approvals',
    'Actions your agents proposed that need a human decision. Nothing listed here has executed yet; approving runs the exact proposal shown.',
  )}
<div class="account-grid">
  ${accountNav('approvals')}
  <div class="stack">
    <div class="panel">${table}</div>
  </div>
</div>`;
}

export function renderPendingAction(ctx: RenderCtx, record: PendingActionRecord): string {
  const expired = record.expiresAt <= Math.floor(Date.now() / 1000);
  const decided = record.state !== 'pending';

  const amountRow =
    record.amount !== undefined
      ? `<dt>Amount</dt><dd><strong>${esc(formatMoneyWithCurrency(record.amount))}</strong></dd>`
      : '';
  const resourceRow =
    record.resource !== undefined
      ? `<dt>Resource</dt><dd><span class="mono-id">${esc(record.resource)}</span></dd>`
      : '';
  const resultBlock =
    record.outcome !== undefined
      ? `<div class="consent-term panel-sunken">
        <h3>Execution result</h3>
        <dl class="dl">
          <dt>Executed</dt><dd>${esc(record.executedAt !== undefined ? formatTime(record.executedAt) : '')}</dd>
          <dt>Response</dt><dd><span class="mono-id">${esc(String(record.outcome.status))}</span></dd>
        </dl>
        <pre class="mono-id">${esc(JSON.stringify(record.outcome.body ?? null, null, 2))}</pre>
      </div>`
      : '';
  const reasonBlock =
    record.reason !== undefined
      ? `<div class="consent-term"><p>Reason: ${esc(record.reason)}</p></div>`
      : '';

  const decideBlock = decided
    ? `<div class="consent-term consent-decision"><h3>Decision recorded</h3>
        <p>This action has been decided: ${statusBadge(record.state)}</p>
        <p style="margin:0"><a class="button button-secondary" href="/account/approvals">Back to approvals</a></p></div>`
    : expired
      ? `<div class="consent-term consent-decision"><h3>Expired</h3><p style="margin:0">This proposal expired at ${esc(formatTime(record.expiresAt))}. The agent must submit it again.</p></div>`
      : `<form method="post" action="/account/approvals/decide" class="consent-term consent-decision">
        ${csrfField(ctx.session?.csrfToken)}
        <h3>Your decision</h3>
        <p class="muted">Approve runs this exact proposal once. Reject closes it without executing.</p>
        <input type="hidden" name="action_id" value="${esc(record.id)}">
        <div class="consent-actions">
          <button class="button" type="submit" name="decision" value="approve">Approve and execute</button>
          <button class="button button-secondary" type="submit" name="decision" value="reject">Reject</button>
        </div>
      </form>`;

  return `
${pageHead('Account', 'Agent approvals', 'Review the exact proposal the agent queued; approving runs it once.')}
<div class="account-grid">
  ${accountNav('approvals')}
  <div class="stack">
    <nav class="crumbs" aria-label="Breadcrumb"><a href="/account/approvals">Agent approvals</a><span class="crumb-sep">/</span>Proposed action</nav>
    <div class="consent-agent">
      <div class="consent-agent-mark" aria-hidden="true">A</div>
      <div>
        <h1>An agent proposed this action</h1>
        <p class="muted" style="margin:0">Signed in as ${esc(ctx.user?.name ?? '')} (${esc(ctx.user?.email ?? '')})</p>
      </div>
    </div>

    <div class="consent-terms" style="margin-bottom:0">
      <div class="consent-term consent-summary">
        <h3>At a glance</h3>
        <p>${esc(record.summary)}</p>
      </div>
      <div class="consent-term panel-sunken">
        <h3>Exactly what was proposed</h3>
        <dl class="dl">
          <dt>Action</dt><dd><span class="mono-id">${esc(record.actionId)}</span></dd>
          <dt>Request</dt><dd><span class="mono-id">${esc(record.method)} ${esc(record.url)}</span></dd>
          ${amountRow}
          ${resourceRow}
          <dt>Grant</dt><dd><span class="mono-id">${esc(record.grantId)}</span></dd>
          <dt>Operation digest</dt><dd><span class="mono-id">${esc(record.requestDigest)}</span></dd>
          <dt>Queued</dt><dd>${esc(formatTime(record.createdAt))}</dd>
          <dt>Decide by</dt><dd>${esc(formatTime(record.expiresAt))}</dd>
        </dl>
        ${describeDetail(record.detail)}
        <p class="faint" style="margin:0">Approving executes this exact proposal once through the site's own order and wallet handlers. The proposal cannot be edited; a changed request needs a new proposal.</p>
      </div>
      <div class="consent-term">
        <h3>If you reject</h3>
        <p>The action never executes. The agent sees the rejection and may submit a new proposal.</p>
      </div>
      ${resultBlock}
      ${reasonBlock}
      ${decideBlock}
    </div>
  </div>
</div>`;
}
