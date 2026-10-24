import type { AuditEvent, Constraint, Money } from '@trailgate/core';
import { requireApprovalPermissions } from '@trailgate/core';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { PERMISSIONS } from '../../tg/vocabulary.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, emptyState, pageHead, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';
import { describeConstraint, type PermissionMode, permModeControl } from './consent.ts';

export interface GrantRequestView {
  requestId: string;
  createdAt: number;
  expiresAt: number;
  status: string;
  agentJkt: string;
  permissions: string[];
  grantId?: string;
}

export interface IssuedGrantView {
  jti: string;
  agentJkt: string;
  issuedAt: number;
  expiresAt: number;
  status: 'active' | 'revoked';
  /** Permissions signed into the grant; the ceiling narrowing can never exceed. */
  issuedPermissions: string[];
  /** Currently effective permissions (issued, or narrowed on this page). */
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  revokedAt?: number;
  revocationReason?: string;
  revocationActor?: string;
}

interface SiteCaps {
  maxCharge: Money;
  maxGrantBudget: Money;
}

/**
 * Post-issuance scope control: the user ticks what the agent may do and
 * sets its spending limits; the site applies both in place, covering every
 * permission the shop advertises - both removing and adding. Only the site
 * can change a grant's scope; the agent can never modify its own.
 */
function permEditor(ctx: RenderCtx, grant: IssuedGrantView, caps: SiteCaps): string {
  if (grant.status !== 'active') {
    return '';
  }
  const effective = new Set(grant.permissions);
  const approvalSet = new Set(grant.constraints.flatMap((c) => requireApprovalPermissions(c)));
  const modeOf = (p: string): PermissionMode =>
    !effective.has(p) ? 'deny' : approvalSet.has(p) ? 'approval' : 'allow';
  const moneyParam = (type: string): Money | undefined => {
    const found = grant.constraints.find((c) => c.type === type);
    return found?.params as Money | undefined;
  };
  const dollars = (m: Money): string => (m.amount / 100).toFixed(2);
  const maxCharge = moneyParam('max_amount') ?? caps.maxCharge;
  const budget = moneyParam('cumulative_budget') ?? caps.maxGrantBudget;
  return `<details class="perm-editor">
            <summary>Change permissions and limits</summary>
            <p class="muted">Tick what this agent may do and set its spending limits. Changes apply to its next request; to remove all access, revoke the connection.</p>
            <form method="post" action="/account/connections/${esc(grant.jti)}/scope">
              ${csrfField(ctx.session?.csrfToken)}
              <div class="scope-group">
                <h4 class="scope-group-title">Permissions</h4>
                <div class="consent-perms">${PERMISSIONS.map((p) =>
                  permModeControl(p, PERM_COPY[p] ?? p, modeOf(p)),
                ).join('')}</div>
              </div>
              <div class="scope-group">
                <h4 class="scope-group-title">Spending limits</h4>
                <div class="scope-limits">
                  <label class="scope-limit">Most per charge (${esc(caps.maxCharge.currency)})
                    <input type="number" name="max_charge" min="0" step="0.01" value="${dollars(maxCharge)}">
                  </label>
                  <label class="scope-limit">Total budget (${esc(caps.maxGrantBudget.currency)})
                    <input type="number" name="total_budget" min="0" step="0.01" value="${dollars(budget)}">
                  </label>
                </div>
                <p class="faint">Site caps: ${esc(formatMoneyWithCurrency(caps.maxCharge))} per charge, ${esc(formatMoneyWithCurrency(caps.maxGrantBudget))} total. Blank fields reset to the cap.</p>
              </div>
              <button class="button button-small" type="submit">Save changes</button>
            </form>
          </details>`;
}

export function renderConnections(
  ctx: RenderCtx,
  requests: GrantRequestView[],
  grants: IssuedGrantView[],
  caps: SiteCaps,
): string {
  const now = Math.floor(Date.now() / 1000);
  const groups = {
    active: [] as IssuedGrantView[],
    expired: [] as IssuedGrantView[],
    revoked: [] as IssuedGrantView[],
  };
  for (const grant of grants) {
    groups[grantEffectiveStatus(grant, now) as keyof typeof groups].push(grant);
  }
  const grantPanel = (grant: IssuedGrantView): string => {
    const perms = grant.permissions
      .map((p) => `<li>${esc(PERM_COPY[p] ?? p)} <span class="row-sub mono">${esc(p)}</span></li>`)
      .join('');
    const narrowed = !sameSet(grant.permissions, grant.issuedPermissions);
    const editor = permEditor(ctx, grant, caps);
    const resources =
      grant.resources.length === 0
        ? '<span class="muted">None</span>'
        : grant.resources.map((r) => `<span class="mono-id">${esc(r)}</span>`).join(', ');
    const constraints =
      grant.constraints.length === 0
        ? '<span class="muted">None</span>'
        : `<ul>${grant.constraints.map((c) => `<li>${describeConstraint(c)}</li>`).join('')}</ul>`;
    const revoke =
      grant.status === 'active'
        ? `<form method="post" action="/account/connections/${esc(grant.jti)}/revoke">
                    ${csrfField(ctx.session?.csrfToken)}
                    <input type="hidden" name="reason" value="revoked from account page">
                    <button class="button button-danger button-small" type="submit">Revoke</button>
                  </form>`
        : `<p class="faint" style="margin:var(--space-3) 0 0">Revoked ${grant.revokedAt !== undefined ? esc(formatTime(grant.revokedAt)) : ''}${grant.revocationReason !== undefined ? ` · ${esc(grant.revocationReason)}` : ''}</p>`;
    return `<div class="panel">
              <div class="split">
                <div><a class="mono-id" href="/account/connections/${esc(grant.jti)}">${esc(grant.jti)}</a></div>
                ${statusBadge(grantEffectiveStatus(grant, now))}
              </div>
              ${narrowed ? '<p class="faint" style="margin:var(--space-2) 0 0">Permissions changed after granting.</p>' : ''}
              <dl class="dl" style="margin-top: var(--space-4)">
                <dt>Agent key</dt><dd><span class="mono-id">${esc(grant.agentJkt)}</span></dd>
                <dt>Issued</dt><dd>${esc(formatTime(grant.issuedAt))}</dd>
                <dt>Expires</dt><dd>${esc(formatTime(grant.expiresAt))}</dd>
                <dt>Permissions</dt><dd><ul>${perms}</ul></dd>
                <dt>Resources</dt><dd>${resources}</dd>
                <dt>Constraints</dt><dd>${constraints}</dd>
              </dl>
              ${editor}
              ${revoke}
            </div>`;
  };
  const section = (title: string, list: IssuedGrantView[]): string =>
    list.length === 0
      ? ''
      : `<div class="section"><div class="section-head"><h3>${esc(title)}</h3></div><div class="stack">${list.map(grantPanel).join('')}</div></div>`;
  const grantRows =
    grants.length === 0
      ? emptyState(
          'No agent connections',
          'An agent that asks for access appears here after you decide. Connect one with the TrailGate agent demo.',
        )
      : section('Active', groups.active) +
        section('Expired', groups.expired) +
        section('Revoked', groups.revoked);
  const requestRows =
    requests.length === 0
      ? '<p class="muted">No consent decisions on record.</p>'
      : `<div class="table-wrap"><table class="table">
          <thead><tr><th>Request</th><th>Agent key</th><th>Permissions</th><th>Decided</th><th>Status</th></tr></thead>
          <tbody>${requests
            .map(
              (req) => `<tr>
                <td><span class="mono-id">${esc(req.requestId)}</span></td>
                <td><span class="mono-id" title="${esc(req.agentJkt)}">${esc(req.agentJkt.slice(0, 12))}…</span></td>
                <td><span class="mono">${esc(req.permissions.join(', '))}</span></td>
                <td>${esc(formatTime(req.createdAt))}</td>
                <td>${statusBadge(req.status)}</td>
              </tr>`,
            )
            .join('')}</tbody>
        </table></div>`;
  const userId = ctx.user?.id;
  const resourceDetails =
    userId === undefined
      ? ''
      : `<details class="tech-details">
        <summary>Resource names an agent can request</summary>
        <p>Agents scope grants to named resources. When writing a request, an agent can name:</p>
        <dl class="dl">
          <dt>Cart</dt><dd><span class="mono-id">cart:cart_${esc(userId)}</span></dd>
          <dt>Wallet</dt><dd><span class="mono-id">wallet:wlt_${esc(userId)}</span></dd>
          <dt>Orders</dt><dd><span class="mono-id">order:ord_*</span> (one selector per order)</dd>
        </dl>
      </details>`;
  return `
${pageHead('Account', 'Agent connections', 'Every request an agent makes is checked against an active grant and its constraints. Revoking takes effect on the next request.')}
<div class="account-grid">
  ${accountNav('connections')}
  <div>
    <section class="section">
      <div class="section-head"><h3>Issued grants</h3></div>
      ${grantRows}
    </section>
    <section class="section">
      <div class="section-head"><h3>Consent decisions</h3></div>
      ${requestRows}
    </section>
    ${resourceDetails}
  </div>
</div>`;
}

export function renderGrantDetail(
  ctx: RenderCtx,
  grant: IssuedGrantView,
  budget: { consumed: number; reserved: number; budgets: { amount: number; currency: string }[] },
  events: { id: string; event: AuditEvent }[],
  receipts: { id: string; decision: string; target: string; method: string; created_at: number }[],
  caps: SiteCaps,
): string {
  const now = Math.floor(Date.now() / 1000);
  const effective =
    grant.status === 'revoked' ? 'revoked' : grant.expiresAt <= now ? 'expired' : 'active';
  const scopeRows = `<dt>Permissions</dt><dd><ul>${grant.permissions
    .map(
      (p) =>
        `<li><span class="mono">${esc(p)}</span> <span class="row-sub">${esc(PERM_COPY[p] ?? '')}</span></li>`,
    )
    .join('')}</ul></dd>
    <dt>Resources</dt><dd>${grant.resources.length === 0 ? '<span class="muted">None requested</span>' : grant.resources.map((r) => `<span class="mono-id">${esc(r)}</span>`).join('<br>')}</dd>
    <dt>Constraints</dt><dd>${grant.constraints.length === 0 ? '<span class="muted">None</span>' : `<ul>${grant.constraints.map((c) => `<li>${describeConstraint(c)}</li>`).join('')}</ul>`}</dd>`;
  const ledgerRows = `<dt>Spent under grant</dt><dd>${budget.consumed} minor units</dd>
    <dt>Reserved (open)</dt><dd>${budget.reserved} minor units</dd>
    ${budget.budgets.map((b) => `<dt>Budget cap</dt><dd>${b.amount} ${esc(b.currency)}</dd>`).join('')}`;
  const eventRows = events
    .slice(0, 50)
    .map(
      ({ event }) =>
        `<tr><td>${esc(formatTime(event.at))}</td><td><span class="mono">${esc(event.event)}</span></td><td><span class="mono-id">${esc(JSON.stringify(event))}</span></td></tr>`,
    )
    .join('');
  const receiptRows = receipts
    .map(
      (r) =>
        `<tr><td><a href="/account/receipts/${esc(r.id)}">${esc(r.id)}</a></td><td><span class="mono">${esc(r.method ?? '')} ${esc(r.target)}</span></td><td>${statusBadge(r.decision === 'allowed' ? 'approved' : 'denied')}</td><td>${esc(formatTime(r.created_at))}</td></tr>`,
    )
    .join('');
  const revokeBlock =
    effective === 'active'
      ? `<div class="panel panel-sunken"><form method="post" action="/account/connections/${esc(grant.jti)}/revoke">
        ${csrfField(ctx.session?.csrfToken)}
        <input type="hidden" name="reason" value="revoked from grant detail">
        <button class="button button-danger" type="submit">Revoke this grant</button>
        <p class="faint" style="margin:var(--space-3) 0 0">Takes effect on the agent's next request. The stored record is re-read after revoking.</p>
      </form></div>`
      : `<p class="faint">This grant is ${effective}.</p>`;
  return `
<nav class="crumbs" aria-label="Breadcrumb"><a href="/account/connections">Agent connections</a><span class="crumb-sep">/</span>Grant</nav>
<div class="page-head">
  <div><h1><span class="mono-id">${esc(grant.jti)}</span></h1></div>
  ${statusBadge(effective)}
</div>
<div class="account-grid">
  ${accountNav('connections')}
  <div class="stack">
    <div class="panel"><dl class="dl">
      <dt>Agent key</dt><dd><span class="mono-id">${esc(grant.agentJkt)}</span></dd>
      <dt>Issued</dt><dd>${esc(formatTime(grant.issuedAt))}</dd>
      <dt>Expires</dt><dd>${esc(formatTime(grant.expiresAt))}</dd>
      ${grant.revokedAt !== undefined ? `<dt>Revoked</dt><dd>${esc(formatTime(grant.revokedAt))}${grant.revocationReason !== undefined ? ` · ${esc(grant.revocationReason)}` : ''}${grant.revocationActor !== undefined ? ` · by ${esc(grant.revocationActor)}` : ''}</dd>` : ''}
      ${scopeRows}
      ${ledgerRows}
    </dl>${permEditor(ctx, grant, caps)}</div>
    ${revokeBlock}
    <div class="section"><div class="section-head"><h3>Signed receipts issued under this grant</h3></div>
      ${receipts.length === 0 ? '<p class="muted">No receipts recorded yet.</p>' : `<div class="table-wrap"><table class="table"><thead><tr><th>Receipt</th><th>Request</th><th>Decision</th><th>At</th></tr></thead><tbody>${receiptRows}</tbody></table></div>`}
    </div>
    <div class="section"><div class="section-head"><h3>Audit events</h3></div>
      ${eventRows === '' ? '<p class="muted">No events recorded for this grant.</p>' : `<div class="table-wrap"><table class="table"><tbody>${eventRows}</tbody></table></div>`}
    </div>
  </div>
</div>`;
}

const PERM_COPY: Record<string, string> = {
  'tg.catalog.read': 'browse the catalog',
  'tg.cart.read': 'read your cart',
  'tg.cart.write': 'change your cart',
  'tg.order.create': 'place orders',
  'tg.order.read': 'read orders and invoices',
  'tg.wallet.read': 'read wallet balance and activity',
  'tg.wallet.charge': 'charge your wallet',
};

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((item) => b.includes(item));
}

export function grantEffectiveStatus(
  grant: { status: string; expiresAt: number },
  now: number,
): string {
  return grant.status === 'revoked' ? 'revoked' : grant.expiresAt <= now ? 'expired' : 'active';
}
