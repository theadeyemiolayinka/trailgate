import type { AuditEvent, Constraint } from '@trailgate/core';
import { formatMoney } from '../../domain/money.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';
import { describeConstraint } from './consent.ts';

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
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  revokedAt?: number;
  revocationReason?: string;
  revocationActor?: string;
}

export function renderConnections(
  ctx: RenderCtx,
  requests: GrantRequestView[],
  grants: IssuedGrantView[],
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
      .map((p) => `<li><span class="mono">${esc(p)}</span></li>`)
      .join('');
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
        : `<p class="faint">Revoked ${grant.revokedAt !== undefined ? esc(formatTime(grant.revokedAt)) : ''}${grant.revocationReason !== undefined ? ` · ${esc(grant.revocationReason)}` : ''}</p>`;
    return `<div class="panel">
              <div class="split">
                <div><a class="mono-id" href="/account/connections/${esc(grant.jti)}">${esc(grant.jti)}</a></div>
                ${statusBadge(grantEffectiveStatus(grant, now))}
              </div>
              <dl class="dl" style="margin-top: var(--space-4)">
                <dt>Agent key</dt><dd><span class="mono-id">${esc(grant.agentJkt)}</span></dd>
                <dt>Issued</dt><dd>${esc(formatTime(grant.issuedAt))}</dd>
                <dt>Expires</dt><dd>${esc(formatTime(grant.expiresAt))}</dd>
                <dt>Permissions</dt><dd><ul style="margin:0;padding-left:1.2em">${perms}</ul></dd>
                <dt>Resources</dt><dd>${resources}</dd>
                <dt>Constraints</dt><dd>${constraints}</dd>
              </dl>
              ${revoke}
            </div>`;
  };
  const section = (title: string, list: IssuedGrantView[]): string =>
    list.length === 0
      ? ''
      : `<div class="section"><div class="section-head"><h3>${esc(title)}</h3></div><div class="stack">${list.map(grantPanel).join('')}</div></div>`;
  const grantRows =
    grants.length === 0
      ? '<p class="muted">No agent grants yet. An agent that asks for access appears here after you decide.</p>'
      : section('Active', groups.active) +
        section('Expired', groups.expired) +
        section('Revoked', groups.revoked);
  const requestRows =
    requests.length === 0
      ? '<p class="muted">No consent decisions on record.</p>'
      : `<table class="table">
          <thead><tr><th>Request</th><th>Agent key</th><th>Permissions</th><th>Decided</th><th>Status</th></tr></thead>
          <tbody>${requests
            .map(
              (req) => `<tr>
                <td><span class="mono-id">${esc(req.requestId)}</span></td>
                <td><span class="mono-id" title="${esc(req.agentJkt)}">${esc(req.agentJkt.slice(0, 12))}…</span></td>
                <td>${req.permissions.map((p) => `<span class="mono">${esc(p)}</span>`).join(', ')}</td>
                <td>${esc(formatTime(req.createdAt))}</td>
                <td>${statusBadge(req.status)}</td>
              </tr>`,
            )
            .join('')}</tbody>
        </table>`;
  return `
<div class="page-head"><div><span class="eyebrow">Account / Connections</span><h1>Agent connections</h1></div></div>
<div class="account-grid">
  ${accountNav('connections')}
  <div>
    <section class="section">
      <div class="section-head"><h3>Issued grants</h3></div>
      <p class="faint">Every request an agent makes carries a grant checked against this list and its constraints. Revoking takes effect on the next request.</p>
      <div class="stack">${grantRows}</div>
    </section>
    <section class="section">
      <div class="section-head"><h3>Consent decisions</h3></div>
      ${requestRows}
    </section>
  </div>
</div>`;
}

// ---------- Prompt 2 additions: grant detail + grouped rendering ----------

export function renderGrantDetail(
  ctx: RenderCtx,
  grant: IssuedGrantView,
  budget: { consumed: number; reserved: number; budgets: { amount: number; currency: string }[] },
  events: { id: string; event: AuditEvent }[],
  receipts: { id: string; decision: string; target: string; method: string; created_at: number }[],
): string {
  const now = Math.floor(Date.now() / 1000);
  const effective =
    grant.status === 'revoked' ? 'revoked' : grant.expiresAt <= now ? 'expired' : 'active';
  const scopeRows = `<dt>Permissions</dt><dd><ul style="margin:0;padding-left:1.2em">${grant.permissions
    .map(
      (p) =>
        `<li><span class="mono">${esc(p)}</span> <span class="row-sub">${esc(PERM_COPY[p] ?? '')}</span></li>`,
    )
    .join('')}</ul></dd>
    <dt>Resources</dt><dd>${grant.resources.length === 0 ? '<span class="muted">None requested</span>' : grant.resources.map((r) => `<span class="mono-id">${esc(r)}</span>`).join('<br>')}</dd>
    <dt>Constraints</dt><dd>${grant.constraints.length === 0 ? '<span class="muted">None</span>' : `<ul style="margin:0;padding-left:1.2em">${grant.constraints.map((c) => `<li>${describeConstraint(c)}</li>`).join('')}</ul>`}</dd>`;
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
        `<tr><td><a href="/account/receipts/${esc(r.id)}">${esc(r.id)}</a></td><td>${esc(r.method ?? '')} ${esc(r.target)}</td><td>${statusBadge(r.decision === 'allowed' ? 'approved' : 'denied')}</td><td>${esc(formatTime(r.created_at))}</td></tr>`,
    )
    .join('');
  const revokeBlock =
    effective === 'active'
      ? `<form method="post" action="/account/connections/${esc(grant.jti)}/revoke">
        ${csrfField(ctx.session?.csrfToken)}
        <input type="hidden" name="reason" value="revoked from grant detail">
        <button class="button button-danger" type="submit">Revoke this grant</button>
        <p class="faint">Takes effect on the agent's next request. This reads back the stored record after revoking.</p>
      </form>`
      : `<p class="faint">This grant is ${effective}.</p>`;
  return `
<div class="page-head">
  <div><span class="eyebrow"><a href="/account/connections">Agent connections</a> / grant</span><h1><span class="mono-id">${esc(grant.jti)}</span> ${statusBadge(effective)}</h1></div>
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
    </dl></div>
    ${revokeBlock}
    <div class="section"><div class="section-head"><h3>Signed receipts issued under this grant</h3></div>
      ${receipts.length === 0 ? '<p class="muted">No receipts recorded yet.</p>' : `<table class="table"><thead><tr><th>Receipt</th><th>Request</th><th>Decision</th><th>At</th></tr></thead><tbody>${receiptRows}</tbody></table>`}
    </div>
    <div class="section"><div class="section-head"><h3>Audit events</h3></div>
      ${eventRows === '' ? '<p class="muted">No events recorded for this grant.</p>' : `<table class="table"><tbody>${eventRows}</tbody></table>`}
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

export function grantEffectiveStatus(
  grant: { status: string; expiresAt: number },
  now: number,
): string {
  return grant.status === 'revoked' ? 'revoked' : grant.expiresAt <= now ? 'expired' : 'active';
}
