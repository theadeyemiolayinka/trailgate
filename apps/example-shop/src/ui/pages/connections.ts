import type { Constraint } from '@trailgate/core';
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
  const grantRows =
    grants.length === 0
      ? '<p class="muted">No agent grants yet. An agent that asks for access appears here after you decide.</p>'
      : grants
          .map((grant) => {
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
                <div><span class="mono-id">${esc(grant.jti)}</span></div>
                ${statusBadge(grant.status)}
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
          })
          .join('');
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
