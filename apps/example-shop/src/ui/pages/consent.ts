import type { Constraint, Money } from '@trailgate/core';
import type { ConsentView } from '@trailgate/server';
import { formatMoneyWithCurrency } from '../../domain/money.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

/** Renders a constraint in plain language. Covers the four registered types of draft 0.1. */
export function describeConstraint(constraint: Constraint): string {
  const params = (constraint.params ?? {}) as Record<string, unknown>;
  switch (constraint.type) {
    case 'max_amount': {
      const m = params as unknown as Money;
      return `at most <strong>${esc(formatMoneyWithCurrency(m))}</strong> per charge`;
    }
    case 'cumulative_budget': {
      const m = params as unknown as Money;
      return `total spending capped at <strong>${esc(formatMoneyWithCurrency(m))}</strong> for the life of this grant`;
    }
    case 'rate_limit': {
      const max = Number(params.max_requests);
      const window = Number(params.window_seconds);
      return `at most <strong>${esc(String(max))}</strong> requests per ${esc(formatDuration(window))}`;
    }
    case 'valid_window': {
      const from = Number(params.not_before);
      const to = Number(params.not_after);
      return `usable only between <strong>${esc(formatTime(from))}</strong> and <strong>${esc(formatTime(to))}</strong>`;
    }
    case 'approval_threshold': {
      const m = params as unknown as Money;
      return `charges above <strong>${esc(formatMoneyWithCurrency(m))}</strong> need your approval each time`;
    }
    default:
      return `<span class="mono">${esc(constraint.type)}</span> <span class="mono-id">${esc(JSON.stringify(params))}</span>`;
  }
}

function formatDuration(seconds: number): string {
  if (!Number.isInteger(seconds) || seconds <= 0) {
    return `${seconds}s`;
  }
  if (seconds % 86400 === 0) {
    return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  }
  if (seconds % 3600 === 0) {
    return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  }
  return `${seconds} seconds`;
}

function permissionList(permissions: string[]): string {
  return `<ul>${permissions
    .map((p) => `<li><span class="mono">${esc(p)}</span></li>`)
    .join('')}</ul>`;
}

function resourceList(resources: string[]): string {
  if (resources.length === 0) {
    return '<span class="muted">No specific resources; access is limited to what the permissions allow on your account.</span>';
  }
  return `<ul>${resources.map((r) => `<li><span class="mono-id">${esc(r)}</span></li>`).join('')}</ul>`;
}

function constraintList(constraints: Constraint[]): string {
  if (constraints.length === 0) {
    return '<span class="muted">None proposed. Only the permissions and resource scope limit this agent.</span>';
  }
  return `<ul>${constraints.map((c) => `<li>${describeConstraint(c)}</li>`).join('')}</ul>`;
}

const PERMISSION_COPY: Record<string, string> = {
  'tg.catalog.read': 'Browse the product catalog',
  'tg.cart.read': 'Read your cart',
  'tg.cart.write': 'Add and remove cart items',
  'tg.order.create': 'Place orders for you',
  'tg.order.read': 'View your orders and invoices',
  'tg.wallet.read': 'View your wallet balance and activity',
  'tg.wallet.charge': 'Charge your wallet',
};

function permissionLabel(permission: string): string {
  return PERMISSION_COPY[permission] ?? permission;
}

/**
 * The consent surface (spec section 10.3). Renders a plain-language summary of
 * the effective scope first, then the requested scope verbatim from the
 * stored grant request, then the effective scope the shop will actually issue
 * when it differs.
 */
export function renderConsent(
  ctx: RenderCtx,
  view: ConsentView,
  site: {
    name: string;
    issuer: string;
    spendingPolicy: { maxCharge: Money; maxGrantBudget: Money };
  },
): string {
  const { requested, effective } = view;
  const narrowed =
    effective.permissions.length !== requested.permissions.length ||
    effective.resources.length !== requested.resources.length ||
    effective.lifetimeSeconds !== (requested.requestedSeconds ?? 3600) ||
    JSON.stringify(effective.constraints) !== JSON.stringify(requested.constraints);

  const decided = view.status !== 'pending';
  const denyCopy = `<div class="consent-term">
      <h3>If you deny</h3>
      <p>Denying records the decision, closes this request, and issues nothing. The agent is informed the request was denied and cannot redeem it. Your cart, orders, and wallet are untouched.</p>
    </div>
    <div class="consent-term">
      <h3>When more approval is needed</h3>
      <p>Approving creates one grant carrying exactly these terms. If the agent later wants more (new permissions, resources, or higher limits) it must submit a new request and you must approve again — it cannot widen this grant. Revoking stops everything from the next request onward.</p>
    </div>`;
  const redirectNote =
    view.redirectUri !== undefined
      ? `<p class="consent-note">After your decision you will be returned to the agent at <span class="mono-id">${esc(view.redirectUri)}</span>.</p>`
      : '<p class="consent-note">The agent is waiting on a status check; there is no redirect.</p>';

  const decidedBlock = decided
    ? `<div class="consent-term"><p>This request has already been decided: ${statusBadge(view.status)}</p>
        <p style="margin:0"><a class="button button-secondary" href="/account/connections">View agent connections</a></p></div>`
    : `<form method="post" action="/tg/consent/decide">
        ${csrfField(ctx.session?.csrfToken)}
        <input type="hidden" name="request_id" value="${esc(view.requestId)}">
        <fieldset class="scope-editor">
          <legend>Approve exactly what this agent may do (uncheck to refuse)</legend>
          ${effective.permissions
            .map(
              (p) => `<label class="scope-choice">
              <input type="checkbox" name="perm" value="${esc(p)}" checked>
              <span>${esc(permissionLabel(p))} <span class="row-sub mono">${esc(p)}</span></span>
            </label>`,
            )
            .join('')}
        </fieldset>
        <div class="consent-actions">
          <button class="button" type="submit" name="decision" value="approve">Approve selected</button>
          <button class="button button-secondary" type="submit" name="decision" value="deny">Deny all</button>
        </div>
      </form>`;

  const effectiveBlock = narrowed
    ? `<div class="consent-term panel-sunken">
        <h3>What the shop will actually issue</h3>
        <p class="term-diff">ExampleShop narrowed the request. The grant will carry these terms, never more than requested.</p>
        <dl class="dl">
          <dt>Permissions</dt><dd>${permissionList(effective.permissions)}</dd>
          <dt>Resources</dt><dd>${resourceList(effective.resources)}</dd>
          <dt>Constraints</dt><dd>${constraintList(effective.constraints)}</dd>
          <dt>Lifetime</dt><dd>${esc(formatDuration(effective.lifetimeSeconds))}</dd>
        </dl>
      </div>`
    : '';

  const summaryPerms = effective.permissions
    .map((p) => `<li>${esc(permissionLabel(p))}</li>`)
    .join('');

  return `
<div class="consent-frame">
  <div class="consent-agent">
    <div class="consent-agent-mark" aria-hidden="true">A</div>
    <div>
      <h1>An agent is requesting access</h1>
      <p class="muted" style="margin:0">Signed in as ${esc(ctx.user?.name ?? '')} (${esc(ctx.user?.email ?? '')})</p>
    </div>
  </div>

  <div class="consent-terms">
    <div class="consent-term consent-summary">
      <h3>At a glance</h3>
      <p>This agent will be able to:</p>
      <ul>${summaryPerms}</ul>
      <p style="margin:var(--space-3) 0 0">Effective for <strong>${esc(formatDuration(effective.lifetimeSeconds))}</strong>, on <strong>${esc(site.name)}</strong> only.</p>
    </div>
    <div class="consent-term">
      <h3>Site granting access</h3>
      <p><strong>${esc(site.name)}</strong> <span class="mono-id">${esc(site.issuer)}</span></p>
      <p class="faint" style="margin:0">The grant, receipts, and spending ledger are issued and enforced by this origin only.</p>
    </div>
    <div class="consent-term">
      <h3>Agent being authorized</h3>
      <dl class="dl">
        <dt>Key thumbprint</dt><dd><span class="mono-id">${esc(view.agentJkt)}</span></dd>
      </dl>
      <p class="faint" style="margin:0">Verified by the protocol: the grant binds to this exact key, and every request must be signed by its private half. Draft 0.1 carries no verified agent name or vendor claim — anything the agent says about itself is descriptive, not verified identity.</p>
    </div>
    <div class="consent-term panel-sunken">
      <h3>Site spending policy</h3>
      <ul>
        <li>any single charge is capped at <strong>${esc(formatMoneyWithCurrency(site.spendingPolicy.maxCharge))}</strong></li>
        <li>a grant's total budget is capped at <strong>${esc(formatMoneyWithCurrency(site.spendingPolicy.maxGrantBudget))}</strong> even if more is requested</li>
        <li>currency: <strong>${esc(site.spendingPolicy.maxCharge.currency)}</strong> only</li>
      </ul>
    </div>
    <div class="consent-term">
      <h3>Permissions requested</h3>
      <ul>${requested.permissions
        .map(
          (p) => `<li>${esc(permissionLabel(p))} <span class="row-sub mono">${esc(p)}</span></li>`,
        )
        .join('')}</ul>
    </div>
    <div class="consent-term">
      <h3>Resources requested</h3>
      ${resourceList(requested.resources)}
    </div>
    <div class="consent-term">
      <h3>Limits proposed by the agent</h3>
      ${constraintList(requested.constraints)}
    </div>
    <div class="consent-term">
      <h3>Lifetime</h3>
      <p>Requested <strong>${esc(formatDuration(requested.requestedSeconds ?? 3600))}</strong>; effective <strong>${esc(formatDuration(effective.lifetimeSeconds))}</strong>.</p>
      <p class="faint" style="margin:0">This request expires ${esc(formatTime(view.expiresAt))} if undecided. You can revoke an issued grant at any time from Agent connections.</p>
    </div>
    ${effectiveBlock}
    ${denyCopy}
  </div>

  ${decidedBlock}
  ${redirectNote}
  <p class="consent-note">Approving issues a grant carrying exactly the terms above. ExampleShop enforces them on every signed request; the agent cannot exceed them by changing what it sends. TrailGate is experimental; review the terms before approving.</p>
</div>`;
}
