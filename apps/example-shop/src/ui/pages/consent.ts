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
    case 'require_approval': {
      const perms = Array.isArray(params.permissions) ? params.permissions : [];
      return `actions using ${perms
        .map((p) => `<span class="mono">${esc(String(p))}</span>`)
        .join(', ')} need your approval each time`;
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

export type PermissionMode = 'deny' | 'approval' | 'allow';

/**
 * The tri-state permission control (spec section 9): each permission can be
 * denied outright, granted but queued for a human decision on every action,
 * or allowed to run when the grant's other checks pass. The form posts one
 * `mode_<permission>` field per permission; the server maps deny to removal
 * from the grant and approval to a `require_approval` constraint.
 */
export function permModeControl(permission: string, label: string, mode: PermissionMode): string {
  const radio = (value: PermissionMode, text: string): string =>
    `<label class="mode-choice"><input type="radio" name="mode_${esc(permission)}" value="${value}"${mode === value ? ' checked' : ''}> ${esc(text)}</label>`;
  return `<div class="scope-choice scope-choice-tristate" data-label="${esc(label)}">
    <span class="scope-choice-name">${esc(label)} <span class="row-sub mono">${esc(permission)}</span></span>
    <span class="mode-choices">${radio('allow', 'Allow')}${radio('approval', 'Require approval')}${radio('deny', 'Deny')}</span>
  </div>`;
}

/**
 * The consent surface (spec section 10.3). One decision card carries the
 * permission picker, the duration picker, and a live summary that updates as
 * the user edits; the verbatim requested terms and site policy sit behind a
 * collapsed details block.
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
    (requested.requestedSeconds !== undefined &&
      effective.lifetimeSeconds !== requested.requestedSeconds) ||
    JSON.stringify(effective.constraints) !== JSON.stringify(requested.constraints);

  const decided = view.status !== 'pending';

  const durationLadder = [3600, 86_400, 604_800, 2_592_000].filter(
    (s) => s <= view.lifetimeCapSeconds,
  );
  if (!durationLadder.includes(effective.lifetimeSeconds)) {
    durationLadder.push(effective.lifetimeSeconds);
    durationLadder.sort((a, b) => a - b);
  }
  const durationOptions = durationLadder
    .map(
      (s) =>
        `<option value="${s}"${s === effective.lifetimeSeconds ? ' selected' : ''}>${esc(formatDuration(s))}</option>`,
    )
    .join('');

  const suggestedApproval = new Set(view.approvalSuggested);
  const permChoices = effective.permissions
    .map((p) =>
      permModeControl(p, permissionLabel(p), suggestedApproval.has(p) ? 'approval' : 'allow'),
    )
    .join('');

  const decidedBlock = decided
    ? `<div class="consent-term consent-decision">
        <h3>This request has been decided</h3>
        <p>${statusBadge(view.status)}</p>
        <p style="margin:0"><a class="button button-secondary" href="/account/connections">View agent connections</a></p>
      </div>`
    : `<div class="consent-term consent-decision">
      <form class="consent-form" method="post" action="/tg/consent/decide">
        ${csrfField(ctx.session?.csrfToken)}
        <input type="hidden" name="request_id" value="${esc(view.requestId)}">
        <h3>Choose what this agent may do</h3>
        <p class="muted" style="margin:0 0 var(--space-3)">For each permission choose whether the agent may use it, must ask you first on every action, or is denied. Approving can only ever grant what is listed here.</p>
        <div class="consent-perms">${permChoices}</div>
        <div class="consent-duration">
          <label for="lifetime-seconds">Keep this access for</label>
          <select id="lifetime-seconds" name="lifetime_seconds">${durationOptions}</select>
        </div>
        <p class="consent-live">This agent will be able to <strong data-perm-echo></strong> on ${esc(site.name)} for <strong data-duration-echo></strong>, until about <strong data-expiry-echo></strong>. You can revoke it any time from Agent connections.</p>
        <div class="consent-actions">
          <button class="button" type="submit" name="decision" value="approve" data-approve-btn>Approve selected</button>
          <button class="button button-secondary" type="submit" name="decision" value="deny">Deny all</button>
        </div>
        <p class="faint" style="margin:var(--space-3) 0 0">Denying closes this request and issues nothing. If the agent wants more later it must ask again and you approve again.</p>
      </form>
    </div>`;

  const narrowedNote = narrowed
    ? `<p class="term-diff">ExampleShop narrowed this request. The grant will carry the terms below, never more than requested.</p>`
    : '';

  const redirectLine =
    view.redirectUri !== undefined
      ? `After your decision you will be returned to the agent at <span class="mono-id">${esc(view.redirectUri)}</span>.`
      : 'The agent is waiting on a status check; there is no redirect.';

  return `
<div class="consent-frame">
  <div class="consent-agent">
    <div class="consent-agent-mark" aria-hidden="true">A</div>
    <div>
      <h1>An agent is requesting access</h1>
      <p class="muted" style="margin:0">Signed in as ${esc(ctx.user?.name ?? '')} (${esc(ctx.user?.email ?? '')})</p>
    </div>
  </div>

  ${decidedBlock}

  <details class="consent-term consent-details">
    <summary>Request details and site policy</summary>
    ${narrowedNote}
    <dl class="dl">
      <dt>Site</dt><dd><strong>${esc(site.name)}</strong> <span class="mono-id">${esc(site.issuer)}</span></dd>
      <dt>Agent key</dt><dd><span class="mono-id">${esc(view.agentJkt)}</span></dd>
      <dt>Resources</dt><dd>${resourceList(effective.resources)}</dd>
      <dt>Limits</dt><dd>${constraintList(effective.constraints)}</dd>
      <dt>Lifetime</dt><dd>${requested.requestedSeconds !== undefined ? `requested ${esc(formatDuration(requested.requestedSeconds))}, ` : ''}defaults to ${esc(formatDuration(effective.lifetimeSeconds))}, yours up to ${esc(formatDuration(view.lifetimeCapSeconds))}</dd>
      <dt>Request expires</dt><dd>${esc(formatTime(view.expiresAt))} if undecided</dd>
    </dl>
    <p class="faint">Spending policy: charges capped at ${esc(formatMoneyWithCurrency(site.spendingPolicy.maxCharge))} each, total budget ${esc(formatMoneyWithCurrency(site.spendingPolicy.maxGrantBudget))}, ${esc(site.spendingPolicy.maxCharge.currency)} only.</p>
    <p class="faint">${redirectLine}</p>
  </details>

  <p class="consent-note">Approving issues a grant carrying exactly the selected terms. ExampleShop enforces them on every signed request; the agent cannot exceed them by changing what it sends. TrailGate is experimental; review before approving.</p>
</div>
<script src="/static/consent.js" defer></script>`;
}
