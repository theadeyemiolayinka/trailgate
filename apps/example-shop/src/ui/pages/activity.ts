import type { AuditEvent } from '@trailgate/core';
import type { Order } from '../../domain/orders.ts';
import { esc, formatTime } from '../html.ts';
import { statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';

export interface ActivityRow {
  id: string;
  event: AuditEvent;
}

const EVENT_LABELS: Record<string, string> = {
  'grant.requested': 'Agent requested access',
  'grant.consent_decided': 'Consent decision recorded',
  'grant.issued': 'Grant issued',
  'grant.revoked': 'Grant revoked',
  'request.authenticated': 'Signed request accepted',
  'request.denied': 'Request denied',
  'reservation.created': 'Spending reserved',
  'reservation.consumed': 'Spending charged',
  'reservation.released': 'Reservation released',
  'key.rotated': 'Signing key rotated',
};

function eventDetail(event: AuditEvent): string {
  const bits: string[] = [];
  if (event.grant_id !== undefined) bits.push(`grant ${event.grant_id}`);
  if (event.request_id !== undefined) bits.push(`request ${event.request_id}`);
  if (event.code !== undefined) bits.push(event.code);
  if (event.reservation_id !== undefined) bits.push(`reservation ${event.reservation_id}`);
  if (event.amount !== undefined && event.currency !== undefined) {
    bits.push(`${event.amount} ${event.currency}`);
  }
  return bits.join(' · ');
}

/**
 * The user's TrailGate activity feed: audit events attached to their
 * grants plus orders placed through an agent. This is recorded protocol
 * activity, not simulated events.
 */
export function renderActivity(
  _ctx: RenderCtx,
  auditRows: ActivityRow[],
  agentOrders: Order[],
): string {
  const audit =
    auditRows.length === 0
      ? '<p class="muted">No recorded agent activity yet. Events appear here when an agent request is decided and used.</p>'
      : `<table class="table">
          <thead><tr><th>When</th><th>Event</th><th>Detail</th></tr></thead>
          <tbody>${auditRows
            .map(
              ({ event }) => `<tr>
                <td style="white-space:nowrap">${esc(formatTime(event.at))}</td>
                <td>${esc(EVENT_LABELS[event.event] ?? event.event)} <span class="row-sub mono">${esc(event.event)}</span></td>
                <td><span class="mono-id">${esc(eventDetail(event))}</span></td>
              </tr>`,
            )
            .join('')}</tbody>
        </table>`;
  const orders =
    agentOrders.length === 0
      ? '<p class="muted">No orders have been placed by an agent.</p>'
      : `<table class="table">
          <thead><tr><th>Order</th><th>Placed</th><th class="num">Total</th><th>Status</th><th>Grant</th></tr></thead>
          <tbody>${agentOrders
            .map(
              (order) => `<tr>
                <td><a href="/orders/${esc(order.id)}">${esc(order.id)}</a></td>
                <td>${esc(formatTime(order.createdAt))}</td>
                <td class="num">${order.total.amount} ${esc(order.total.currency)}</td>
                <td>${statusBadge(order.status)}</td>
                <td><span class="mono-id">${esc(order.grantJti ?? '')}</span></td>
              </tr>`,
            )
            .join('')}</tbody>
        </table>`;
  return `
<div class="page-head"><div><span class="eyebrow">Account / Activity</span><h1>Activity</h1></div></div>
<div class="account-grid">
  ${accountNav('activity')}
  <div>
    <section class="section">
      <div class="section-head"><h3>TrailGate audit events</h3></div>
      <p class="faint">Append-only protocol events recorded by the shop for your grants. Receipts returned to agents reference these records.</p>
      ${audit}
    </section>
    <section class="section">
      <div class="section-head"><h3>Orders placed by agents</h3></div>
      ${orders}
    </section>
  </div>
</div>`;
}
