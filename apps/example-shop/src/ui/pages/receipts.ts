import type { ReceiptPayload } from '@trailgate/core';
import { esc, formatTime } from '../html.ts';
import { csrfField, statusBadge } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';

export interface StoredReceiptRow {
  id: string;
  grant_id: string;
  decision: string;
  code: string | null;
  method: string;
  target: string;
  created_at: number;
}

export type ReceiptVerdict =
  | { kind: 'verified'; payload: ReceiptPayload }
  | { kind: 'unverified'; reason: string }
  | { kind: 'malformed'; reason: string };

export function renderReceiptList(ctx: RenderCtx, rows: StoredReceiptRow[]): string {
  const body =
    rows.length === 0
      ? '<p class="muted">No receipts recorded yet. Every signed request under a grant produces a receipt; they appear here after an agent acts.</p>'
      : `<table class="table">
        <thead><tr><th>Receipt</th><th>Grant</th><th>Request</th><th>Decision</th><th>Issued</th></tr></thead>
        <tbody>${rows
          .map(
            (r) => `<tr>
              <td><a class="mono-id" href="/account/receipts/${esc(r.id)}">${esc(r.id)}</a></td>
              <td><span class="mono-id">${esc(r.grant_id)}</span></td>
              <td><span class="mono">${esc(r.method)} ${esc(r.target)}</span></td>
              <td>${statusBadge(r.decision === 'allowed' ? 'approved' : 'denied')}</td>
              <td>${esc(formatTime(r.created_at))}</td>
            </tr>`,
          )
          .join('')}</tbody>
      </table>`;
  return `
<div class="page-head"><div><span class="eyebrow">Account / Receipts</span><h1>Signed receipts</h1></div></div>
<div class="account-grid">
  ${accountNav('receipts')}
  <div>
    <section class="section">
      <div class="section-head"><h3>Issued under your grants</h3></div>
      <p class="faint">Receipts are signed by the shop for every protected request. Open one to verify it against the site's current signing keys.</p>
      ${body}
    </section>
    <section class="section">
      <div class="section-head"><h3>Verify a receipt</h3></div>
      <form method="post" action="/account/receipts/verify">
        ${csrfField(ctx.session?.csrfToken)}
        <div class="field" style="max-width:none">
          <label for="receipt">Receipt token (compact JWS)</label>
          <textarea id="receipt" name="receipt" rows="4" spellcheck="false" class="mono" style="width:100%"></textarea>
        </div>
        <button class="button button-secondary" type="submit">Verify</button>
      </form>
    </section>
  </div>
</div>`;
}

export function renderReceiptDetail(
  verdict: ReceiptVerdict,
  rawToken: string,
  meta?: { grant_id: string; method: string; target: string; created_at: number },
): string {
  const head =
    verdict.kind === 'verified'
      ? `<div class="flash flash-ok">Verified: signature checks against the site's published signing key.</div>`
      : `<div class="flash flash-error">${verdict.kind === 'malformed' ? 'Not a receipt' : 'Unverified'}: ${esc(verdict.reason)}</div>`;
  const claims =
    verdict.kind === 'verified'
      ? `<dl class="dl">
        <dt>Receipt id</dt><dd><span class="mono-id">${esc(verdict.payload.jti)}</span></dd>
        <dt>Issuer</dt><dd><span class="mono-id">${esc(verdict.payload.iss)}</span></dd>
        <dt>Audience</dt><dd><span class="mono-id">${esc(verdict.payload.aud)}</span></dd>
        <dt>Issued at</dt><dd>${esc(formatTime(verdict.payload.iat))}</dd>
        <dt>Grant</dt><dd><span class="mono-id">${esc(verdict.payload.tg.grant_id)}</span></dd>
        <dt>Decision</dt><dd>${statusBadge(verdict.payload.tg.decision === 'allowed' ? 'approved' : 'denied')}</dd>
        ${verdict.payload.tg.code !== undefined ? `<dt>Denial code</dt><dd><span class="mono">${esc(verdict.payload.tg.code)}</span></dd>` : ''}
        <dt>Request digest</dt><dd><span class="mono-id">${esc(verdict.payload.tg.request_digest)}</span></dd>
        <dt>Audit event</dt><dd><span class="mono-id">${esc(verdict.payload.tg.audit_id)}</span></dd>
        ${verdict.payload.tg.amounts !== undefined ? `<dt>Ledger effect</dt><dd><span class="mono-id">${esc(JSON.stringify(verdict.payload.tg.amounts))}</span></dd>` : ''}
      </dl>`
      : '';
  const metaBlock =
    meta !== undefined
      ? `<dl class="dl"><dt>Stored for request</dt><dd><span class="mono">${esc(meta.method)} ${esc(meta.target)}</span></dd><dt>Grant</dt><dd><a class="mono-id" href="/account/connections/${esc(meta.grant_id)}">${esc(meta.grant_id)}</a></dd></dl>`
      : '';
  return `
<div class="page-head"><div><span class="eyebrow"><a href="/account/receipts">Receipts</a> / inspection</span><h1>Receipt inspection</h1></div></div>
<div class="account-grid">
  ${accountNav('receipts')}
  <div class="stack">
    ${head}
    ${metaBlock !== '' ? `<div class="panel">${metaBlock}</div>` : ''}
    ${claims !== '' ? `<div class="panel">${claims}</div>` : ''}
    <div class="panel panel-sunken"><h3>Raw token</h3><p class="mono-id" style="word-break:break-all">${esc(rawToken)}</p>
    <p class="faint">A verified receipt proves the site recorded a decision for a specific request. It does not prove settlement or fulfillment.</p></div>
  </div>
</div>`;
}
