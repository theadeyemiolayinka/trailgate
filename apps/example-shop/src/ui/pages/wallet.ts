import { formatMoney } from '../../domain/money.ts';
import type { Wallet, WalletEntry } from '../../domain/wallet.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField, emptyState, pageHead } from '../layout.ts';
import type { RenderCtx } from '../render.ts';
import { accountNav } from './account.ts';

const KIND_LABELS: Record<WalletEntry['kind'], string> = {
  topup: 'Top-up',
  order_debit: 'Order payment',
  order_refund: 'Order refund',
  adjustment: 'Adjustment',
};

export function renderWallet(ctx: RenderCtx, wallet: Wallet, entries: WalletEntry[]): string {
  const ledger =
    entries.length === 0
      ? emptyState('No activity yet', 'Top-ups, order payments, and refunds appear here.')
      : `<table class="table table-cards">
        <thead><tr><th>When</th><th>Entry</th><th class="num">Amount ${esc(wallet.currency)}</th><th class="num">Balance</th></tr></thead>
        <tbody>${entries
          .map((entry) => {
            const signed = `${entry.amount.amount >= 0 ? '+' : ''}${formatMoney(entry.amount)}`;
            const ref =
              entry.ref !== undefined
                ? ` <span class="row-sub"><a href="/orders/${esc(entry.ref)}">${esc(entry.ref)}</a></span>`
                : '';
            const signedClass = entry.amount.amount >= 0 ? 'amt-pos' : 'amt-neg';
            return `<tr>
              <td data-label="When">${esc(formatTime(entry.createdAt))}</td>
              <td data-label="Entry">${esc(KIND_LABELS[entry.kind])}${ref}</td>
              <td data-label="Amount" class="num"><span class="${signedClass}">${esc(signed)}</span></td>
              <td data-label="Balance" class="num">${esc(formatMoney({ amount: entry.balanceAfter, currency: entry.amount.currency }))}</td>
            </tr>`;
          })
          .join('')}</tbody>
      </table>`;
  const presetForm = (
    amount: number,
  ) => `<form method="post" action="/account/wallet/topup" class="inline-form">
      ${csrfField(ctx.session?.csrfToken)}
      <input type="hidden" name="amount" value="${amount}">
      <button type="submit">+${amount}</button>
    </form>`;
  return `
${pageHead('Account', 'Wallet', 'Add simulated funds and track spending. No real money moves.')}
<div class="account-grid">
  ${accountNav('wallet')}
  <div>
    <div class="cart-layout">
      <div>
        <section class="section">
          <div class="section-head"><h3>Activity</h3></div>
          ${ledger}
        </section>
      </div>
      <aside>
        <div class="balance-card">
          <p class="eyebrow">Available balance</p>
          <p class="balance-figure">${esc(formatMoney(wallet.balance))}</p>
          <p class="balance-sub">${esc(wallet.currency)} · simulated funds</p>
        </div>
        <div class="panel" style="margin-top:var(--space-4)">
          <h3>Add test funds</h3>
          <p class="faint">Simulated credit for testing. Maximum 10,000.00 per top-up.</p>
          <div class="topup-presets">
            ${presetForm(25)}
            ${presetForm(50)}
            ${presetForm(100)}
          </div>
          <form method="post" action="/account/wallet/topup">
            ${csrfField(ctx.session?.csrfToken)}
            <div class="field" style="max-width:none">
              <label for="topup-amount">Custom amount (${esc(wallet.currency)})</label>
              <input id="topup-amount" name="amount" type="number" min="1" max="10000" step="1" required>
            </div>
            <button class="button button-secondary button-block" type="submit">Add funds</button>
          </form>
        </div>
      </aside>
    </div>
  </div>
</div>`;
}
