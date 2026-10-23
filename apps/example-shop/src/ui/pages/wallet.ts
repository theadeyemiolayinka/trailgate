import { formatMoney, formatMoneyWithCurrency } from '../../domain/money.ts';
import type { Wallet, WalletEntry } from '../../domain/wallet.ts';
import { esc, formatTime } from '../html.ts';
import { csrfField } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

const KIND_LABELS: Record<WalletEntry['kind'], string> = {
  topup: 'Top-up',
  order_debit: 'Order payment',
  order_refund: 'Order refund',
  adjustment: 'Adjustment',
};

export function renderWallet(ctx: RenderCtx, wallet: Wallet, entries: WalletEntry[]): string {
  const rows =
    entries.length === 0
      ? '<tr><td colspan="4" class="muted">No activity yet.</td></tr>'
      : entries
          .map((entry) => {
            const signed = `${entry.amount.amount >= 0 ? '+' : ''}${formatMoney(entry.amount)}`;
            const ref =
              entry.ref !== undefined
                ? ` · <a href="/orders/${esc(entry.ref)}">${esc(entry.ref)}</a>`
                : '';
            return `<tr>
              <td>${esc(formatTime(entry.createdAt))}</td>
              <td>${esc(KIND_LABELS[entry.kind])}<span class="row-sub">${ref}</span></td>
              <td class="num">${esc(signed)}</td>
              <td class="num">${esc(formatMoney({ amount: entry.balanceAfter, currency: entry.amount.currency }))}</td>
            </tr>`;
          })
          .join('');
  return `
<div class="page-head">
  <div>
    <span class="eyebrow">Account / Wallet</span>
    <h1>Simulated wallet</h1>
  </div>
</div>
<div class="cart-layout">
  <div>
    <section class="section">
      <div class="section-head"><h3>Activity</h3></div>
      <table class="table">
        <thead><tr><th>When</th><th>Entry</th><th class="num">Amount ${esc(wallet.currency)}</th><th class="num">Balance</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
  </div>
  <aside class="panel">
    <p class="eyebrow">Balance</p>
    <p class="total-row">${esc(formatMoneyWithCurrency(wallet.balance))}</p>
    <hr class="rule">
    <form method="post" action="/account/wallet/topup">
      ${csrfField(ctx.session?.csrfToken)}
      <div class="field">
        <label for="topup-amount">Top up (${esc(wallet.currency)})</label>
        <input id="topup-amount" name="amount" type="number" min="1" max="10000" step="1" required>
        <p class="hint">Simulated credit. Maximum 10,000.00 per top-up.</p>
      </div>
      <button class="button button-secondary" type="submit">Add funds</button>
    </form>
    <p class="consent-note">The wallet is simulated for the reference app; balances and entries are real database state so spending rules can be tested honestly.</p>
  </aside>
</div>`;
}
