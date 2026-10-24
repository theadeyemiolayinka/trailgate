import type { Address } from '../../domain/users.ts';
import { esc } from '../html.ts';
import { csrfField, emptyState, pageHead } from '../layout.ts';
import type { RenderCtx } from '../render.ts';

export function accountNav(section: string): string {
  const items: [string, string, string][] = [
    ['/account', 'Profile', 'profile'],
    ['/orders', 'Orders', 'orders'],
    ['/account/addresses', 'Addresses', 'addresses'],
    ['/account/wallet', 'Wallet', 'wallet'],
    ['/account/connections', 'Agent connections', 'connections'],
    ['/account/approvals', 'Agent approvals', 'approvals'],
    ['/account/receipts', 'Receipts', 'receipts'],
    ['/account/activity', 'Activity', 'activity'],
  ];
  const links = items
    .map(
      ([href, label, key]) =>
        `<a href="${href}"${section === key ? ' aria-current="page"' : ''}>${esc(label)}</a>`,
    )
    .join('');
  return `<nav class="account-nav" aria-label="Account sections">${links}</nav>`;
}

export function renderProfile(ctx: RenderCtx): string {
  const user = ctx.user;
  if (user === undefined) {
    return '';
  }
  return `
${pageHead('Account', user.name)}
<div class="account-grid">
  ${accountNav('profile')}
  <div class="stack">
    <div class="panel">
      <div class="section-head"><h3>Profile</h3></div>
      <dl class="dl">
        <dt>Email</dt><dd>${esc(user.email)}</dd>
        <dt>Member since</dt><dd>${esc(new Date(user.createdAt * 1000).toISOString().slice(0, 10))}</dd>
        <dt>User id</dt><dd><span class="mono-id">${esc(user.id)}</span></dd>
      </dl>
    </div>
  </div>
</div>`;
}

export function renderAddresses(ctx: RenderCtx, addresses: Address[]): string {
  const list =
    addresses.length === 0
      ? emptyState('No addresses', 'Add a shipping address for checkout.')
      : `<div class="stack">${addresses
          .map(
            (a) => `<div class="panel split">
              <div>
                <strong>${esc(a.label)}</strong>${a.isDefault ? ' <span class="badge badge-muted">Default</span>' : ''}
                <p class="muted" style="margin:4px 0 0">${esc(a.line1)}${a.line2 !== undefined ? `, ${esc(a.line2)}` : ''}, ${esc(a.city)}${a.region !== undefined ? `, ${esc(a.region)}` : ''} ${esc(a.postcode)}, ${esc(a.country)}</p>
              </div>
              <form method="post" action="/account/addresses/${esc(a.id)}/delete">
                ${csrfField(ctx.session?.csrfToken)}
                <button class="link-button" type="submit">Delete</button>
              </form>
            </div>`,
          )
          .join('')}</div>`;
  return `
${pageHead('Account', 'Addresses')}
<div class="account-grid">
  ${accountNav('addresses')}
  <div>
    ${list}
    <div class="panel" style="margin-top:var(--space-4)">
      <div class="section-head"><h3>Add an address</h3></div>
      <form method="post" action="/account/addresses">
        ${csrfField(ctx.session?.csrfToken)}
        <div class="field"><label for="label">Label</label><input id="label" name="label" required maxlength="40" placeholder="Home"></div>
        <div class="field"><label for="line1">Address line 1</label><input id="line1" name="line1" required maxlength="200"></div>
        <div class="field"><label for="line2">Address line 2</label><input id="line2" name="line2" maxlength="200"></div>
        <div class="field-row">
          <div class="field"><label for="city">City</label><input id="city" name="city" required maxlength="100"></div>
          <div class="field"><label for="region">Region</label><input id="region" name="region" maxlength="100"></div>
        </div>
        <div class="field-row">
          <div class="field"><label for="postcode">Postcode</label><input id="postcode" name="postcode" required maxlength="20"></div>
          <div class="field"><label for="country">Country</label><input id="country" name="country" required maxlength="100"></div>
        </div>
        <div class="checkbox-field"><input id="is_default" name="is_default" type="checkbox"><label for="is_default">Make default</label></div>
        <button class="button" type="submit">Save address</button>
      </form>
    </div>
  </div>
</div>`;
}
