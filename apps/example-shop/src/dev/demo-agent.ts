/**
 * Judge-facing TrailGate demonstration covering the required scenarios.
 * Run with the shop up: `pnpm demo`. Every step goes through the real
 * Agent SDK, Server SDK, enforcement pipeline, and database. Denials
 * shown are real protocol denials or real business errors — nothing is
 * simulated.
 *
 * Flags:
 *   --manual      stop at the consent step and wait for browser approval
 *   --max N       per-charge constraint ceiling (minor units, default 6000)
 *   --budget N    cumulative budget ceiling (minor units, default 12000)
 */
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';
import { verifyReceipt } from '@trailgate/core';
import { loopbackTransport } from './loopback.ts';

const ISSUER = process.env['SHOP_ISSUER'] ?? 'https://localhost:3443';
const HTTP_BASE = `http://127.0.0.1:${process.env['SHOP_PORT'] ?? '3300'}`;
const args = process.argv.slice(2);
const flag = (name: string, fallback: number): number => {
  const i = args.indexOf(name);
  return i >= 0 ? Number.parseInt(args[i + 1] as string, 10) : fallback;
};
const MAX_CHARGE = flag('--max', 6_000);
const BUDGET = flag('--budget', 12_000);
const MANUAL = args.includes('--manual');

const ok = (label: string, detail: string) => console.log(`   ${label}: ${detail}`);
const step = (n: string, title: string) => console.log(`\n${n}. ${title}`);

function printOutcome(status: number, code: string | undefined, receipt: string): void {
  ok('status', `${status}`);
  if (code !== undefined) {
    const kind = code.startsWith('tg.')
      ? 'protocol denial'
      : code.startsWith('shop.')
        ? 'business failure'
        : 'error';
    ok('outcome', `${code} (${kind})`);
  }
  ok('receipt', receipt);
}

/** Logs in over real HTTP and scrapes the CSRF token from the consent page. */
async function consentViaBrowserPath(requestId: string): Promise<void> {
  const login = await fetch(`${HTTP_BASE}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      email: 'ada@example.com',
      password: 'demo-pass-1234',
      next: '/',
    }).toString(),
    redirect: 'manual',
  });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0] as string;
  const page = await fetch(`${HTTP_BASE}/tg/consent?request_id=${requestId}`, {
    headers: { cookie },
  });
  const html = await page.text();
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  if (csrf === undefined) {
    throw new Error('consent page did not render a CSRF token');
  }
  const decide = await fetch(`${HTTP_BASE}/tg/consent/decide`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      _csrf: csrf,
      request_id: requestId,
      decision: 'approve',
    }).toString(),
    redirect: 'manual',
  });
  if (decide.status !== 303) {
    throw new Error(`consent decision failed: ${decide.status}`);
  }
}

const transport = loopbackTransport(ISSUER, HTTP_BASE);
const client = createAgentClient({ transport });
client.useKey(SoftwareKeyProvider.generate());

step('1', 'discovery');
const site = await client.discover(ISSUER);
ok('issuer', `${site.issuer}  protocol ${site.protocolVersion}`);

step('2', 'protected request with no grant (expect denial)');
const unsigned = await transport.send({ method: 'GET', url: `${ISSUER}/api/products` });
const unsignedErr = JSON.parse(new TextDecoder().decode(unsigned.body)) as {
  error?: { code: string };
};
printOutcome(unsigned.status, unsignedErr.error?.code, 'none issued');

step('3', 'consent: request a narrowly scoped grant');
const session = await client.requestGrant(site, {
  permissions: [
    'tg.catalog.read',
    'tg.cart.read',
    'tg.cart.write',
    'tg.order.create',
    'tg.wallet.read',
    'tg.wallet.charge',
    // tg.order.read deliberately NOT requested: step 5 exercises it.
  ],
  resources: ['cart:cart_usr_demo', 'wallet:wlt_usr_demo', 'order:ord_bill_seed01'],
  constraints: [
    { type: 'max_amount', params: { amount: MAX_CHARGE, currency: 'USD' } },
    { type: 'cumulative_budget', params: { amount: BUDGET, currency: 'USD' } },
  ],
});
ok('request', session.requestId);
if (MANUAL) {
  console.log(`   approve in the browser: ${HTTP_BASE}/tg/consent?request_id=${session.requestId}`);
  console.log('   (ada@example.com / demo-pass-1234)');
} else {
  console.log('   auto-approving through the real login + consent form...');
  await consentViaBrowserPath(session.requestId);
}
const grant = await client.awaitApproval(session.requestId, { intervalMs: 50 });
ok('grant', grant.jti);

step('4', 'allowed actions inside scope');
const cat = await client.fetchProtected(site, { method: 'GET', target: '/api/products' });
printOutcome(cat.status, cat.error?.code, cat.receipt?.verified === true ? 'verified' : 'missing');
const add = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/cart/items',
  body: JSON.stringify({ sku: 'drk-mug-01', qty: 2 }),
});
printOutcome(add.status, add.error?.code, '');

step('5', 'action outside granted scope (order.read was not granted)');
const outOfScope = await client.fetchProtected(site, { method: 'GET', target: '/api/orders' });
printOutcome(
  outOfScope.status,
  outOfScope.error?.code,
  outOfScope.receipt?.verified === true ? 'denial receipt verified' : '',
);

step('6', "another user's resource (order:ord_bill_seed01 is IN scope but owned by usr_bill)");
const crossUser = await client.fetchProtected(site, {
  method: 'GET',
  target: '/api/orders/ord_bill_seed01',
});
printOutcome(crossUser.status, crossUser.error?.code, '');

step('7', 'tampered request body (signature/digest no longer matches)');
// Corrupt the body bytes in-flight: the signature and Content-Digest were
// computed over the original body, so verification must fail server-side.
const origSend = transport.send.bind(transport);
transport.send = async (req) =>
  req.body !== undefined
    ? origSend({ ...req, body: new TextEncoder().encode('{"sku":"drk-mug-01","qty":99}') })
    : origSend(req);
const tamperedRes = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/cart/items',
  body: JSON.stringify({ sku: 'drk-mug-01', qty: 1 }),
});
transport.send = origSend;
printOutcome(tamperedRes.status, tamperedRes.error?.code, '');

step('8', 'charge above the authorized max_amount');
const bigAdd = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/cart/items',
  body: JSON.stringify({ sku: 'hm-throw-01', qty: 1 }), // 8900 > max_amount 6000
});
void bigAdd;
const bigOrder = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
});
const bigOrderId = (JSON.parse(new TextDecoder().decode(bigOrder.body)) as { id?: string }).id;
const bigPay = await client.fetchProtected(site, {
  method: 'POST',
  target: `/api/orders/${bigOrderId}/pay`,
  body: '{}',
});
printOutcome(
  bigPay.status,
  bigPay.error?.code,
  bigPay.receipt?.verified === true ? 'denial receipt verified' : '',
);

step('9', 'duplicate checkout (idempotency) and concurrent spending');
const cart2 = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/cart/items',
  body: JSON.stringify({ sku: 'stn-pen-02', qty: 1 }),
});
void cart2;
const idem = `idem_demo_${Date.now()}`;
const dup1 = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
  idempotencyKey: idem,
});
const dup2 = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
  idempotencyKey: idem,
});
const b1 = JSON.parse(new TextDecoder().decode(dup1.body)) as {
  id?: string;
  error?: { code: string };
};
const b2 = JSON.parse(new TextDecoder().decode(dup2.body)) as {
  id?: string;
  error?: { code: string };
};
const dup2desc =
  b2.id !== undefined
    ? `replayed same order ${b2.id}`
    : `${dup2.status} ${b2.error?.code ?? 'error'}`;
ok('duplicate checkout', `first=order ${b1.id} second=${dup2desc}`);
const [pay1, pay2] = await Promise.all([
  client.fetchProtected(site, { method: 'POST', target: `/api/orders/${b1.id}/pay`, body: '{}' }),
  client.fetchProtected(site, { method: 'POST', target: `/api/orders/${b1.id}/pay`, body: '{}' }),
]);
printOutcome(pay1.status, pay1.error?.code, '');
printOutcome(pay2.status, pay2.error?.code, '');

step('10', 'revocation');
const cookie = (
  await fetch(`${HTTP_BASE}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      email: 'ada@example.com',
      password: 'demo-pass-1234',
      next: '/',
    }).toString(),
    redirect: 'manual',
  })
).headers
  .get('set-cookie')
  ?.split(';')[0] as string;
const connPage = await fetch(`${HTTP_BASE}/account/connections/${grant.jti}`, {
  headers: { cookie },
});
const connHtml = await connPage.text();
const connCsrf = connHtml.match(/name="_csrf" value="([^"]+)"/)?.[1] as string;
const revoke = await fetch(`${HTTP_BASE}/account/connections/${grant.jti}/revoke`, {
  method: 'POST',
  headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ _csrf: connCsrf, reason: 'demo revocation' }).toString(),
  redirect: 'manual',
});
ok('revoke', `HTTP ${revoke.status}`);
const after = await client.fetchProtected(site, { method: 'GET', target: '/api/cart' });
printOutcome(after.status, after.error?.code, '');

step('11', 'activity records + a legitimate receipt');
const receiptsPage = await fetch(`${HTTP_BASE}/account/receipts`, { headers: { cookie } });
ok('receipts page', `HTTP ${receiptsPage.status}`);
const goodReceipt = cat.receipt?.verified === true ? cat.receipt.payload : undefined;
if (goodReceipt !== undefined) {
  ok(
    'receipt claims',
    `decision=${goodReceipt.tg.decision} grant=${goodReceipt.tg.grant_id} audit=${goodReceipt.tg.audit_id}`,
  );
}

step('12', 'tampered receipt (verification must fail)');
const jws = cat.headers?.['trailgate-receipt'] ?? '';
const forged = `${jws.slice(0, -4)}AAAA`;
try {
  await verifyReceipt(forged, {
    resolveSiteKey: {
      resolve: async (kid: string) => site.document.signing_keys.keys.find((k) => k.kid === kid),
    },
    issuer: ISSUER,
    audience: ISSUER,
  });
  console.log('   UNEXPECTED: tampered receipt verified');
} catch (err) {
  ok('tampered receipt', `rejected: ${err instanceof Error ? err.message : String(err)}`);
}

console.log(
  '\ndone. Open /account/activity and /account/receipts in the browser to inspect records.',
);
