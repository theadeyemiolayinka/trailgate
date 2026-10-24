import assert from 'node:assert/strict';
import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  buildProtectedRequestHeaders,
  createAgentClient,
  SoftwareKeyProvider,
} from '@trailgate/agent';
import { Codes } from '@trailgate/core';
import { openDatabase } from './db/database.ts';
import { loopbackTransport } from './dev/loopback.ts';

/**
 * Live end-to-end flow:
 *
 * The ExampleShop server runs as a real child process over real HTTP with
 * a real SQLite file; the stock Agent SDK (plus the shipped loopback
 * transport that maps the https issuer onto the dev listener) drives
 * discovery, consent, redemption, signing, enforcement, and one real
 * database-backed business action. Nothing is stubbed: grants come from
 * the live lifecycle and denials come from the live pipeline.
 *
 * Denials exercised: missing grant headers, out-of-scope permission, and
 * a request signed by a key that is not the bound key.
 */

const ISSUER = 'https://localhost:3443';
const serverEntry = fileURLToPath(new URL('./server.ts', import.meta.url));

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolve);
  });
  const address = probe.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  assert.ok(port > 0);
  return port;
}

async function waitForServer(
  base: string,
  proc: ChildProcess,
  getOutput: () => string,
): Promise<void> {
  const deadline = Date.now() + 15_000;
  let lastError = 'not started';
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(
        `server exited early with code ${proc.exitCode}: ${lastError}\n${getOutput()}`,
      );
    }
    try {
      const res = await fetch(`${base}/`, { signal: AbortSignal.timeout(1000) });
      if (res.status === 200) {
        return;
      }
      lastError = `status ${res.status}`;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`server did not become ready: ${lastError}\n${getOutput()}`);
}

/** Logs in over real HTTP and approves the consent request via the real form. */
async function approveConsent(base: string, requestId: string): Promise<void> {
  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      email: 'ada@example.com',
      password: 'demo-pass-1234',
      next: '/',
    }).toString(),
    redirect: 'manual',
  });
  assert.equal(login.status, 303, `login failed: ${login.status}`);
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0] as string;
  const page = await fetch(`${base}/tg/consent?request_id=${requestId}`, {
    headers: { cookie },
  });
  const html = await page.text();
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf !== undefined, 'consent page did not render a CSRF token');
  const approve = new URLSearchParams({
    _csrf: csrf,
    request_id: requestId,
    decision: 'approve',
  });
  approve.append('perm', 'tg.catalog.read');
  approve.append('perm', 'tg.cart.read');
  const decide = await fetch(`${base}/tg/consent/decide`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: approve.toString(),
    redirect: 'manual',
  });
  assert.equal(decide.status, 303, `consent decision failed: ${decide.status}`);
}

test('live end-to-end flow over real http, real db, real sdks', async () => {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dir = mkdtempSync(join(tmpdir(), 'tg-live-e2e-'));
  const dbPath = join(dir, 'shop.db');
  const proc = spawn(process.execPath, [serverEntry], {
    env: {
      ...process.env,
      SHOP_PORT: String(port),
      SHOP_DB: dbPath,
      SHOP_ISSUER: ISSUER,
      SHOP_SEED: '1',
      SHOP_CERTS_DIR: join(dir, 'no-certs'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOutput = '';
  proc.stdout?.on('data', (chunk) => {
    serverOutput += chunk;
  });
  proc.stderr?.on('data', (chunk) => {
    serverOutput += chunk;
  });
  try {
    await waitForServer(base, proc, () => serverOutput);
    const transport = loopbackTransport(ISSUER, base);
    const client = createAgentClient({ transport });
    const key = SoftwareKeyProvider.generate();
    client.useKey(key);

    // Discovery: the real document validates against the schema,
    // same-origin rules, and version negotiation inside the agent SDK.
    const site = await client.discover(ISSUER);
    assert.equal(site.issuer, ISSUER);
    assert.equal(site.protocolVersion, '0.1');
    assert.ok(site.document.permissions.includes('tg.cart.read'));
    // The advertised action catalog lets an agent map intent to endpoints.
    const actions = site.document.actions ?? [];
    const cartAction = actions.find((a) => a.id === 'cart.read');
    assert.equal(cartAction?.method, 'GET');
    assert.equal(cartAction?.path, '/api/cart');
    assert.equal(cartAction?.permission, 'tg.cart.read');
    const payAction = actions.find((a) => a.id === 'orders.pay');
    assert.equal(payAction?.spend, true);

    // No applicable grant exists yet; the catalog shows every action
    // uncovered and which permission it would need at consent time.
    const access = await client.checkAccess(site, { permissions: ['tg.cart.read'] });
    assert.equal(access.status, 'no_grant');
    const coverage = await client.listActions(site);
    assert.ok(coverage.length >= 10);
    assert.ok(coverage.every((entry) => entry.covered === false));

    // Denial 1: a request without grant headers.
    const unsigned = await transport.send({ method: 'GET', url: `${ISSUER}/api/products` });
    const unsignedBody = JSON.parse(new TextDecoder().decode(unsigned.body)) as {
      error?: { code?: string };
    };
    assert.equal(unsigned.status, 400);
    assert.equal(unsignedBody.error?.code, Codes.REQUEST_MALFORMED);

    // Consent: a narrowly scoped grant request, approved by the user
    // through the site's own login + CSRF form. Not autonomous.
    const session = await client.requestGrant(site, {
      permissions: ['tg.catalog.read', 'tg.cart.read'],
      resources: ['cart:cart_usr_demo'],
      constraints: [{ type: 'max_amount', params: { amount: 5_000, currency: 'USD' } }],
    });
    await approveConsent(base, session.requestId);
    const grant = await client.awaitApproval(session.requestId, { intervalMs: 50 });
    assert.equal(grant.keyId, key.jkt, 'grant must be bound to the presented agent key');
    assert.equal(grant.issuer, ISSUER);
    assert.deepEqual(grant.permissions.sort(), ['tg.cart.read', 'tg.catalog.read'].sort());

    // Allowed business action: read the cart over a signed request.
    const cart = await client.fetchProtected(site, { method: 'GET', target: '/api/cart' });
    assert.equal(cart.status, 200);
    const cartBody = JSON.parse(new TextDecoder().decode(cart.body)) as { selector?: string };
    assert.equal(cartBody.selector, 'cart:cart_usr_demo');
    assert.equal(cart.receipt?.verified, true, 'receipt must verify against the site keys');
    assert.equal(
      cart.receipt?.verified === true ? cart.receipt.payload.tg.decision : '',
      'allowed',
    );

    // Denial 2: out-of-scope permission (tg.wallet.read was not granted).
    // The catalog also reflects the boundary: cart/catalog read covered,
    // wallet actions still need consent.
    const postCoverage = await client.listActions(site);
    assert.equal(postCoverage.find((entry) => entry.action.id === 'cart.read')?.covered, true);
    assert.equal(postCoverage.find((entry) => entry.action.id === 'wallet.read')?.covered, false);
    const wallet = await client.fetchProtected(site, { method: 'GET', target: '/api/wallet' });
    assert.equal(wallet.error?.code, Codes.REQUEST_PERMISSION_DENIED);

    // Denial 3: signed by a key that is not the bound key (keyid != cnf.jkt).
    const wrongKey = SoftwareKeyProvider.generate();
    const forged = await buildProtectedRequestHeaders(
      { method: 'GET', url: `${ISSUER}/api/cart`, body: new Uint8Array() },
      grant.token,
      wrongKey,
    );
    const wrongKeyRes = await transport.send({
      method: 'GET',
      url: `${ISSUER}/api/cart`,
      headers: forged.headers,
      body: new Uint8Array(),
    });
    const wrongKeyBody = JSON.parse(new TextDecoder().decode(wrongKeyRes.body)) as {
      error?: { code?: string };
    };
    assert.equal(wrongKeyBody.error?.code, Codes.REQUEST_KEY_MISMATCH);

    // Audit and receipt persistence on the same SQLite file the server uses.
    const db = openDatabase(dbPath);
    const events = db
      .prepare('SELECT event FROM tg_audit ORDER BY rowid')
      .all()
      .map((row) => (row as { event: string }).event);
    assert.ok(events.includes('grant.requested'), `audit missing grant.requested: ${events}`);
    assert.ok(events.includes('grant.consent_decided'), 'audit missing consent decision');
    assert.ok(events.includes('grant.issued'), 'audit missing issuance');
    assert.ok(events.includes('request.authenticated'), 'audit missing authenticated request');
    assert.ok(events.includes('request.denied'), 'audit missing denial events');
    const receipt = db
      .prepare("SELECT decision FROM tg_receipts WHERE decision = 'allowed' LIMIT 1")
      .get() as { decision: string } | undefined;
    assert.equal(receipt?.decision, 'allowed', 'allowed receipt must be persisted');
    db.close();
  } finally {
    proc.kill('SIGTERM');
    rmSync(dir, { recursive: true, force: true });
  }
});
