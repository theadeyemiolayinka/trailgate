/**
 * Reproducible agent-connection demo: runs the full client flow against the
 * server SDK in-process (no ExampleShop, no network). Prints each step the
 * way a runtime would narrate it.
 *
 * Run after `pnpm build`:  node --experimental-strip-types scripts/agent-demo.ts
 */
import { createAgentClient, planAccess, reportAction, SoftwareKeyProvider } from '@trailgate/agent';
import type { HostRequest } from '@trailgate/server';
import { createTrailGateServer, generateSigningKeyPair } from '@trailgate/server';

const ORIGIN = 'https://shop.example.com';
const server = createTrailGateServer({
  issuer: ORIGIN,
  signingKeys: [{ privateJwk: generateSigningKeyPair().privateJwk }],
  permissions: ['tg.order.create'],
});
const protectedOrders = server.protect({ permission: 'tg.order.create' }, async () => ({
  status: 200,
  body: { placed: true },
}));

const transport = {
  send: async (req: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: Uint8Array;
  }) => {
    const hostReq: HostRequest = {
      method: req.method,
      url: req.url,
      headers: req.headers ?? {},
      body: req.body,
    };
    const path = new URL(req.url).pathname;
    const res =
      path === '/.well-known/trailgate'
        ? {
            status: 200,
            headers: { 'content-type': 'application/json' },
            body: server.discoveryDocument(),
          }
        : path === '/tg/grant-request'
          ? await server.handleGrantRequest(hostReq)
          : path === '/tg/grant-redemption'
            ? await server.handleRedemption(hostReq)
            : path === '/tg/grant-status'
              ? await server.handleStatus(hostReq)
              : path === '/api/orders'
                ? await protectedOrders(hostReq)
                : {
                    status: 404,
                    body: { error: { code: 'tg.internal.error', message: 'no route' } },
                  };
    const body =
      res.body === undefined
        ? new Uint8Array()
        : new TextEncoder().encode(
            typeof res.body === 'string' ? res.body : JSON.stringify(res.body),
          );
    return { status: res.status, headers: res.headers ?? {}, body };
  },
};

const client = createAgentClient({ transport });
client.useKey(SoftwareKeyProvider.generate());

console.log('1. inspect site');
const site = await client.discover(ORIGIN);
console.log(
  '   supported:',
  site.protocolVersion,
  '| permissions:',
  site.document.permissions.join(', '),
);

console.log('2-4. check access');
const plan = await planAccess(client, site, { permissions: ['tg.order.create'] });
console.log('   plan:', plan.status);
if (plan.status !== 'consent_required') process.exit(1);

console.log('5. consent required ->', plan.session.consentUrl);
await server.decideConsent(plan.session.requestId, 'approve', 'user_1');
const grant = await client.awaitApproval(plan.session.requestId, { intervalMs: 1 });
console.log('   consent confirmed; grant', grant.jti, 'expires', grant.expiresAt);

console.log('6. execute permitted action');
const res = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: '{}',
});

console.log('7. report');
console.log('  ', JSON.stringify(reportAction(res)));
