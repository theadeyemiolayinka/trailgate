import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from '@trailgate/core';
import type { HostRequest, HostResponse, TrailGateServer } from '@trailgate/server';
import { createTrailGateServer, generateSigningKeyPair } from '@trailgate/server';
import { AgentError, createAgentClient } from './client.ts';
import { fakeTransport } from './helpers.test.ts';
import { SoftwareKeyProvider } from './keys.ts';
import { InMemoryGrantStore } from './store.ts';
import type { AgentHttpRequest, AgentHttpResponse, HttpTransport } from './transport.ts';

const ORIGIN = 'https://shop.example.com';
const siteKey = generateSigningKeyPair();

function encodeBody(body: unknown): Uint8Array {
  if (body === undefined) {
    return new Uint8Array();
  }
  if (typeof body === 'string') {
    return new TextEncoder().encode(body);
  }
  return new TextEncoder().encode(JSON.stringify(body));
}

/**
 * Adapts the framework-neutral server SDK surface to the agent's transport
 * port. No real sockets: requests route by path to the SDK handlers exactly
 * as a host application would wire them.
 */
function hostTransport(
  server: TrailGateServer,
  protectedRoutes: Map<string, (req: HostRequest) => Promise<HostResponse>>,
): { transport: HttpTransport; requests: AgentHttpRequest[] } {
  const { transport, requests } = fakeTransport(async (req): Promise<AgentHttpResponse> => {
    const url = new URL(req.url);
    const hostReq: HostRequest = {
      method: req.method,
      url: req.url,
      headers: req.headers ?? {},
      ...(req.body !== undefined ? { body: req.body } : {}),
    };
    let res: HostResponse;
    if (url.pathname === '/.well-known/trailgate') {
      res = {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: server.discoveryDocument(),
      };
    } else if (url.pathname === '/tg/grant-request') {
      res = await server.handleGrantRequest(hostReq);
    } else if (url.pathname === '/tg/grant-redemption') {
      res = await server.handleRedemption(hostReq);
    } else if (url.pathname === '/tg/grant-status') {
      res = await server.handleStatus(hostReq);
    } else if (url.pathname === '/tg/grant-revocation') {
      res = await server.handleRevocation(hostReq);
    } else {
      const handler = protectedRoutes.get(url.pathname);
      res =
        handler !== undefined
          ? await handler(hostReq)
          : { status: 404, body: { error: { code: 'tg.internal.error', message: 'no route' } } };
    }
    return { status: res.status, headers: res.headers ?? {}, body: encodeBody(res.body) };
  });
  return { transport, requests };
}

function makeServer() {
  return createTrailGateServer({
    issuer: ORIGIN,
    signingKeys: [{ privateJwk: siteKey.privateJwk }],
    permissions: ['tg.order.create', 'tg.cart.read'],
    revocationAuthorizer: async () => ({ actor: 'agent-self-service' }),
  });
}

const instantPoll = { intervalMs: 1, sleep: () => Promise.resolve() };

describe('agent against the server SDK (end to end)', () => {
  it('runs discovery, consent, redemption, and a verified signed request', async () => {
    const server = makeServer();
    const routes = new Map([
      [
        '/api/orders',
        server.protect({ permission: 'tg.order.create' }, async (_req, ctx) => ({
          status: 200,
          body: { placed: true, grant: ctx.grantId },
        })),
      ],
    ]);
    const { transport } = hostTransport(server, routes);
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());

    const ctx = await client.discover(ORIGIN);
    assert.equal(ctx.protocolVersion, '0.1');

    const session = await client.requestGrant(ctx, {
      permissions: ['tg.order.create'],
      resources: ['order:ord_1'],
    });
    assert.ok(session.consentUrl.startsWith(`${ORIGIN}/`));

    // The site's own consent surface: an authenticated user approves.
    await server.decideConsent(session.requestId, 'approve', 'user_1');
    const grant = await client.awaitApproval(session.requestId, instantPoll);
    assert.equal(grant.issuer, ORIGIN);
    assert.ok(grant.keyId.length > 0);
    assert.deepEqual(grant.permissions, ['tg.order.create']);

    const res = await client.fetchProtected(ctx, {
      method: 'POST',
      target: '/api/orders',
      body: JSON.stringify({ item: 'book' }),
      idempotencyKey: 'idem_order_1',
    });
    assert.equal(res.status, 200);
    assert.equal(res.error, undefined);
    assert.equal(res.receipt?.verified, true, 'receipt must verify against discovery keys');
    if (res.receipt?.verified === true) {
      assert.equal(res.receipt.payload.tg.decision, 'allowed');
      assert.equal(res.receipt.payload.tg.grant_id, grant.jti);
    }
  });

  it('receives a signed denial receipt for an out-of-scope action', async () => {
    const server = makeServer();
    const routes = new Map([
      ['/api/cart', server.protect({ permission: 'tg.cart.read' }, async () => ({ status: 200 }))],
    ]);
    const { transport } = hostTransport(server, routes);
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());
    const ctx = await client.discover(ORIGIN);
    const session = await client.requestGrant(ctx, { permissions: ['tg.order.create'] });
    await server.decideConsent(session.requestId, 'approve', 'user_1');
    await client.awaitApproval(session.requestId, instantPoll);

    const res = await client.fetchProtected(ctx, { method: 'GET', target: '/api/cart' });
    assert.equal(res.status, 403);
    assert.equal(res.error?.code, Codes.REQUEST_PERMISSION_DENIED);
    assert.equal(res.receipt?.verified, true);
    if (res.receipt?.verified === true) {
      assert.equal(res.receipt.payload.tg.decision, 'denied');
      assert.equal(res.receipt.payload.tg.code, Codes.REQUEST_PERMISSION_DENIED);
    }
  });

  it('replays an identical idempotent request without re-executing', async () => {
    const server = makeServer();
    let executions = 0;
    const routes = new Map([
      [
        '/api/orders',
        server.protect({ permission: 'tg.order.create' }, async () => {
          executions += 1;
          return { status: 201, body: { seq: executions } };
        }),
      ],
    ]);
    const { transport } = hostTransport(server, routes);
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());
    const ctx = await client.discover(ORIGIN);
    const session = await client.requestGrant(ctx, { permissions: ['tg.order.create'] });
    await server.decideConsent(session.requestId, 'approve', 'user_1');
    await client.awaitApproval(session.requestId, instantPoll);

    const first = await client.fetchProtected(ctx, {
      method: 'POST',
      target: '/api/orders',
      body: '{"item":1}',
      idempotencyKey: 'same-key',
    });
    const replay = await client.fetchProtected(ctx, {
      method: 'POST',
      target: '/api/orders',
      body: '{"item":1}',
      idempotencyKey: 'same-key',
    });
    assert.equal(first.status, 201);
    assert.equal(replay.status, 201);
    assert.equal(executions, 1, 'idempotent replay must not re-execute');

    const conflict = await client.fetchProtected(ctx, {
      method: 'POST',
      target: '/api/orders',
      body: '{"item":2}',
      idempotencyKey: 'same-key',
    });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.error?.code, Codes.REQUEST_IDEMPOTENCY_CONFLICT);
  });

  it('handles consent denial as a typed error', async () => {
    const server = makeServer();
    const { transport } = hostTransport(server, new Map());
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());
    const ctx = await client.discover(ORIGIN);
    const session = await client.requestGrant(ctx, { permissions: ['tg.order.create'] });
    await server.decideConsent(session.requestId, 'deny', 'user_1');
    await assert.rejects(client.awaitApproval(session.requestId, instantPoll), (err) => {
      assert.ok(err instanceof TrailGateError);
      assert.equal(err.code, Codes.GRANT_CONSENT_DENIED);
      return true;
    });
  });

  it('reports grant status, revokes, and fails closed on a stale local record', async () => {
    const server = makeServer();
    const routes = new Map([
      [
        '/api/orders',
        server.protect({ permission: 'tg.order.create' }, async () => ({ status: 200 })),
      ],
    ]);
    const { transport } = hostTransport(server, routes);
    const store = new InMemoryGrantStore();
    const client = createAgentClient({ transport, grantStore: store });
    client.useKey(SoftwareKeyProvider.generate());
    const ctx = await client.discover(ORIGIN);
    const session = await client.requestGrant(ctx, { permissions: ['tg.order.create'] });
    await server.decideConsent(session.requestId, 'approve', 'user_1');
    const grant = await client.awaitApproval(session.requestId, instantPoll);

    const status = await client.grantStatus(ctx, { grantId: grant.jti });
    assert.equal(status.status, 'active');

    await client.revokeGrant(ctx, grant.jti, { reason: 'user requested' });
    assert.equal(await client.getGrant(grant.jti), undefined, 'local record must drop');
    const statusAfter = await client.grantStatus(ctx, { grantId: grant.jti });
    assert.equal(statusAfter.status, 'revoked');

    // If a stale record is reintroduced locally, server-side enforcement
    // still denies and the client evicts the record again.
    await store.put(grant);
    const res = await client.fetchProtected(ctx, {
      method: 'POST',
      target: '/api/orders',
      grantId: grant.jti,
    });
    assert.equal(res.error?.code, Codes.GRANT_REVOKED);
    assert.equal(await client.getGrant(grant.jti), undefined);
  });

  it('fails closed locally when no grant is stored', async () => {
    const server = makeServer();
    const { transport } = hostTransport(server, new Map());
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());
    const ctx = await client.discover(ORIGIN);
    await assert.rejects(
      client.fetchProtected(ctx, { method: 'GET', target: '/api/orders' }),
      (err) => err instanceof AgentError && err.kind === 'no_grant',
    );
  });
});
