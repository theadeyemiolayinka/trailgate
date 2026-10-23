import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import type { Jwk } from '@trailgate/core';
import { Codes, signRequest, TrailGateError, verifyReceipt } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import { RECEIPT_HEADER } from './enforcement.ts';
import { createTrailGateServer } from './server.ts';
import type { HostRequest, HostResponse } from './types.ts';

/**
 * A minimal host application that is NOT ExampleShop: a photo library where
 * users own albums. It wires the SDK end to end over real HTTP (node:http,
 * no web framework), keeps its own session auth and its own resource
 * database, and demonstrates the adapter the host must write.
 *
 * In production the issuer origin and the transport origin are the same TLS
 * endpoint. Here the issuer is a fixed https identity while the listener is
 * loopback http; the client rewrites the origin for transport only.
 */

const ISSUER = 'https://photos.example.com';
const NOW = 1_700_000_000;

const site = generateEd25519KeyPair();
const agent = generateEd25519KeyPair();

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  return { verifier, challenge };
}

interface Album {
  owner: string;
  photos: string[];
}

function createHost() {
  const now = NOW;
  const albums = new Map<string, Album>([
    ['alb_f1', { owner: 'user_1', photos: [] }],
    ['alb_g9', { owner: 'user_2', photos: [] }],
  ]);
  const sessions = new Map<string, string>([['sess_1', 'user_1']]);

  const tg = createTrailGateServer({
    issuer: ISSUER,
    signingKeys: [{ privateJwk: site.privateJwk }],
    permissions: ['tg.album.create', 'tg.album.read', 'tg.photo.upload'],
    clock: { now: () => now },
    resourceOwners: {
      ownerOf: async (selector) => {
        const [type, id] = selector.split(':');
        if (type !== 'album' || id === undefined) {
          return undefined;
        }
        return albums.get(id)?.owner;
      },
    },
    policy: {
      authorize: async (ctx) => {
        // Host business rule: user_1's agents may not upload to shared albums.
        if (ctx.subject === 'user_1' && ctx.resources.includes('album:alb_shared')) {
          throw new TrailGateError(
            Codes.AUTHORIZATION_DENIED,
            'host policy: shared album uploads are staff-only',
          );
        }
      },
    },
  });

  const sessionUser = (req: HostRequest): string | undefined =>
    sessions.get(req.headers['cookie']?.replace('session=', '') ?? '');

  const bodyJson = (req: HostRequest): unknown => {
    const text =
      req.body === undefined
        ? ''
        : typeof req.body === 'string'
          ? req.body
          : new TextDecoder().decode(req.body);
    return text === '' ? {} : JSON.parse(text);
  };

  const readBody = async (req: import('node:http').IncomingMessage): Promise<Buffer> => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  };

  const routes = async (req: HostRequest): Promise<HostResponse> => {
    const path = new URL(req.url).pathname;
    if (path === '/.well-known/trailgate') {
      return { status: 200, body: tg.discoveryDocument() };
    }
    if (path === '/tg/grant-request') {
      return tg.handleGrantRequest(req);
    }
    if (path === '/tg/grant-redemption') {
      return tg.handleRedemption(req);
    }
    if (path === '/tg/grant-status') {
      return tg.handleStatus(req);
    }
    if (path === '/tg/consent') {
      const requestId = new URL(req.url).searchParams.get('request_id');
      if (sessionUser(req) === undefined) {
        return { status: 401, body: { error: 'login required' } };
      }
      const view = requestId === null ? undefined : await tg.getConsent(requestId);
      return view === undefined
        ? { status: 404, body: { error: 'unknown request' } }
        : { status: 200, body: view };
    }
    if (path === '/tg/consent/decide') {
      const user = sessionUser(req);
      if (user === undefined) {
        return { status: 401, body: { error: 'login required' } };
      }
      const decision = bodyJson(req) as { request_id: string; approve: boolean };
      const outcome = await tg.decideConsent(
        decision.request_id,
        decision.approve ? 'approve' : 'deny',
        user,
      );
      return { status: 200, body: outcome };
    }
    if (path === '/tg/admin/revoke') {
      const user = sessionUser(req);
      if (user === undefined) {
        return { status: 401, body: { error: 'login required' } };
      }
      const { grant_id } = bodyJson(req) as { grant_id: string };
      await tg.revokeGrant(grant_id, { reason: 'user requested', actor: user });
      return { status: 200, body: { revoked: grant_id } };
    }
    if (path === '/albums' && req.method === 'POST') {
      return tg.protect({ permission: 'tg.album.create' }, async (_r, ctx) => {
        const id = `alb_${randomBytes(4).toString('base64url')}`;
        albums.set(id, { owner: ctx.subject as string, photos: [] });
        return { status: 201, body: { id, owner: ctx.subject } };
      })(req);
    }
    const albumMatch = /^\/albums\/(alb_[^/]+)(\/photos)?$/.exec(path);
    if (albumMatch !== null) {
      const id = albumMatch[1] as string;
      const isPhotoUpload = albumMatch[2] !== undefined;
      if (!isPhotoUpload) {
        return tg.protect(
          { permission: 'tg.album.read', resource: `album:${id}` },
          async (_r, ctx) => ({ status: 200, body: { id, grant: ctx.grantId } }),
        )(req);
      }
      return tg.protect(
        {
          permission: 'tg.photo.upload',
          resource: `album:${id}`,
          amount: (r) => {
            const body = bodyJson(r) as { price: { amount: number; currency: string } };
            return body.price;
          },
        },
        async (r, ctx) => {
          const body = bodyJson(r) as { photo: string };
          const album = albums.get(id) as Album;
          album.photos.push(body.photo);
          return { status: 201, body: { id, photos: album.photos.length, grant: ctx.grantId } };
        },
      )(req);
    }
    return { status: 404, body: { error: 'not found' } };
  };

  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value as string);
    }
    const hostReq: HostRequest = {
      method: req.method as string,
      url: `${ISSUER}${req.url}`,
      headers,
      body: body.length > 0 ? new Uint8Array(body) : '',
    };
    const out = await routes(hostReq);
    res.writeHead(out.status, {
      'content-type': 'application/json',
      ...(out.headers ?? {}),
    });
    res.end(
      out.body === undefined
        ? ''
        : typeof out.body === 'string'
          ? out.body
          : JSON.stringify(out.body),
    );
  });
  return { server, tg, albums };
}

describe('minimal host application over real HTTP', () => {
  let server: Server;
  let base: string;

  before(async () => {
    const host = createHost();
    server = host.server;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(resolve));
  });

  async function fetchHost(path: string, init: RequestInit = {}): Promise<Response> {
    return fetch(`${base}${path}`, init);
  }

  async function signedFetch(
    path: string,
    grant: string,
    init: { method: string; body?: string; idem?: string },
  ): Promise<Response> {
    const body = init.body ?? '';
    const headers = await signRequest(
      { method: init.method, url: `${ISSUER}${path}`, body: new TextEncoder().encode(body) },
      {
        privateJwk: agent.privateJwk as Jwk,
        keyid: agent.jkt,
        nonce: randomBytes(16).toString('base64url'),
        created: NOW,
        expires: NOW + 60,
        grant,
        idempotencyKey: init.idem ?? `idem_${randomBytes(12).toString('base64url')}`,
      },
    );
    return fetch(`${base}${path}`, {
      method: init.method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body === '' ? undefined : body,
    });
  }

  it('serves a valid discovery document', async () => {
    const res = await fetchHost('/.well-known/trailgate');
    assert.equal(res.status, 200);
    const doc = (await res.json()) as { issuer: string; permissions: string[] };
    assert.equal(doc.issuer, ISSUER);
    assert.deepEqual(doc.permissions, ['tg.album.create', 'tg.album.read', 'tg.photo.upload']);
  });

  it('runs the full lifecycle over HTTP: request, consent, redeem, use, revoke', async () => {
    const { verifier, challenge } = pkce();
    const created = await fetchHost('/tg/grant-request', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        version: '0.1',
        permissions: ['tg.album.create', 'tg.album.read'],
        resources: ['album:alb_f1'],
        constraints: [],
        agent_key: agent.publicJwk,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      }),
    });
    assert.equal(created.status, 201);
    const accepted = (await created.json()) as { request_id: string; consent_url: string };

    const consentPage = await fetchHost(`/tg/consent?request_id=${accepted.request_id}`, {
      headers: { cookie: 'session=sess_1' },
    });
    assert.equal(consentPage.status, 200);
    const view = (await consentPage.json()) as { requested: { permissions: string[] } };
    assert.deepEqual(view.requested.permissions, ['tg.album.create', 'tg.album.read']);

    const decided = await fetchHost('/tg/consent/decide', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: 'session=sess_1' },
      body: JSON.stringify({ request_id: accepted.request_id, approve: true }),
    });
    assert.equal(decided.status, 200);

    const redeemed = await fetchHost('/tg/grant-redemption', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ request_id: accepted.request_id, code_verifier: verifier }),
    });
    assert.equal(redeemed.status, 200);
    const grant = (await redeemed.json()) as { grant: string };

    const albumRead = await signedFetch('/albums/alb_f1', grant.grant, { method: 'GET' });
    assert.equal(albumRead.status, 200);
    const receipt = albumRead.headers.get(RECEIPT_HEADER);
    assert.ok(receipt !== null);
    const payload = await verifyReceipt(receipt, {
      resolveSiteKey: { resolve: async () => site.publicJwk },
      issuer: ISSUER,
      audience: ISSUER,
    });
    assert.equal(payload.tg.decision, 'allowed');

    const otherAlbum = await signedFetch('/albums/alb_g9', grant.grant, { method: 'GET' });
    assert.equal(otherAlbum.status, 403);
    const denied = (await otherAlbum.json()) as { error: { code: string } };
    assert.equal(denied.error.code, Codes.REQUEST_RESOURCE_DENIED);

    const status = await fetchHost(`/tg/grant-status?request_id=${accepted.request_id}`);
    assert.equal(((await status.json()) as { status: string }).status, 'active');

    const jti = payload.tg.grant_id;
    await fetchHost('/tg/admin/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: 'session=sess_1' },
      body: JSON.stringify({ grant_id: jti }),
    });
    const afterRevoke = await signedFetch('/albums/alb_f1', grant.grant, { method: 'GET' });
    assert.equal(afterRevoke.status, 403);
    assert.equal(
      ((await afterRevoke.json()) as { error: { code: string } }).error.code,
      Codes.GRANT_REVOKED,
    );
  });
});
