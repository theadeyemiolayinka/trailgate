import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError, validateDiscoveryDocument } from '@trailgate/core';
import { generateEd25519KeyPair } from '@trailgate/test-fixtures';
import { createTrailGateServer } from './server.ts';

const ISSUER = 'https://shop.example.com';
const site = generateEd25519KeyPair();

function makeServer(overrides: Record<string, unknown> = {}) {
  return createTrailGateServer({
    issuer: ISSUER,
    signingKeys: [{ privateJwk: site.privateJwk }],
    permissions: ['tg.order.create'],
    ...overrides,
  });
}

describe('discovery document', () => {
  it('produces a schema-valid, same-origin document', () => {
    const server = makeServer();
    const doc = server.discoveryDocument();
    assert.equal(doc.issuer, ISSUER);
    assert.equal(doc.version, '0.1');
    assert.deepEqual(doc.protocol_versions, ['0.1']);
    for (const url of Object.values(doc.endpoints)) {
      assert.ok(url.startsWith(`${ISSUER}/`), `endpoint ${url} must share the issuer origin`);
    }
    assert.deepEqual(doc.permissions, ['tg.order.create']);
    assert.equal(doc.signing_keys.keys.length, 1);
    const key = doc.signing_keys.keys[0];
    assert.equal(key?.kid, site.jkt);
    assert.equal(key?.d, undefined, 'private key material must never be published');
    const validated = validateDiscoveryDocument(doc, {
      expectedOrigin: ISSUER,
      supportedProtocolVersions: ['0.1'],
    });
    assert.deepEqual(validated.endpoints, doc.endpoints);
  });

  it('honors custom paths, capabilities, and extensions', () => {
    const server = makeServer({
      paths: { grantRequest: '/api/tg/request' },
      capabilities: { supports_redirect: true },
      maxGrantSeconds: 7200,
      discoveryExtensions: { 'x-site': 'trailgate-demo' },
    });
    const doc = server.discoveryDocument();
    assert.equal(doc.endpoints.grant_request, `${ISSUER}/api/tg/request`);
    assert.equal(doc.capabilities?.supports_redirect, true);
    assert.equal(doc.capabilities?.max_grant_seconds, 7200);
    assert.equal(doc['x-site'], 'trailgate-demo');
  });

  it('advertises protect()-declared actions derived from the route protection', () => {
    const server = makeServer();
    server.protect(
      {
        permission: 'tg.order.create',
        mutating: false,
        action: {
          id: 'orders.create',
          method: 'POST',
          path: '/api/orders',
          description: 'place an order',
          resource: 'order:{id}',
          spend: true,
        },
      },
      () => ({ status: 200 }),
    );
    const doc = server.discoveryDocument();
    const actions = doc.actions;
    assert.equal(actions?.length, 1);
    assert.deepEqual(actions?.[0], {
      id: 'orders.create',
      method: 'POST',
      path: '/api/orders',
      permission: 'tg.order.create',
      description: 'place an order',
      mutates: false,
      resource: 'order:{id}',
      spend: true,
    });
    const validated = validateDiscoveryDocument(doc, {
      expectedOrigin: ISSUER,
      supportedProtocolVersions: ['0.1'],
    });
    assert.equal(validated.actions?.length, 1);
  });

  it('rejects malformed or conflicting action declarations at protect() time', () => {
    const server = makeServer();
    assert.throws(
      () =>
        server.protect(
          {
            permission: 'tg.order.create',
            action: { id: 'bad', method: 'post', path: '/x', description: 'bad method' },
          },
          () => ({ status: 200 }),
        ),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
    assert.throws(
      () =>
        server.protect(
          {
            permission: 'tg.order.create',
            action: {
              id: 'bad2',
              method: 'POST',
              path: 'https://evil.example/x',
              description: 'bad path',
            },
          },
          () => ({ status: 200 }),
        ),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
    server.protect(
      {
        permission: 'tg.order.create',
        action: { id: 'dup', method: 'GET', path: '/a', description: 'first' },
      },
      () => ({ status: 200 }),
    );
    assert.throws(
      () =>
        server.protect(
          {
            permission: 'tg.order.create',
            action: { id: 'dup', method: 'POST', path: '/b', description: 'second' },
          },
          () => ({ status: 200 }),
        ),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });

  it('rejects an action without a description', () => {
    const server = makeServer();
    assert.throws(
      () =>
        server.protect(
          {
            permission: 'tg.order.create',
            action: { id: 'nodesc', method: 'GET', path: '/a', description: '' },
          },
          () => ({ status: 200 }),
        ),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });

  it('rejects an action whose permission is outside the site vocabulary', () => {
    const server = makeServer();
    assert.throws(
      () =>
        server.protect(
          {
            permission: 'tg.wallet.charge',
            action: { id: 'wallet.charge', method: 'POST', path: '/pay', description: 'charge' },
          },
          () => ({ status: 200 }),
        ),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });

  it('rejects a non-https issuer at configuration time', () => {
    assert.throws(
      () =>
        createTrailGateServer({
          issuer: 'http://shop.example.com',
          signingKeys: [{ privateJwk: site.privateJwk }],
          permissions: [],
        }),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });

  it('rejects a configuration without signing keys', () => {
    assert.throws(
      () =>
        createTrailGateServer({
          issuer: ISSUER,
          signingKeys: [],
          permissions: [],
        }),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });

  it('rejects an out-of-bounds signature tolerance', () => {
    assert.throws(
      () =>
        createTrailGateServer({
          issuer: ISSUER,
          signingKeys: [{ privateJwk: site.privateJwk }],
          permissions: [],
          toleranceSeconds: 121,
        }),
      (err: unknown) => err instanceof TrailGateError && err.code === Codes.INTERNAL_ERROR,
    );
  });
});
