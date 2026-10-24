import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { DiscoveryDocument } from '@trailgate/core';
import { Codes, DISCOVERY_PATH, jwkThumbprint, TrailGateError } from '@trailgate/core';
import { makeDiscovery } from '@trailgate/test-fixtures';
import { createAgentClient } from './client.ts';
import { discoverSite, resolveSiteUrl, siteKeyResolver } from './discovery.ts';
import { fakeTransport, jsonResponse, textResponse } from './helpers.test.ts';

const ORIGIN = 'https://shop.example.com';

function transportWith(doc: unknown, headers: Record<string, string> = {}) {
  return fakeTransport(() => jsonResponse(200, doc, headers));
}

function expectTgError(err: unknown, code: string): boolean {
  return err instanceof TrailGateError && err.code === code;
}

describe('discoverSite', () => {
  it('fetches and validates a well-formed document', async () => {
    const doc = makeDiscovery();
    const { transport, requests } = transportWith(doc);
    const ctx = await discoverSite(ORIGIN, { transport });
    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.url, `${ORIGIN}${DISCOVERY_PATH}`);
    assert.equal(requests[0]?.method, 'GET');
    assert.equal(ctx.origin, ORIGIN);
    assert.equal(ctx.issuer, ORIGIN);
    assert.equal(ctx.protocolVersion, '0.1');
    assert.deepEqual(ctx.document.permissions, [
      'tg.cart.read',
      'tg.order.create',
      'tg.wallet.charge',
    ]);
    assert.ok(ctx.cacheMaxAgeSeconds > 0);
  });

  it('normalizes a full URL to its origin', async () => {
    const { transport, requests } = transportWith(makeDiscovery());
    const ctx = await discoverSite(`${ORIGIN}/products/42?sort=asc`, { transport });
    assert.equal(ctx.origin, ORIGIN);
    assert.equal(requests[0]?.url, `${ORIGIN}${DISCOVERY_PATH}`);
  });

  it('rejects a non-https target before any fetch', async () => {
    const { transport, requests } = transportWith(makeDiscovery());
    await assert.rejects(discoverSite('http://shop.example.com', { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
    assert.equal(requests.length, 0);
  });

  it('rejects a redirect response', async () => {
    const { transport } = fakeTransport(() =>
      textResponse(302, '', { location: 'https://evil.example.com/tg' }),
    );
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
  });

  it('rejects a non-200 response', async () => {
    const { transport } = fakeTransport(() => textResponse(404, 'not found'));
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
  });

  it('rejects an invalid document', async () => {
    const { transport } = transportWith({ version: '0.1' });
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
  });

  it('rejects a document with a cross-origin endpoint', async () => {
    const doc = makeDiscovery();
    (doc['endpoints'] as Record<string, string>)['grant_request'] =
      'https://evil.example.com/tg/grant-request';
    const { transport } = transportWith(doc);
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
  });

  it('rejects a document with no common protocol version', async () => {
    const { transport } = transportWith(makeDiscovery({ protocol_versions: ['9.9'] }));
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_UNSUPPORTED_VERSION),
    );
  });

  it('rejects a document over the size limit', async () => {
    const { transport } = transportWith(makeDiscovery());
    await assert.rejects(discoverSite(ORIGIN, { transport, maxBodyBytes: 10 }), (err) =>
      expectTgError(err, Codes.DISCOVERY_INVALID),
    );
  });
});

describe('discovery caching (client)', () => {
  it('serves a second discover from cache', async () => {
    const { transport, requests } = transportWith(makeDiscovery());
    const client = createAgentClient({ transport });
    await client.discover(ORIGIN);
    await client.discover(ORIGIN);
    assert.equal(requests.length, 1);
  });

  it('refetches when the site sends no-store', async () => {
    const { transport, requests } = transportWith(makeDiscovery(), {
      'cache-control': 'no-store',
    });
    const client = createAgentClient({ transport });
    await client.discover(ORIGIN);
    await client.discover(ORIGIN);
    assert.equal(requests.length, 2);
  });

  it('refetches on explicit refresh', async () => {
    const { transport, requests } = transportWith(makeDiscovery());
    const client = createAgentClient({ transport });
    await client.discover(ORIGIN);
    await client.discover(ORIGIN, { refresh: true });
    assert.equal(requests.length, 2);
  });

  it('refetches automatically once the cached document ages out', async () => {
    let now = 1_700_000_000;
    const { transport, requests } = transportWith(makeDiscovery(), {
      'cache-control': 'max-age=60',
    });
    const client = createAgentClient({ transport, clock: { now: () => now } });
    await client.discover(ORIGIN);
    await client.discover(ORIGIN);
    assert.equal(requests.length, 1, 'within max-age the cache serves');
    now += 61;
    await client.discover(ORIGIN);
    assert.equal(requests.length, 2, 'past max-age the document refetches');
  });
});

describe('resolveSiteUrl', () => {
  const ctx = {
    origin: ORIGIN,
    issuer: ORIGIN,
    protocolVersion: '0.1',
    document: makeDiscovery() as DiscoveryDocument,
    fetchedAt: 0,
    cacheMaxAgeSeconds: 3600,
  };

  it('resolves site-relative paths', () => {
    assert.equal(resolveSiteUrl(ctx, '/api/orders'), `${ORIGIN}/api/orders`);
    assert.equal(resolveSiteUrl(ctx, '/api?a=1'), `${ORIGIN}/api?a=1`);
  });

  it('accepts same-origin absolute urls', () => {
    assert.equal(resolveSiteUrl(ctx, `${ORIGIN}/api`), `${ORIGIN}/api`);
  });

  it('rejects cross-origin urls', () => {
    assert.throws(
      () => resolveSiteUrl(ctx, 'https://evil.example.com/api'),
      (err) => expectTgError(err, Codes.REQUEST_MALFORMED),
    );
    assert.throws(
      () => resolveSiteUrl(ctx, '//evil.example.com/api'),
      (err) => expectTgError(err, Codes.REQUEST_MALFORMED),
    );
  });
});

describe('siteKeyResolver', () => {
  it('resolves published keys by thumbprint kid', async () => {
    const doc = makeDiscovery() as DiscoveryDocument;
    const resolver = siteKeyResolver(doc);
    assert.equal(await resolver.resolve('not-a-real-thumbprint'), undefined);
    const published = doc.signing_keys.keys[0];
    const jkt = jwkThumbprint(published ?? { kty: 'OKP' });
    assert.equal(await resolver.resolve(jkt), published);
  });
});
