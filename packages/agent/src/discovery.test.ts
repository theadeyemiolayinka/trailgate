import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import type { DiscoveryDocument, Jwk } from '@trailgate/core';
import {
  Codes,
  DISCOVERY_PATH,
  DISCOVERY_SIGNATURE_HEADER,
  jwkThumbprint,
  signDiscoveryBody,
  TrailGateError,
} from '@trailgate/core';
import { makeDiscovery } from '@trailgate/test-fixtures';
import { createAgentClient } from './client.ts';
import { discoverSite, resolveSiteUrl, siteKeyResolver } from './discovery.ts';
import { fakeTransport, jsonResponse, textResponse } from './helpers.test.ts';

const ORIGIN = 'https://shop.example.com';

function transportWith(doc: unknown, headers: Record<string, string> = {}) {
  return fakeTransport(() => jsonResponse(200, doc, headers));
}

function makeSiteKey(): { publicJwk: Jwk; privateJwk: Jwk; kid: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' }) as Jwk;
  const publicJwk = publicKey.export({ format: 'jwk' }) as Jwk;
  const kid = jwkThumbprint(publicJwk);
  return { publicJwk: { ...publicJwk, kid }, privateJwk, kid };
}

async function signedTransport(
  doc: Record<string, unknown>,
  signers: { privateJwk: Jwk; kid: string }[],
) {
  const body = JSON.stringify(doc);
  const signatures = await Promise.all(
    signers.map((key) => signDiscoveryBody(body, { ...key, alg: 'EdDSA' })),
  );
  return transportWith(doc, { [DISCOVERY_SIGNATURE_HEADER]: signatures.join(',') });
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
    (doc.endpoints as Record<string, string>).grant_request =
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

describe('discovery signatures and key continuity (spec 5.5)', () => {
  it('verifies a signed document and records the pinning set', async () => {
    const key = makeSiteKey();
    const doc = makeDiscovery({ signing_keys: { keys: [key.publicJwk] } });
    const { transport } = await signedTransport(doc, [key]);
    const ctx = await discoverSite(ORIGIN, { transport });
    assert.equal(ctx.signatureVerified, true);
    assert.deepEqual(ctx.keyThumbprints, [key.kid]);
  });

  it('rejects a garbage signature token', async () => {
    const key = makeSiteKey();
    const doc = makeDiscovery({ signing_keys: { keys: [key.publicJwk] } });
    const { transport } = fakeTransport(() =>
      jsonResponse(200, doc, { [DISCOVERY_SIGNATURE_HEADER]: 'x' }),
    );
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_SIGNATURE_INVALID),
    );
  });

  it('rejects a signature replayed over a tampered body', async () => {
    const key = makeSiteKey();
    const doc = makeDiscovery({ signing_keys: { keys: [key.publicJwk] } });
    const body = JSON.stringify(doc);
    const sig = await signDiscoveryBody(body, { ...key, alg: 'EdDSA' });
    const tampered = { ...doc, permissions: ['tg.admin.all'] };
    const { transport } = fakeTransport(() =>
      jsonResponse(200, tampered, { [DISCOVERY_SIGNATURE_HEADER]: sig }),
    );
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_SIGNATURE_INVALID),
    );
  });

  it('rejects a signature by an unpublished key', async () => {
    const published = makeSiteKey();
    const attacker = makeSiteKey();
    const doc = makeDiscovery({ signing_keys: { keys: [published.publicJwk] } });
    const { transport } = await signedTransport(doc, [attacker]);
    await assert.rejects(discoverSite(ORIGIN, { transport }), (err) =>
      expectTgError(err, Codes.DISCOVERY_SIGNATURE_INVALID),
    );
  });

  it('treats an unsigned document as lower assurance but usable', async () => {
    const { transport } = transportWith(makeDiscovery());
    const ctx = await discoverSite(ORIGIN, { transport });
    assert.equal(ctx.signatureVerified, false);
    assert.equal(ctx.origin, ORIGIN);
  });

  it('accepts a refetch with unchanged keys', async () => {
    const key = makeSiteKey();
    const doc = makeDiscovery({
      signing_keys: { keys: [key.publicJwk] },
    });
    const { transport, requests } = await signedTransport(doc, [key]);
    const first = await discoverSite(ORIGIN, { transport });
    const second = await discoverSite(ORIGIN, {
      transport,
      pinnedSigningKeys: first.document.signing_keys.keys,
    });
    assert.equal(second.signatureVerified, true);
    assert.equal(requests.length, 2);
  });

  it('rejects unendorsed key changes against the pin set', async () => {
    const oldKey = makeSiteKey();
    const newKey = makeSiteKey();
    const oldDoc = makeDiscovery({ signing_keys: { keys: [oldKey.publicJwk] } });
    const newDoc = makeDiscovery({ signing_keys: { keys: [newKey.publicJwk] } });
    // New document signed only by the new key: no endorsement from old.
    const { transport } = await signedTransport(newDoc, [newKey]);
    await assert.rejects(
      discoverSite(ORIGIN, {
        transport,
        pinnedSigningKeys: oldDoc.signing_keys.keys as Jwk[],
      }),
      (err) => expectTgError(err, Codes.DISCOVERY_KEY_CHANGED),
    );
  });

  it('accepts rotation endorsed by a signature under the outgoing key', async () => {
    const oldKey = makeSiteKey();
    const newKey = makeSiteKey();
    const oldDoc = makeDiscovery({ signing_keys: { keys: [oldKey.publicJwk] } });
    // New document lists only the new key but is also signed by the old one.
    const newDoc = makeDiscovery({ signing_keys: { keys: [newKey.publicJwk] } });
    const { transport } = await signedTransport(newDoc, [oldKey, newKey]);
    const ctx = await discoverSite(ORIGIN, {
      transport,
      pinnedSigningKeys: oldDoc.signing_keys.keys as Jwk[],
    });
    assert.equal(ctx.signatureVerified, true);
    assert.deepEqual(ctx.keyThumbprints, [newKey.kid]);
  });

  it('permits unendorsed rotation only with allowKeyRotation', async () => {
    const oldKey = makeSiteKey();
    const newKey = makeSiteKey();
    const oldDoc = makeDiscovery({ signing_keys: { keys: [oldKey.publicJwk] } });
    const newDoc = makeDiscovery({ signing_keys: { keys: [newKey.publicJwk] } });
    const { transport } = await signedTransport(newDoc, [newKey]);
    const ctx = await discoverSite(ORIGIN, {
      transport,
      pinnedSigningKeys: oldDoc.signing_keys.keys as Jwk[],
      allowKeyRotation: true,
    });
    assert.equal(ctx.origin, ORIGIN);
  });

  it('fails closed through the client cache on unendorsed rotation', async () => {
    const oldKey = makeSiteKey();
    const newKey = makeSiteKey();
    const oldDoc = makeDiscovery({ signing_keys: { keys: [oldKey.publicJwk] } });
    const newDoc = makeDiscovery({ signing_keys: { keys: [newKey.publicJwk] } });
    const attackSig = await signDiscoveryBody(JSON.stringify(newDoc), {
      privateJwk: newKey.privateJwk,
      kid: newKey.kid,
      alg: 'EdDSA',
    });
    let call = 0;
    const { transport } = fakeTransport(() => {
      call += 1;
      // no-store forces the second discover to refetch and re-pin.
      if (call === 1) {
        return jsonResponse(200, oldDoc, { 'cache-control': 'no-store' });
      }
      return jsonResponse(200, newDoc, {
        'cache-control': 'no-store',
        [DISCOVERY_SIGNATURE_HEADER]: attackSig,
      });
    });
    const client = createAgentClient({ transport });
    await client.discover(ORIGIN);
    await assert.rejects(client.discover(ORIGIN), (err) =>
      expectTgError(err, Codes.DISCOVERY_KEY_CHANGED),
    );
  });

  it('accepts endorsed rotation through the client cache', async () => {
    const oldKey = makeSiteKey();
    const newKey = makeSiteKey();
    const oldDoc = makeDiscovery({ signing_keys: { keys: [oldKey.publicJwk] } });
    const newDoc = makeDiscovery({ signing_keys: { keys: [newKey.publicJwk] } });
    const body = JSON.stringify(newDoc);
    const sigs = await Promise.all(
      [oldKey, newKey].map((key) =>
        signDiscoveryBody(body, { privateJwk: key.privateJwk, kid: key.kid, alg: 'EdDSA' }),
      ),
    );
    let call = 0;
    const { transport } = fakeTransport(() => {
      call += 1;
      if (call === 1) {
        return jsonResponse(200, oldDoc, { 'cache-control': 'no-store' });
      }
      return jsonResponse(200, newDoc, {
        'cache-control': 'no-store',
        [DISCOVERY_SIGNATURE_HEADER]: sigs.join(','),
      });
    });
    const client = createAgentClient({ transport });
    const first = await client.discover(ORIGIN);
    const second = await client.discover(ORIGIN);
    assert.equal(second.keyThumbprints[0], newKey.kid);
    assert.notDeepEqual(first.keyThumbprints, second.keyThumbprints);
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
    signatureVerified: false,
    keyThumbprints: [],
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
