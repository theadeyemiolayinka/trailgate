import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { DiscoveryDocument, Jwk } from '@trailgate/core';
import {
  buildReceiptPayload,
  buildSignatureBase,
  Codes,
  computeContentDigest,
  fixedClock,
  getSignatureBytes,
  parseTgSignatureInput,
  publicKeyFromJwk,
  REQUIRED_COVERED_COMPONENTS,
  signReceipt,
  signRequest,
  TrailGateError,
  verifyProtectedRequest,
  verifySignatureBytes,
} from '@trailgate/core';
import {
  generateEd25519KeyPair,
  makeDiscovery,
  makeGrantPayload,
  signCompactJws,
} from '@trailgate/test-fixtures';
import type { SiteContext } from './discovery.ts';
import { fakeTransport, jsonResponse } from './helpers.test.ts';
import { SoftwareKeyProvider } from './keys.ts';
import { buildProtectedRequestHeaders, executeProtectedRequest, responseJson } from './request.ts';
import { recordFromGrantToken } from './store.ts';

const ORIGIN = 'https://shop.example.com';
const siteKey = generateEd25519KeyPair();
const agentPair = generateEd25519KeyPair();

function discovery(): DiscoveryDocument {
  const doc = makeDiscovery() as DiscoveryDocument;
  doc.signing_keys = { keys: [siteKey.publicJwk] };
  return doc;
}

function site(): SiteContext {
  return {
    origin: ORIGIN,
    issuer: ORIGIN,
    protocolVersion: '0.1',
    document: discovery(),
    fetchedAt: 0,
    cacheMaxAgeSeconds: 3600,
  };
}

async function grantTokenFor(jkt: string, overrides: Record<string, unknown> = {}) {
  const payload = makeGrantPayload({ jkt, ...overrides });
  return signCompactJws(payload, {
    privateJwk: siteKey.privateJwk,
    kid: siteKey.jkt,
    typ: 'trailgate-grant+jwt',
  });
}

describe('buildProtectedRequestHeaders', () => {
  it('produces the spec section 11.2 profile and a valid signature', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const token = await grantTokenFor(signer.jkt);
    const url = `${ORIGIN}/api/orders?x=1`;
    const body = new TextEncoder().encode('{"item":1}');
    const { headers, signatureBase } = await buildProtectedRequestHeaders(
      { method: 'POST', url, body },
      token,
      signer,
      { nonce: 'test-nonce-with-128-bits-minimum', idempotencyKey: 'idem_1' },
      fixedClock(1_700_000_000),
    );
    for (const name of [
      'content-digest',
      'trailgate-grant',
      'idempotency-key',
      'signature-input',
      'signature',
    ]) {
      assert.ok(headers[name] !== undefined, `missing ${name}`);
    }
    assert.equal(headers['content-digest'], computeContentDigest(body));
    assert.equal(headers['trailgate-grant'], token);
    assert.equal(headers['idempotency-key'], 'idem_1');

    const parsed = parseTgSignatureInput(headers['signature-input'] as string);
    assert.deepEqual(parsed.components, [...REQUIRED_COVERED_COMPONENTS]);
    assert.equal(parsed.params.keyid, signer.jkt);
    assert.equal(parsed.params.alg, 'ed25519');
    assert.equal(parsed.params.tag, 'trailgate');
    assert.equal(parsed.params.created, 1_700_000_000);

    const rebuilt = buildSignatureBase(
      { method: 'POST', url, headers },
      parsed.components,
      parsed.entry,
    );
    const ok = verifySignatureBytes(
      'ed25519',
      publicKeyFromJwk(signer.publicJwk),
      getSignatureBytes(headers['signature'] as string),
      rebuilt,
    );
    assert.equal(ok, true, 'signature must verify under the agent public key');
    assert.equal(signatureBase, rebuilt);
  });

  it('emits headers identical to core signRequest for Ed25519', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const token = await grantTokenFor(signer.jkt);
    const req = { method: 'POST', url: `${ORIGIN}/api`, body: new Uint8Array([1, 2, 3]) };
    const options = {
      nonce: 'fixed-nonce-000000000000000',
      created: 1_700_000_000,
      expires: 1_700_000_060,
      idempotencyKey: 'idem_fixed',
    };
    const ours = await buildProtectedRequestHeaders(req, token, signer, options);
    const theirs = await signRequest(req, {
      privateJwk: agentPair.privateJwk as Jwk,
      keyid: signer.jkt,
      grant: token,
      ...options,
    });
    assert.deepEqual(ours.headers, theirs);
  });
});

describe('executeProtectedRequest', () => {
  it('rejects a target outside the site origin', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const grant = recordFromGrantToken(await grantTokenFor(signer.jkt));
    const { transport } = fakeTransport(() => jsonResponse(200, {}));
    await assert.rejects(
      executeProtectedRequest(
        site(),
        grant,
        signer,
        { method: 'GET', target: 'https://evil.example.com/api' },
        { transport },
      ),
      (err) => err instanceof TrailGateError && err.code === Codes.REQUEST_MALFORMED,
    );
  });

  it('rejects a signer bound to a different key', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const other = SoftwareKeyProvider.generate();
    const grant = recordFromGrantToken(await grantTokenFor(signer.jkt));
    await assert.rejects(
      executeProtectedRequest(
        site(),
        grant,
        other,
        { method: 'GET', target: '/api' },
        {
          transport: fakeTransport(() => jsonResponse(200, {})).transport,
        },
      ),
      (err) => err instanceof TrailGateError && err.code === Codes.REQUEST_KEY_MISMATCH,
    );
  });

  it('passes server-side verification and verifies the receipt', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const token = await grantTokenFor(signer.jkt, { permissions: ['tg.order.create'] });
    const grant = recordFromGrantToken(token);

    const { transport, requests } = fakeTransport(async (req) => {
      // The same pipeline the server SDK runs (spec section 11.3).
      const result = await verifyProtectedRequest(
        { method: req.method, url: req.url, headers: req.headers ?? {}, body: req.body },
        {
          issuer: ORIGIN,
          audience: ORIGIN,
          resolveSiteKey: {
            resolve: async (kid) => (kid === siteKey.jkt ? siteKey.publicJwk : undefined),
          },
          resolveAgentKey: {
            resolve: async (jkt) => (jkt === signer.jkt ? signer.publicJwk : undefined),
          },
          revocation: { isRevoked: async () => false },
          nonceStore: { claim: async () => true },
          requiredPermission: 'tg.order.create',
        },
      );
      const receiptPayload = buildReceiptPayload({
        issuer: ORIGIN,
        audience: ORIGIN,
        grantId: result.grant.jti,
        signatureBase: result.signatureBase,
        decision: 'allowed',
        auditId: 'aud_1',
        now: Math.floor(Date.now() / 1000),
      });
      const receipt = await signReceipt(receiptPayload, {
        privateJwk: siteKey.privateJwk as Jwk,
        kid: siteKey.jkt,
      });
      return jsonResponse(200, { ok: true }, { 'trailgate-receipt': receipt });
    });

    const res = await executeProtectedRequest(
      site(),
      grant,
      signer,
      { method: 'POST', target: '/api/orders', body: '{"a":1}', idempotencyKey: 'k1' },
      { transport },
    );
    assert.equal(res.status, 200);
    assert.equal(res.error, undefined);
    assert.deepEqual(responseJson(res), { ok: true });
    assert.equal(res.receipt?.verified, true);
    if (res.receipt?.verified === true) {
      assert.equal(res.receipt.payload.tg.decision, 'allowed');
      assert.equal(res.receipt.payload.tg.grant_id, grant.jti);
    }
    const sent = requests[0];
    assert.equal(sent?.method, 'POST');
    assert.equal(sent?.url, `${ORIGIN}/api/orders`);
  });

  it('surfaces the site error envelope as data', async () => {
    const signer = SoftwareKeyProvider.fromPrivateJwk(agentPair.privateJwk);
    const grant = recordFromGrantToken(await grantTokenFor(signer.jkt));
    const { transport } = fakeTransport(() =>
      jsonResponse(403, {
        error: { code: 'tg.request.permission_denied', message: 'not granted' },
      }),
    );
    const res = await executeProtectedRequest(
      site(),
      grant,
      signer,
      { method: 'POST', target: '/api/orders' },
      { transport },
    );
    assert.equal(res.status, 403);
    assert.equal(res.error?.code, 'tg.request.permission_denied');
  });
});
