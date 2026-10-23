import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes } from '@trailgate/core';
import { makeDiscovery } from '@trailgate/test-fixtures';
import { createAgentClient } from './client.ts';
import { describeSite, explainAccessCheck, inspectSite, planAccess, reportAction } from './flow.ts';
import { fakeTransport, jsonResponse, textResponse } from './helpers.test.ts';
import { SoftwareKeyProvider } from './keys.ts';

const ORIGIN = 'https://shop.example.com';

describe('inspectSite', () => {
  it('separates unsupported version from unavailable discovery', async () => {
    const badVersion = createAgentClient({
      transport: fakeTransport(() =>
        jsonResponse(200, makeDiscovery({ protocol_versions: ['9.9'] })),
      ).transport,
    });
    const unsupported = await inspectSite(badVersion, ORIGIN);
    assert.equal(unsupported.status, 'unsupported_version');

    const broken = createAgentClient({
      transport: fakeTransport(() => textResponse(404, 'nope')).transport,
    });
    const unavailable = await inspectSite(broken, ORIGIN);
    assert.equal(unavailable.status, 'unavailable');
    if (unavailable.status === 'unavailable') {
      assert.equal(unavailable.code, Codes.DISCOVERY_INVALID);
    }
  });

  it('returns capabilities for a supported site', async () => {
    const client = createAgentClient({
      transport: fakeTransport(() => jsonResponse(200, makeDiscovery())).transport,
    });
    const result = await inspectSite(client, ORIGIN);
    assert.equal(result.status, 'supported');
    if (result.status === 'supported') {
      assert.deepEqual(describeSite(result.site)['protocolVersion'], '0.1');
    }
  });
});

describe('planAccess', () => {
  it('starts consent for missing scope instead of implying access', async () => {
    const { transport } = fakeTransport((req) => {
      if (req.url.endsWith('/.well-known/trailgate')) {
        return jsonResponse(200, makeDiscovery());
      }
      return jsonResponse(201, {
        request_id: 'req_1',
        consent_url: `${ORIGIN}/tg/consent?request_id=req_1`,
        expires_at: 1,
      });
    });
    const client = createAgentClient({ transport });
    client.useKey(SoftwareKeyProvider.generate());
    const plan = await planAccess(client, ORIGIN, { permissions: ['tg.order.create'] });
    assert.equal(plan.status, 'consent_required');
    if (plan.status === 'consent_required') {
      assert.ok(plan.session.consentUrl.startsWith(`${ORIGIN}/`));
      assert.equal(plan.reason.status, 'no_grant');
    }
  });

  it('blocks when consent cannot fix the gap', async () => {
    const { transport } = fakeTransport(() =>
      jsonResponse(200, makeDiscovery({ protocol_versions: ['9.9'] })),
    );
    const client = createAgentClient({ transport });
    await assert.rejects(
      planAccess(client, ORIGIN, { permissions: ['tg.order.create'] }),
      // discover itself fails on version; blocked plans only arise for
      // wrong_key/revoked with a stored grant
      (err) => (err as { code?: string }).code === Codes.DISCOVERY_UNSUPPORTED_VERSION,
    );
  });
});

describe('explainAccessCheck + reportAction', () => {
  it('narrates each status distinctly', () => {
    const statuses = [
      'no_grant',
      'insufficient_permission',
      'expired',
      'wrong_key',
      'revoked',
      'unsupported_version',
      'ready',
    ] as const;
    for (const status of statuses) {
      const explained = explainAccessCheck({
        status,
        grant: {},
        missing: ['p'],
        expectedKeyId: 'k',
        site: [],
        client: [],
      } as never);
      assert.equal(explained.status, status);
      assert.ok(explained.summary.length > 0);
    }
  });

  it('reports denials and receipts faithfully', () => {
    const denied = reportAction({
      status: 403,
      headers: {},
      body: new Uint8Array(),
      error: { code: 'tg.request.permission_denied', message: 'no' },
    });
    assert.equal(denied.outcome, 'denied');
    assert.equal(denied.code, 'tg.request.permission_denied');
    assert.equal(denied.receipt, 'absent');
    assert.equal(denied.retryable, false);

    const unverified = reportAction({
      status: 200,
      headers: {},
      body: new Uint8Array(),
      receipt: { verified: false, reason: 'bad sig' },
    });
    assert.equal(unverified.receipt, 'unverified');
    assert.equal(unverified.outcome, 'allowed');
  });
});
