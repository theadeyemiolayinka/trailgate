import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { DiscoveryDocument } from '@trailgate/core';
import { fixedClock } from '@trailgate/core';
import {
  generateEd25519KeyPair,
  makeDiscovery,
  makeGrantPayload,
  signCompactJws,
} from '@trailgate/test-fixtures';
import { checkAccess, checkAccessAsync } from './access.ts';
import type { SiteContext } from './discovery.ts';
import { SoftwareKeyProvider } from './keys.ts';
import { recordFromGrantToken, type StoredGrantRecord } from './store.ts';

const ORIGIN = 'https://shop.example.com';
const siteKey = generateEd25519KeyPair();
const signer = SoftwareKeyProvider.generate();
const signers = new Map([[signer.jkt, signer]]);
const NOW = 1_800_000_000;

function site(protocolVersions: string[] = ['0.1']): SiteContext {
  const doc = makeDiscovery() as DiscoveryDocument;
  doc.protocol_versions = protocolVersions;
  return {
    origin: ORIGIN,
    issuer: ORIGIN,
    protocolVersion: '0.1',
    document: doc,
    fetchedAt: NOW,
    cacheMaxAgeSeconds: 3600,
  };
}

async function grant(overrides: Record<string, unknown> = {}): Promise<StoredGrantRecord> {
  const token = await signCompactJws(
    makeGrantPayload({ jkt: signer.jkt, exp: NOW + 3600, iat: NOW - 60, ...overrides }),
    { privateJwk: siteKey.privateJwk, kid: siteKey.jkt, typ: 'trailgate-grant+jwt' },
  );
  return recordFromGrantToken(token);
}

const deps = { clock: fixedClock(NOW), signers };

describe('checkAccess', () => {
  it('reports ready with the signable grant', async () => {
    const g = await grant();
    const result = checkAccess(site(), [g], { permissions: ['tg.order.create'] }, deps);
    assert.equal(result.status, 'ready');
    if (result.status === 'ready') {
      assert.equal(result.grant.jti, g.jti);
      assert.equal(result.signer.jkt, signer.jkt);
    }
  });

  it('reports unsupported_version before looking at grants', async () => {
    const g = await grant();
    const result = checkAccess(site(['9.9']), [g], {}, deps);
    assert.equal(result.status, 'unsupported_version');
    if (result.status === 'unsupported_version') {
      assert.deepEqual(result.site, ['9.9']);
      assert.deepEqual(result.client, ['0.1']);
    }
  });

  it('reports no_grant when nothing is stored for the issuer', async () => {
    const other = await grant({ issuer: 'https://other.example.com' });
    const result = checkAccess(site(), [other], {}, deps);
    assert.equal(result.status, 'no_grant');
    if (result.status === 'no_grant') {
      assert.equal(result.issuer, ORIGIN);
    }
  });

  it('reports insufficient_permission with the missing names', async () => {
    const g = await grant({ permissions: ['tg.cart.read'] });
    const result = checkAccess(
      site(),
      [g],
      { permissions: ['tg.order.create', 'tg.pay.charge'] },
      deps,
    );
    assert.equal(result.status, 'insufficient_permission');
    if (result.status === 'insufficient_permission') {
      assert.deepEqual(result.missing, ['tg.order.create', 'tg.pay.charge']);
    }
  });

  it('reports expired when exp has passed', async () => {
    const g = await grant({ iat: NOW - 7200, exp: NOW - 10 });
    const result = checkAccess(site(), [g], {}, deps);
    assert.equal(result.status, 'expired');
  });

  it('reports wrong_key when the bound key has no registered signer', async () => {
    const foreign = generateEd25519KeyPair();
    const token = await signCompactJws(
      makeGrantPayload({ jkt: foreign.jkt, exp: NOW + 3600, iat: NOW - 60 }),
      { privateJwk: siteKey.privateJwk, kid: siteKey.jkt, typ: 'trailgate-grant+jwt' },
    );
    const g = recordFromGrantToken(token);
    const result = checkAccess(site(), [g], {}, deps);
    assert.equal(result.status, 'wrong_key');
    if (result.status === 'wrong_key') {
      assert.equal(result.expectedKeyId, foreign.jkt);
    }
  });

  it('restricts by keyId when given', async () => {
    const g = await grant();
    const result = checkAccess(site(), [g], { keyId: 'jkt_other' }, deps);
    assert.equal(result.status, 'no_grant');
  });

  it('confirms revocation live when confirmFresh is set', async () => {
    const g = await grant();
    const result = await checkAccessAsync(
      site(),
      [g],
      { confirmFresh: true },
      {
        ...deps,
        statusOf: async () => ({ status: 'revoked' }),
      },
    );
    assert.equal(result.status, 'revoked');
  });

  it('stays ready when the fresh status is active', async () => {
    const g = await grant();
    const result = await checkAccessAsync(
      site(),
      [g],
      { confirmFresh: true },
      {
        ...deps,
        statusOf: async () => ({ status: 'active' }),
      },
    );
    assert.equal(result.status, 'ready');
  });

  it('adopts scope the site added after granting when confirmFresh is set', async () => {
    const g = await grant();
    // The stored grant covers tg.order.create only; the site now reports
    // wallet access too, so the local check becomes ready.
    const result = await checkAccessAsync(
      site(),
      [g],
      { confirmFresh: true, permissions: ['tg.order.create', 'tg.wallet.charge'] },
      {
        ...deps,
        statusOf: async () => ({
          status: 'active',
          permissions: ['tg.order.create', 'tg.wallet.charge'],
        }),
      },
    );
    assert.equal(result.status, 'ready');
    // Without the fresh lookup the same criteria stays insufficient.
    const stale = checkAccess(site(), [g], {
      permissions: ['tg.order.create', 'tg.wallet.charge'],
    });
    assert.equal(stale.status, 'insufficient_permission');
  });

  it('does not downgrade ready when the status lookup fails', async () => {
    const g = await grant();
    const result = await checkAccessAsync(
      site(),
      [g],
      { confirmFresh: true },
      {
        ...deps,
        statusOf: async () => {
          throw new Error('offline');
        },
      },
    );
    assert.equal(result.status, 'ready');
  });
});
