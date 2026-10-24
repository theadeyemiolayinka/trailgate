import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import type { DiscoveryAction } from '@trailgate/core';
import { actionCoverage, siteActions } from './actions.ts';
import { FileDiscoveryCache } from './discovery-cache.ts';
import type { StoredGrantRecord } from './store.ts';

const ISSUER = 'https://shop.example.com';
const NOW = 1_700_000_000;

function grant(overrides: Partial<StoredGrantRecord> = {}): StoredGrantRecord {
  return {
    jti: 'grt_test',
    issuer: ISSUER,
    token: 'x.y.z',
    keyId: 'jkt_test',
    issuedAt: NOW - 60,
    expiresAt: NOW + 3600,
    permissions: [],
    resources: [],
    ...overrides,
  };
}

const CATALOG: DiscoveryAction[] = [
  {
    id: 'cart.read',
    method: 'GET',
    path: '/api/cart',
    permission: 'tg.cart.read',
    description: 'read the shopping cart',
    mutates: false,
    resource: 'cart:{user}',
  },
  {
    id: 'orders.pay',
    method: 'POST',
    path: '/api/orders/{id}/pay',
    permission: 'tg.wallet.charge',
    description: 'pay an order from the wallet',
    resource: 'wallet:{user}',
    spend: true,
  },
  {
    id: 'products.list',
    method: 'GET',
    path: '/api/products',
    permission: 'tg.catalog.read',
    description: 'list the product catalog',
    mutates: false,
  },
];

describe('siteActions', () => {
  it('returns the catalog from a document or an empty list', () => {
    assert.equal(
      siteActions({
        version: '0.1',
        protocol_versions: ['0.1'],
        issuer: ISSUER,
        endpoints: {
          grant_request: 'x',
          grant_redemption: 'x',
          grant_status: 'x',
          grant_revocation: 'x',
        },
        signing_keys: { keys: [] },
        permissions: [],
        constraint_types: [],
        actions: CATALOG,
      }).length,
      3,
    );
    assert.equal(
      siteActions({
        version: '0.1',
        protocol_versions: ['0.1'],
        issuer: ISSUER,
        endpoints: {
          grant_request: 'x',
          grant_redemption: 'x',
          grant_status: 'x',
          grant_revocation: 'x',
        },
        signing_keys: { keys: [] },
        permissions: [],
        constraint_types: [],
      }).length,
      0,
    );
  });
});

describe('actionCoverage', () => {
  it('marks actions covered by permission and resource prefix', () => {
    const coverage = actionCoverage(
      CATALOG,
      [
        grant({ permissions: ['tg.cart.read'], resources: ['cart:cart_usr_demo'] }),
        grant({ jti: 'g2', permissions: ['tg.catalog.read'] }),
      ],
      ISSUER,
      NOW,
    );
    assert.equal(coverage.find((c) => c.action.id === 'cart.read')?.covered, true);
    assert.equal(coverage.find((c) => c.action.id === 'products.list')?.covered, true);
    const pay = coverage.find((c) => c.action.id === 'orders.pay');
    assert.equal(pay?.covered, false);
    assert.deepEqual(pay?.missing, ['tg.wallet.charge']);
  });

  it('reports resource-not-covered separately from missing permission', () => {
    const coverage = actionCoverage(
      CATALOG,
      [grant({ permissions: ['tg.cart.read'], resources: ['order:ord_1'] })],
      ISSUER,
      NOW,
    );
    const cart = coverage.find((c) => c.action.id === 'cart.read');
    assert.equal(cart?.covered, false);
    assert.equal(cart?.missing, undefined, 'permission is held; the resource is not');
  });

  it('ignores expired grants and grants from other issuers', () => {
    const coverage = actionCoverage(
      CATALOG,
      [
        grant({ permissions: ['tg.cart.read'], resources: ['cart:x'], expiresAt: NOW - 1 }),
        grant({
          jti: 'g3',
          issuer: 'https://other.example',
          permissions: ['tg.cart.read'],
          resources: ['cart:x'],
        }),
      ],
      ISSUER,
      NOW,
    );
    assert.equal(coverage.find((c) => c.action.id === 'cart.read')?.covered, false);
  });
});

describe('FileDiscoveryCache', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-cache-'));
  after(() => rmSync(dir, { recursive: true, force: true }));

  const entry = {
    context: {
      origin: ISSUER,
      issuer: ISSUER,
      protocolVersion: '0.1',
      document: { version: '0.1' },
      fetchedAt: NOW,
      cacheMaxAgeSeconds: 60,
    },
    staleAt: NOW + 60,
  };

  it('persists entries across instances', () => {
    const path = join(dir, 'discovery.json');
    const cache = new FileDiscoveryCache(path);
    cache.set(ISSUER, entry as never);
    const reloaded = new FileDiscoveryCache(path);
    assert.equal(reloaded.get(ISSUER)?.staleAt, NOW + 60);
    assert.equal(reloaded.get('https://other.example'), undefined);
  });

  it('drops entries whose stored origin does not match the key', () => {
    const path = join(dir, 'tampered.json');
    writeFileSync(
      path,
      JSON.stringify({
        entries: {
          'https://evil.example': { ...entry, context: { ...entry.context, origin: ISSUER } },
        },
      }),
    );
    const cache = new FileDiscoveryCache(path);
    assert.equal(cache.get('https://evil.example'), undefined);
  });

  it('treats a corrupt file as an empty cache', () => {
    const path = join(dir, 'corrupt.json');
    writeFileSync(path, 'not json{{{');
    const cache = new FileDiscoveryCache(path);
    assert.equal(cache.get(ISSUER), undefined);
  });
});
