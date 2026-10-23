import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  FIXTURE_ORIGIN,
  generateEd25519KeyPair,
  makeConstraint,
  makeGrantPayload,
  signCompactJws,
} from '../../test-fixtures/src/index.ts';
import { Codes, TrailGateError } from './errors.ts';
import { GRANT_TYP } from './grant.ts';
import type {
  IdempotencyRecord,
  IdempotencyStore,
  Ledger,
  NonceStore,
  RateLimiter,
  RevocationChecker,
  SitePolicy,
} from './ports.ts';
import { type ProtectedRequest, verifyProtectedRequest } from './request.ts';
import { signRequest } from './signature.ts';

const site = generateEd25519KeyPair();
const SITE_KID = site.jkt;
const agent = generateEd25519KeyPair();
const impostor = generateEd25519KeyPair();
const NOW = 1700000000;
const URL = 'https://shop.example.com/orders';
const BODY = '{"cart_id":"crt_1","item":"sku_1"}';

function memoryNonceStore(): NonceStore {
  const seen = new Map<string, number>();
  return {
    claim: async (grantId, nonce, ttlSeconds) => {
      const key = `${grantId}:${nonce}`;
      const expiry = seen.get(key);
      const now = Math.floor(Date.now() / 1000);
      if (expiry !== undefined && expiry > now) {
        return false;
      }
      seen.set(key, now + ttlSeconds);
      return true;
    },
  };
}

function memoryIdempotency(): IdempotencyStore & {
  store: Map<string, IdempotencyRecord>;
} {
  const store = new Map<string, IdempotencyRecord>();
  return {
    store,
    lookup: async (grantId, key) => store.get(`${grantId}:${key}`),
  };
}

async function makeRequest(
  options: {
    grantOverrides?: Record<string, unknown>;
    payloadExtras?: Record<string, unknown>;
    signOptions?: Record<string, unknown>;
    body?: string;
    url?: string;
    method?: string;
  } = {},
): Promise<{ req: ProtectedRequest; grantId: string }> {
  const grantPayload = {
    ...makeGrantPayload({
      jkt: agent.jkt,
      iat: NOW - 60,
      exp: NOW + 3600,
      permissions: ['tg.order.create'],
      resources: ['order:ord_1'],
      constraints: [makeConstraint('max_amount', { amount: 5000, currency: 'USD' })],
      ...(options.grantOverrides ?? {}),
    }),
    ...(options.payloadExtras ?? {}),
  };
  const grantToken = await signCompactJws(grantPayload, {
    privateJwk: site.privateJwk,
    kid: SITE_KID,
    typ: GRANT_TYP,
  });
  const method = options.method ?? 'POST';
  const url = options.url ?? URL;
  const body = options.body ?? BODY;
  const headers = await signRequest(
    { method, url, body: new TextEncoder().encode(body) },
    {
      privateJwk: agent.privateJwk,
      keyid: agent.jkt,
      created: NOW,
      nonce: `n_${randomBytes(16).toString('base64url')}`,
      grant: grantToken,
      idempotencyKey: 'idem-key-1',
      ...options.signOptions,
    },
  );
  return {
    req: { method, url, headers, body },
    grantId: grantPayload['jti'] as string,
  };
}

function deps(overrides: Record<string, unknown> = {}) {
  return {
    issuer: FIXTURE_ORIGIN,
    audience: FIXTURE_ORIGIN,
    resolveSiteKey: {
      resolve: async (kid: string) => (kid === SITE_KID ? site.publicJwk : undefined),
    },
    resolveAgentKey: {
      resolve: async (jkt: string) =>
        jkt === agent.jkt ? agent.publicJwk : jkt === impostor.jkt ? impostor.publicJwk : undefined,
    },
    revocation: { isRevoked: async () => false } satisfies RevocationChecker,
    nonceStore: memoryNonceStore(),
    clock: { now: () => NOW },
    ...overrides,
  };
}

async function expectCode(code: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError, `expected TrailGateError, got ${String(err)}`);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

describe('verifyProtectedRequest', () => {
  it('accepts a fully valid request', async () => {
    const { req, grantId } = await makeRequest();
    const result = await verifyProtectedRequest(req, deps());
    assert.equal(result.grant.jti, grantId);
    assert.match(result.requestDigest, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(result.idempotentReplay, false);
  });

  it('rejects requests missing required headers', async () => {
    const { req } = await makeRequest();
    const { 'trailgate-grant': _removed, ...headers } = req.headers;
    await expectCode(Codes.REQUEST_MALFORMED, () =>
      verifyProtectedRequest({ ...req, headers }, deps()),
    );
  });

  it('rejects a tampered body via content digest', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.REQUEST_BODY_DIGEST_MISMATCH, () =>
      verifyProtectedRequest({ ...req, body: '{"cart_id":"crt_evil"}' }, deps()),
    );
  });

  it('rejects a tampered url via signature binding', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.REQUEST_SIGNATURE_INVALID, () =>
      verifyProtectedRequest({ ...req, url: 'https://shop.example.com/admin' }, deps()),
    );
  });

  it('rejects keyid that does not match grant key binding', async () => {
    const { req } = await makeRequest({ signOptions: { keyid: impostor.jkt } });
    await expectCode(Codes.REQUEST_KEY_MISMATCH, () => verifyProtectedRequest(req, deps()));
  });

  it('rejects signatures made with the wrong private key', async () => {
    const { req } = await makeRequest({ signOptions: { privateJwk: impostor.privateJwk } });
    await expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => verifyProtectedRequest(req, deps()));
  });

  it('detects nonce replay for the same grant', async () => {
    const nonce = `n_${randomBytes(16).toString('base64url')}`;
    const first = await makeRequest({ signOptions: { nonce } });
    const second = await makeRequest({
      grantOverrides: { jti: first.grantId },
      signOptions: { nonce },
    });
    const shared = deps();
    await verifyProtectedRequest(first.req, shared);
    await expectCode(Codes.REQUEST_REPLAY_DETECTED, () =>
      verifyProtectedRequest(second.req, shared),
    );
  });

  it('does not treat the same nonce under a different grant as replay', async () => {
    const nonce = `n_${randomBytes(16).toString('base64url')}`;
    const first = await makeRequest({ signOptions: { nonce } });
    const second = await makeRequest({ signOptions: { nonce } });
    const shared = deps();
    await verifyProtectedRequest(first.req, shared);
    await verifyProtectedRequest(second.req, shared);
  });

  it('rejects revoked grants', async () => {
    const revoked: RevocationChecker = { isRevoked: async () => true };
    const { req } = await makeRequest();
    await expectCode(Codes.GRANT_REVOKED, () =>
      verifyProtectedRequest(req, deps({ revocation: revoked })),
    );
  });

  it('rejects expired grants', async () => {
    const { req } = await makeRequest({ grantOverrides: { exp: NOW - 1 } });
    await expectCode(Codes.GRANT_EXPIRED, () => verifyProtectedRequest(req, deps()));
  });

  it('rejects grants for another audience', async () => {
    const { req } = await makeRequest({
      grantOverrides: { audience: 'https://other.example.com' },
    });
    await expectCode(Codes.REQUEST_AUDIENCE_MISMATCH, () => verifyProtectedRequest(req, deps()));
  });

  it('rejects unsupported protocol versions in the grant', async () => {
    const { req } = await makeRequest({ grantOverrides: { version: '9.9' } });
    await expectCode(Codes.GRANT_MALFORMED, () => verifyProtectedRequest(req, deps()));
  });

  it('rejects expired signature windows', async () => {
    const { req } = await makeRequest({
      signOptions: { created: NOW - 400, expires: NOW - 340 },
    });
    await expectCode(Codes.REQUEST_EXPIRED, () => verifyProtectedRequest(req, deps()));
  });

  it('denies requests without the required permission', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.REQUEST_PERMISSION_DENIED, () =>
      verifyProtectedRequest(req, deps({ requiredPermission: 'tg.wallet.charge' })),
    );
  });

  it('denies resources outside the grant scope', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.REQUEST_RESOURCE_DENIED, () =>
      verifyProtectedRequest(
        req,
        deps({
          touchedResource: 'order:ord_999',
          resourceOwners: { ownerOf: async () => 'sub_1' },
        }),
      ),
    );
  });

  it('denies resources owned by another subject', async () => {
    const { req } = await makeRequest({ grantOverrides: { sub: 'sub_1' } });
    await expectCode(Codes.REQUEST_RESOURCE_DENIED, () =>
      verifyProtectedRequest(
        req,
        deps({
          touchedResource: 'order:ord_1',
          resourceOwners: { ownerOf: async () => 'sub_other' },
        }),
      ),
    );
  });

  it('accepts in-scope resources owned by the grant subject', async () => {
    const { req } = await makeRequest({ grantOverrides: { sub: 'sub_1' } });
    const result = await verifyProtectedRequest(
      req,
      deps({
        touchedResource: 'order:ord_1',
        resourceOwners: { ownerOf: async () => 'sub_1' },
      }),
    );
    assert.equal(result.context.subject, 'sub_1');
  });

  it('enforces grant constraints against the request amount', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      verifyProtectedRequest(req, deps({ requestAmount: { amount: 9000, currency: 'USD' } })),
    );
  });

  it('evaluates cumulative budget through the ledger port', async () => {
    const budgetLedger: Ledger = {
      consumedMinorUnits: async () => 4900,
      reservedMinorUnits: async () => 0,
    };
    const { req } = await makeRequest({
      grantOverrides: {
        constraints: [makeConstraint('cumulative_budget', { amount: 5000, currency: 'USD' })],
      },
    });
    await verifyProtectedRequest(
      req,
      deps({ ledger: budgetLedger, requestAmount: { amount: 100, currency: 'USD' } }),
    );
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      verifyProtectedRequest(
        req,
        deps({ ledger: budgetLedger, requestAmount: { amount: 200, currency: 'USD' } }),
      ),
    );
  });

  it('reports stored outcomes for identical operations', async () => {
    const idem = memoryIdempotency();
    const { req, grantId } = await makeRequest();
    const operationDigest = createHash('sha256')
      .update(`POST ${URL} ${req.headers['content-digest']} ${grantId}`, 'utf8')
      .digest('base64url');
    idem.store.set(`${grantId}:idem-key-1`, { requestDigest: operationDigest });
    const result = await verifyProtectedRequest(req, deps({ idempotency: idem }));
    assert.equal(result.idempotentReplay, true);
  });

  it('conflicts when an idempotency key is reused with a different operation', async () => {
    const idem = memoryIdempotency();
    const { req, grantId } = await makeRequest();
    idem.store.set(`${grantId}:idem-key-1`, { requestDigest: 'different' });
    await expectCode(Codes.REQUEST_IDEMPOTENCY_CONFLICT, () =>
      verifyProtectedRequest(req, deps({ idempotency: idem })),
    );
  });

  it('lets the site policy reject after all checks pass', async () => {
    const policy: SitePolicy = {
      authorize: async () => {
        throw new TrailGateError(Codes.AUTHORIZATION_DENIED, 'site policy: closed beta');
      },
    };
    const { req } = await makeRequest();
    await expectCode(Codes.AUTHORIZATION_DENIED, () =>
      verifyProtectedRequest(req, deps({ policy })),
    );
  });

  it('rejects short nonces', async () => {
    const { req } = await makeRequest({ signOptions: { nonce: 'short' } });
    await expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => verifyProtectedRequest(req, deps()));
  });

  it('rejects grants carrying permissions outside the site vocabulary', async () => {
    const { req } = await makeRequest();
    await expectCode(Codes.GRANT_MALFORMED, () =>
      verifyProtectedRequest(req, deps({ permissionVocabulary: ['tg.wallet.charge'] })),
    );
  });

  it('rejects grants declaring unknown critical fields', async () => {
    const { req } = await makeRequest({ payloadExtras: { critical: ['unseen_field'] } });
    await expectCode(Codes.GRANT_MALFORMED, () => verifyProtectedRequest(req, deps()));
  });

  it('enforces rate limit constraints through the limiter port', async () => {
    const rateLimiter: RateLimiter = { countInWindow: async () => 60 };
    const { req } = await makeRequest({
      grantOverrides: {
        constraints: [makeConstraint('rate_limit', { max_requests: 60, window_seconds: 3600 })],
      },
    });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      verifyProtectedRequest(req, deps({ rateLimiter })),
    );
  });
});
