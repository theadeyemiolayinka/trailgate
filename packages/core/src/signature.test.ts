import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateEd25519KeyPair, generateP256KeyPair } from '../../test-fixtures/src/keys.ts';
import { Codes, TrailGateError } from './errors.ts';
import {
  buildSignatureBase,
  checkNonceShape,
  checkSignatureWindow,
  getSignatureBytes,
  parseTgSignatureInput,
  publicKeyFromJwk,
  signRequest,
  verifySignatureBytes,
} from './signature.ts';

const URL = 'https://shop.example.com/orders?expand=items';
const BODY = new TextEncoder().encode('{"cart_id":"crt_1"}');
const NOW = 1700000000;

function requestFor(headers: Record<string, string>, url = URL, method = 'POST', body = BODY) {
  return { method, url, headers, body };
}

async function signedRequest(
  keys: { privateJwk: object; publicJwk: object },
  overrides: Record<string, unknown> = {},
) {
  const headers = await signRequest(
    { method: 'POST', url: URL, body: BODY },
    {
      privateJwk: keys.privateJwk,
      keyid: 'k_test',
      created: NOW,
      nonce: 'n_' + 'a'.repeat(24),
      grant: 'grt.jwt.value',
      idempotencyKey: 'idem-1',
      ...overrides,
    },
  );
  return requestFor(headers);
}

function expectCode(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError, `expected TrailGateError, got ${String(err)}`);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

describe('parseTgSignatureInput', () => {
  const VALID =
    'tg=("@method" "@authority" "@path" "@query" "content-digest" "trailgate-grant" "idempotency-key")' +
    ';keyid="k_1";alg="ed25519";created=1700000000;expires=1700000060;nonce="n_1";tag="trailgate"';

  it('parses a valid signature-input entry', () => {
    const parsed = parseTgSignatureInput(VALID);
    assert.equal(parsed.params.keyid, 'k_1');
    assert.equal(parsed.params.alg, 'ed25519');
    assert.equal(parsed.params.created, NOW);
    assert.equal(parsed.params.expires, NOW + 60);
    assert.equal(parsed.params.nonce, 'n_1');
    assert.equal(parsed.components.length, 7);
  });

  it('rejects a missing tg entry as signature_invalid', () => {
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () =>
      parseTgSignatureInput(
        'sig=("@method");keyid="k";alg="ed25519";created=1;nonce="n";tag="trailgate"',
      ),
    );
  });

  it('rejects missing required params', () => {
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () =>
      parseTgSignatureInput('tg=("@method");keyid="k";alg="ed25519";nonce="n";tag="trailgate"'),
    );
  });

  it('rejects disallowed algorithms', () => {
    const input = VALID.replace('alg="ed25519"', 'alg="rsa-v1_5-sha256"');
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => parseTgSignatureInput(input));
  });

  it('rejects a wrong tag', () => {
    const input = VALID.replace('tag="trailgate"', 'tag="other"');
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => parseTgSignatureInput(input));
  });

  it('rejects component lists missing required identifiers', () => {
    const input =
      'tg=("@method" "@authority");keyid="k";alg="ed25519";created=1;nonce="n";tag="trailgate"';
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => parseTgSignatureInput(input));
  });
});

describe('checkSignatureWindow', () => {
  it('accepts a request within window and tolerance', () => {
    checkSignatureWindow(NOW, NOW + 60, NOW + 30, 60);
    checkSignatureWindow(NOW, NOW + 300, NOW, 60);
  });

  it('rejects expired signatures', () => {
    expectCode(Codes.REQUEST_EXPIRED, () => checkSignatureWindow(NOW - 400, NOW - 350, NOW, 60));
  });

  it('rejects windows beyond the maximum', () => {
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () =>
      checkSignatureWindow(NOW, NOW + 600, NOW, 60),
    );
  });

  it('rejects future created beyond tolerance', () => {
    expectCode(Codes.REQUEST_EXPIRED, () => checkSignatureWindow(NOW + 120, NOW + 180, NOW, 60));
  });

  it('rejects tolerance above the maximum', () => {
    expectCode(Codes.INTERNAL_ERROR, () => checkSignatureWindow(NOW, NOW + 60, NOW, 300));
  });
});

describe('checkNonceShape', () => {
  it('accepts adequately long nonces', () => {
    checkNonceShape('n_' + 'a'.repeat(24));
  });

  it('rejects short nonces as signature_invalid', () => {
    expectCode(Codes.REQUEST_SIGNATURE_INVALID, () => checkNonceShape('short'));
  });
});

describe('signRequest + verification', () => {
  it('round-trips an ed25519 signature', async () => {
    const keys = generateEd25519KeyPair();
    const req = await signedRequest(keys);
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    const base = buildSignatureBase(req, input.components, input.entry);
    const sig = getSignatureBytes(req.headers['signature'] as string);
    assert.equal(
      verifySignatureBytes(input.params.alg, publicKeyFromJwk(keys.publicJwk), sig, base),
      true,
    );
  });

  it('round-trips an ecdsa p256 signature', async () => {
    const keys = generateP256KeyPair();
    const req = await signedRequest(keys);
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    assert.equal(input.params.alg, 'ecdsa-p256-sha256');
    const base = buildSignatureBase(req, input.components, input.entry);
    const sig = getSignatureBytes(req.headers['signature'] as string);
    assert.equal(
      verifySignatureBytes(input.params.alg, publicKeyFromJwk(keys.publicJwk), sig, base),
      true,
    );
  });

  it('fails verification under a different key', async () => {
    const keys = generateEd25519KeyPair();
    const other = generateEd25519KeyPair();
    const req = await signedRequest(keys);
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    const base = buildSignatureBase(req, input.components, input.entry);
    const sig = getSignatureBytes(req.headers['signature'] as string);
    assert.equal(
      verifySignatureBytes(input.params.alg, publicKeyFromJwk(other.publicJwk), sig, base),
      false,
    );
  });

  it('fails verification after target url tampering', async () => {
    const keys = generateEd25519KeyPair();
    const req = await signedRequest(keys);
    const tampered = { ...req, url: 'https://shop.example.com/admin' };
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    const base = buildSignatureBase(tampered, input.components, input.entry);
    const sig = getSignatureBytes(req.headers['signature'] as string);
    assert.equal(
      verifySignatureBytes(input.params.alg, publicKeyFromJwk(keys.publicJwk), sig, base),
      false,
    );
  });

  it('builds a deterministic base covering every required component', async () => {
    const keys = generateEd25519KeyPair();
    const req = await signedRequest(keys);
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    const base = buildSignatureBase(req, input.components, input.entry);
    const lines = base.split('\n');
    assert.deepEqual(lines.slice(0, 4), [
      '"@method": POST',
      '"@authority": shop.example.com',
      '"@path": /orders',
      '"@query": ?expand=items',
    ]);
    assert.ok(lines.some((l) => l.startsWith('"trailgate-grant": grt.jwt.value')));
    assert.ok(lines.some((l) => l.startsWith('"idempotency-key": idem-1')));
    assert.ok(lines.some((l) => l.startsWith('"content-digest": sha-256=:')));
    assert.match(lines[lines.length - 1] as string, /^"@signature-params": \("@method"/);
  });

  it('serializes an absent query as the RFC 9421 bare question mark', async () => {
    const keys = generateEd25519KeyPair();
    const headers = await signRequest(
      { method: 'GET', url: 'https://shop.example.com/cart', body: new Uint8Array() },
      {
        privateJwk: keys.privateJwk,
        keyid: 'k',
        created: NOW,
        nonce: 'n_' + 'b'.repeat(24),
        grant: 'grt.jwt.value',
        idempotencyKey: 'idem-1',
      },
    );
    const req = requestFor(headers, 'https://shop.example.com/cart', 'GET', new Uint8Array());
    const input = parseTgSignatureInput(req.headers['signature-input'] as string);
    const base = buildSignatureBase(req, input.components, input.entry);
    assert.ok(base.split('\n').some((l) => l === '"@query": ?'));
  });
});
