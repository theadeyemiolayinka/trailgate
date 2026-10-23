import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { fetchTransport } from './transport.ts';

const originalFetch = globalThis.fetch;

function stubFetch(capture: (init: RequestInit) => void): void {
  globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
    capture(init ?? {});
    return new Response(new Uint8Array(), { status: 200 });
  }) as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('fetchTransport', () => {
  it('omits body on GET when the request body is empty', async () => {
    let init: RequestInit | undefined;
    stubFetch((i) => {
      init = i;
    });
    // undici rejects GET/HEAD requests whose RequestInit carries a body,
    // even a zero-length one; the SDK always produces a body buffer, so the
    // transport must suppress it for bodiless methods.
    await fetchTransport().send({
      method: 'GET',
      url: 'https://site.example.com/api/products',
      body: new Uint8Array(0),
    });
    assert.equal(init?.body, undefined);
  });

  it('sends a non-empty body through', async () => {
    let init: RequestInit | undefined;
    stubFetch((i) => {
      init = i;
    });
    const body = new TextEncoder().encode('{"sku":"book"}');
    await fetchTransport().send({
      method: 'POST',
      url: 'https://site.example.com/api/cart/items',
      body,
    });
    assert.deepEqual(init?.body, body);
  });

  it('never follows redirects', async () => {
    let init: RequestInit | undefined;
    stubFetch((i) => {
      init = i;
    });
    await fetchTransport().send({ method: 'GET', url: 'https://site.example.com/' });
    assert.equal(init?.redirect, 'manual');
  });
});
