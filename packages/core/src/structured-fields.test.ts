import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from './errors.ts';
import {
  parseSignatureField,
  parseSignatureInput,
  type SfSignatureEntry,
  serializeSignatureParams,
} from './structured-fields.ts';

function expectMalformed(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, Codes.REQUEST_MALFORMED);
    return;
  }
  assert.fail('expected tg.request.malformed');
}

describe('parseSignatureInput', () => {
  it('parses a single labeled entry with components and params', () => {
    const input =
      'tg=("@method" "@path");keyid="k_1";alg="ed25519";created=1700000000;nonce="n_1";tag="trailgate"';
    const entries = parseSignatureInput(input);
    const entry = entries.get('tg');
    assert.ok(entry);
    assert.deepEqual(
      entry.components.map((c) => c.value),
      ['@method', '@path'],
    );
    assert.equal(entry.params.keyid, 'k_1');
    assert.equal(entry.params.created, 1700000000);
    assert.equal(entry.params.nonce, 'n_1');
  });

  it('parses multiple signature labels', () => {
    const entries = parseSignatureInput(
      'a=("@method");keyid="k1";created=1, b=("@path");keyid="k2";created=2',
    );
    assert.equal(entries.size, 2);
    assert.equal(entries.get('a')?.params.keyid, 'k1');
    assert.equal(entries.get('b')?.params.keyid, 'k2');
  });

  it('rejects duplicate labels', () => {
    expectMalformed(() => parseSignatureInput('tg=("@method");keyid="a", tg=("@path");keyid="b"'));
  });

  it('rejects malformed input', () => {
    expectMalformed(() => parseSignatureInput('tg=("@method"'));
    expectMalformed(() => parseSignatureInput('tg("@method")'));
    expectMalformed(() => parseSignatureInput(''));
  });

  it('rejects inner-list items without space separation', () => {
    expectMalformed(() => parseSignatureInput('tg=("@method""@path");keyid="k"'));
  });

  it('rejects duplicate parameters', () => {
    expectMalformed(() => parseSignatureInput('tg=("@method");keyid="a";keyid="b"'));
  });

  it('rejects tokens containing invalid characters', () => {
    expectMalformed(() => parseSignatureInput('tg:x=("@method");keyid="k"'));
  });
});

describe('parseSignatureField', () => {
  it('parses labeled byte sequences', () => {
    const b64 = Buffer.from('sigbytes').toString('base64');
    const entries = parseSignatureField(`tg=:${b64}:`);
    assert.deepEqual(Buffer.from(entries.get('tg') as Uint8Array).toString(), 'sigbytes');
  });

  it('rejects non-byte-sequence values', () => {
    expectMalformed(() => parseSignatureField('tg="abc"'));
  });

  it('rejects duplicate signature labels', () => {
    const b64 = Buffer.from('x').toString('base64');
    expectMalformed(() => parseSignatureField(`tg=:${b64}:, tg=:${b64}:`));
  });
});

describe('serializeSignatureParams', () => {
  it('round-trips through the parser', () => {
    const entry: SfSignatureEntry = {
      components: [
        { value: '@method', params: {} },
        { value: 'content-digest', params: {} },
      ],
      params: { keyid: 'k', created: 1700000000, nonce: 'n', alg: 'ed25519', tag: 'trailgate' },
    };
    const serialized = serializeSignatureParams(entry);
    const parsed = parseSignatureInput(`tg=${serialized}`).get('tg');
    assert.ok(parsed);
    assert.deepEqual(
      parsed.components.map((c) => c.value),
      ['@method', 'content-digest'],
    );
    assert.equal(parsed.params.created, 1700000000);
    assert.equal(parsed.params.tag, 'trailgate');
  });
});
