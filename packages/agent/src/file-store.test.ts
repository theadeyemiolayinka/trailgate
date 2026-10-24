import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { generateEd25519KeyPair, makeGrantPayload, signCompactJws } from '@trailgate/test-fixtures';
import { FileGrantStore } from './file-store.ts';
import { recordFromGrantToken } from './store.ts';

const siteKey = generateEd25519KeyPair();
const agentKey = generateEd25519KeyPair();

async function makeRecord(jti: string) {
  const token = await signCompactJws(makeGrantPayload({ jkt: agentKey.jkt, jti }), {
    privateJwk: siteKey.privateJwk,
    kid: siteKey.jkt,
    typ: 'trailgate-grant+jwt',
  });
  return recordFromGrantToken(token);
}

describe('FileGrantStore', () => {
  const dirs: string[] = [];
  after(async () => {
    await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function tempStore() {
    const dir = await mkdtemp(join(tmpdir(), 'trailgate-agent-'));
    dirs.push(dir);
    return new FileGrantStore(join(dir, 'grants.json'));
  }

  it('persists records across instances', async () => {
    const store = await tempStore();
    const record = await makeRecord('grt_1');
    await store.put(record);
    const reopened = new FileGrantStore(store.path);
    assert.equal((await reopened.get('grt_1'))?.jti, 'grt_1');
    assert.equal((await reopened.list()).length, 1);
    await reopened.remove('grt_1');
    assert.equal(await reopened.get('grt_1'), undefined);
  });

  it('treats a missing or corrupt file as empty', async () => {
    const store = await tempStore();
    assert.equal((await store.list()).length, 0);
    await writeFile(store.path, 'not json {{{', 'utf8');
    assert.equal((await store.list()).length, 0);
  });

  it('drops records whose embedded token does not match metadata', async () => {
    const store = await tempStore();
    const record = await makeRecord('grt_1');
    await store.put(record);
    const raw = JSON.parse(await readFile(store.path, 'utf8')) as Record<string, unknown>[];
    const first = raw[0];
    assert.ok(first !== undefined);
    first.jti = 'grt_forged';
    await writeFile(store.path, JSON.stringify(raw), 'utf8');
    assert.equal(
      (await store.list()).length,
      0,
      'metadata that disagrees with the token must be dropped',
    );
  });

  it('drops malformed entries while keeping valid ones', async () => {
    const store = await tempStore();
    const record = await makeRecord('grt_1');
    await store.put(record);
    const raw = JSON.parse(await readFile(store.path, 'utf8')) as unknown[];
    raw.push({ jti: 42 }, 'garbage', null);
    await writeFile(store.path, JSON.stringify(raw), 'utf8');
    const records = await store.list();
    assert.equal(records.length, 1);
    assert.equal(records[0]?.jti, 'grt_1');
  });
});
