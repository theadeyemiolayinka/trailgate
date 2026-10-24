import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import type { AgentHttpRequest, AgentHttpResponse } from '@trailgate/agent';
import { createAgentClient, FileGrantStore } from '@trailgate/agent';
import type { Jwk } from '@trailgate/core';
import { jwkThumbprint } from '@trailgate/core';
import {
  generateEd25519KeyPair,
  makeDiscovery,
  makeGrantPayload,
  signCompactJws,
} from '@trailgate/test-fixtures';
import { runCli } from './commands.ts';
import { loadPending, loadSigners } from './state.ts';

const ORIGIN = 'https://shop.example.com';
const siteKey = generateEd25519KeyPair();

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): AgentHttpResponse {
  return {
    status,
    headers: { 'content-type': 'application/json', ...headers },
    body: new TextEncoder().encode(JSON.stringify(body)),
  };
}

/** Mini fake site: discovery, grant request, status (approved), redemption, one protected route. */
function fakeSite(agentJkt: { value?: string }) {
  const requests: AgentHttpRequest[] = [];
  const transport = {
    send: async (req: AgentHttpRequest): Promise<AgentHttpResponse> => {
      requests.push(req);
      const url = new URL(req.url);
      if (url.pathname === '/.well-known/trailgate') {
        const doc = makeDiscovery() as {
          signing_keys: { keys: Jwk[] };
          actions: unknown[];
        };
        doc.signing_keys = { keys: [siteKey.publicJwk] };
        doc.actions = [
          {
            id: 'orders.create',
            method: 'POST',
            path: '/api/orders',
            permission: 'tg.order.create',
            description: 'place an order',
            spend: true,
          },
        ];
        return jsonResponse(200, doc);
      }
      if (url.pathname === '/tg/grant-request') {
        const body = JSON.parse(new TextDecoder().decode(req.body)) as { agent_key: Jwk };
        agentJkt.value = jwkThumbprint(body.agent_key);
        return jsonResponse(201, {
          request_id: 'req_1',
          consent_url: `${ORIGIN}/tg/consent?request_id=req_1`,
          expires_at: Math.floor(Date.now() / 1000) + 600,
        });
      }
      if (url.pathname === '/tg/status') {
        return jsonResponse(200, { status: 'approved' });
      }
      if (url.pathname === '/tg/redeem') {
        const grant = await signCompactJws(
          makeGrantPayload({ jkt: agentJkt.value as string, requestId: 'req_1' }),
          { privateJwk: siteKey.privateJwk, kid: siteKey.jkt, typ: 'trailgate-grant+jwt' },
        );
        return jsonResponse(200, { grant });
      }
      if (url.pathname === '/api/orders') {
        return jsonResponse(200, { placed: true });
      }
      return jsonResponse(404, { error: { code: 'tg.internal.error', message: 'no route' } });
    },
  };
  return { transport, requests };
}

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

describe('cli commands', () => {
  const dirs: string[] = [];
  after(async () => {
    await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function setup(withKey = true) {
    const stateDir = await mkdtemp(join(tmpdir(), 'trailgate-cli-'));
    dirs.push(stateDir);
    const agentJkt: { value?: string } = {};
    const { transport, requests } = fakeSite(agentJkt);
    const out: string[] = [];
    const err: string[] = [];
    const run = async (argv: string[]): Promise<CliResult> => {
      out.length = 0;
      err.length = 0;
      const code = await runCli([...argv, '--state-dir', stateDir], {
        stdout: (line) => out.push(line),
        stderr: (line) => err.push(line),
        clientFactory: async ({ stateDir: dir }) => {
          const client = createAgentClient({
            transport,
            grantStore: new FileGrantStore(join(dir, 'grants.json')),
          });
          for (const signer of await loadSigners(dir)) {
            client.useKey(signer);
          }
          for (const record of await loadPending(dir)) {
            client.restorePending(record);
          }
          return client;
        },
      });
      return { code, stdout: out.join('\n'), stderr: err.join('\n') };
    };
    if (withKey) {
      const result = await run(['keygen']);
      assert.equal(result.code, 0, result.stderr);
    }
    return { run, stateDir, requests, agentJkt };
  }

  it('keygen stores a key and prints only public material', async () => {
    const stateDir = await mkdtemp(join(tmpdir(), 'trailgate-cli-'));
    dirs.push(stateDir);
    const out: string[] = [];
    const code = await runCli(['keygen', '--state-dir', stateDir], {
      stdout: (line) => out.push(line),
    });
    assert.equal(code, 0);
    const printed = JSON.parse(out.join('\n')) as { jkt: string; publicJwk: Jwk };
    assert.ok(printed.jkt.length > 0);
    assert.equal(printed.publicJwk.d, undefined);
    const keys = JSON.parse(await readFile(join(stateDir, 'keys.json'), 'utf8')) as Record<
      string,
      Jwk
    >;
    assert.ok(keys[printed.jkt]?.d !== undefined, 'stored file holds the private JWK');
  });

  it('discover prints validated capabilities', async () => {
    const { run } = await setup();
    const result = await run(['discover', ORIGIN]);
    assert.equal(result.code, 0, result.stderr);
    const summary = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(summary.issuer, ORIGIN);
    assert.equal(summary.protocolVersion, '0.1');
    assert.deepEqual(summary.permissions, ['tg.cart.read', 'tg.order.create', 'tg.wallet.charge']);
  });

  it('actions lists the advertised catalog with coverage', async () => {
    const { run } = await setup();
    const empty = await run(['actions', ORIGIN]);
    assert.equal(empty.code, 0, empty.stderr);
    const uncovered = JSON.parse(empty.stdout) as { id: string; covered: boolean }[];
    assert.equal(uncovered[0]?.id, 'orders.create');
    assert.equal(uncovered[0]?.covered, false);

    await run(['request', ORIGIN, '--permission', 'tg.order.create', '--wait']);
    const covered = await run(['actions', ORIGIN]);
    const list = JSON.parse(covered.stdout) as { id: string; covered: boolean; grant?: string }[];
    assert.equal(list[0]?.covered, true);
    assert.ok(list[0]?.grant !== undefined);
  });

  it('request submits, persists pending, wait redeems and stores the grant', async () => {
    const { run, stateDir, requests } = await setup();
    const result = await run(['request', ORIGIN, '--permission', 'tg.order.create', '--wait']);
    assert.equal(result.code, 0, result.stderr);
    const posted = requests.find((r) => r.url.endsWith('/tg/grant-request'));
    assert.ok(posted !== undefined);
    const body = JSON.parse(new TextDecoder().decode(posted.body)) as Record<string, unknown>;
    assert.equal(body.code_challenge_method, 'S256');
    assert.equal((body.agent_key as Jwk).d, undefined);

    const grants = await run(['grants']);
    assert.equal(grants.code, 0);
    const list = JSON.parse(grants.stdout) as { jti: string; token?: string }[];
    assert.equal(list.length, 1);
    assert.equal(list[0]?.token, undefined, 'grant view must not print the token');
    assert.equal((await loadPending(stateDir)).length, 0, 'redeemed session is dropped');
  });

  it('access reports distinguishable availability', async () => {
    const { run } = await setup();
    const before = await run(['access', ORIGIN, '--permission', 'tg.order.create']);
    assert.equal(before.code, 1);
    assert.equal((JSON.parse(before.stdout) as { status: string }).status, 'no_grant');

    await run(['request', ORIGIN, '--permission', 'tg.order.create', '--wait']);
    const after = await run(['access', ORIGIN, '--permission', 'tg.order.create']);
    assert.equal(after.code, 0);
    assert.equal((JSON.parse(after.stdout) as { status: string }).status, 'ready');
  });

  it('status queries by request id', async () => {
    const { run } = await setup();
    const result = await run(['status', ORIGIN, '--request-id', 'req_1']);
    assert.equal(result.code, 0);
    assert.equal((JSON.parse(result.stdout) as { status: string }).status, 'approved');
  });

  it('fetch prints the structured result', async () => {
    const { run } = await setup();
    await run(['request', ORIGIN, '--permission', 'tg.order.create', '--wait']);
    const result = await run(['fetch', ORIGIN, '/api/orders', '--method', 'POST']);
    assert.equal(result.code, 0, result.stderr);
    const out = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(out.status, 200);
    assert.deepEqual(out.body, { placed: true });
  });

  it('reports protocol errors with their code', async () => {
    const { run } = await setup();
    const result = await run(['fetch', ORIGIN, '/missing']);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /tg\.|no_grant|error/);
  });

  it('returns 2 for unknown commands', async () => {
    const { run } = await setup(false);
    const result = await run(['frobnicate']);
    assert.equal(result.code, 2);
  });

  it('prints usage on no arguments', async () => {
    const { run } = await setup(false);
    const result = await run([]);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /commands:/);
  });
});
