import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createTrailGateTools, type ToolDefinition } from './tools.ts';

/**
 * The adapter's tests focus on the boundary contract, not protocol
 * mechanics (covered by @trailgate/agent tests): every tool result is free
 * of private key material, code verifiers, and grant tokens, and errors map
 * to typed results rather than thrown exceptions.
 */

interface FakeClient {
  calls: string[];
  [method: string]: unknown;
}

function fakeClient(): FakeClient & Parameters<typeof createTrailGateTools>[0] {
  const calls: string[] = [];
  const client = {
    calls,
    discover: async () => {
      calls.push('discover');
      return {
        issuer: 'https://shop.example.com',
        protocolVersion: '0.1',
        document: {
          permissions: ['tg.order.create'],
          constraint_types: ['max_amount'],
          capabilities: { supports_redirect: false },
        },
      };
    },
    requestGrant: async () => {
      calls.push('requestGrant');
      return { requestId: 'req_1', consentUrl: 'https://shop.example.com/consent', expiresAt: 1 };
    },
    awaitApproval: async () => {
      calls.push('awaitApproval');
      return {
        jti: 'grt_1',
        issuer: 'https://shop.example.com',
        token: 'SECRET-GRANT-TOKEN',
        keyId: 'jkt_1',
        issuedAt: 1,
        expiresAt: 2,
        permissions: ['tg.order.create'],
        resources: [],
      };
    },
    grantStatus: async () => ({ status: 'pending', expires_at: 2 }),
    fetchProtected: async () => ({
      status: 200,
      headers: {},
      body: new TextEncoder().encode('{"ok":true}'),
    }),
    listGrants: async () => [
      {
        jti: 'grt_1',
        issuer: 'https://shop.example.com',
        token: 'SECRET-GRANT-TOKEN',
        keyId: 'jkt_1',
        issuedAt: 1,
        expiresAt: 2,
        permissions: ['tg.order.create'],
        resources: [],
      },
    ],
    redeemGrant: async () => {
      throw new Error('no pending request');
    },
  };
  return client as never;
}

function tool(tools: ToolDefinition[], name: string): ToolDefinition {
  const found = tools.find((t) => t.name === name);
  assert.ok(found !== undefined, `missing tool ${name}`);
  return found;
}

function serialized(result: { content: { text: string }[] }): string {
  return result.content.map((c) => c.text).join('\n');
}

describe('createTrailGateTools', () => {
  const client = fakeClient();
  const tools = createTrailGateTools(client);

  it('exposes the documented tool names', () => {
    assert.deepEqual(tools.map((t) => t.name).sort(), [
      'trailgate.discover',
      'trailgate.fetch',
      'trailgate.grants',
      'trailgate.redeem',
      'trailgate.request',
      'trailgate.status',
    ]);
  });

  it('discover returns capabilities only', async () => {
    const result = await tool(tools, 'trailgate.discover').handler({
      url: 'https://shop.example.com',
    });
    assert.equal(result.isError, undefined);
    const parsed = JSON.parse(serialized(result)) as Record<string, unknown>;
    assert.equal(parsed['protocolVersion'], '0.1');
  });

  it('request returns a consent session, wait redeems to metadata', async () => {
    const pending = await tool(tools, 'trailgate.request').handler({
      url: 'https://shop.example.com',
      permissions: ['tg.order.create'],
    });
    const parsed = JSON.parse(serialized(pending)) as Record<string, unknown>;
    assert.equal(parsed['status'], 'pending');
    assert.ok(typeof parsed['consentUrl'] === 'string');

    const issued = await tool(tools, 'trailgate.request').handler({
      url: 'https://shop.example.com',
      permissions: ['tg.order.create'],
      wait: true,
    });
    const issuedParsed = JSON.parse(serialized(issued)) as { grant?: { token?: string } };
    assert.equal(issuedParsed.grant?.token, undefined, 'grant token must not reach the model');
  });

  it('never leaks secrets in any tool result', async () => {
    const forbidden = ['SECRET-GRANT-TOKEN', 'codeVerifier', '"d":'];
    const results = await Promise.all([
      tool(tools, 'trailgate.discover').handler({ url: 'https://x.example.com' }),
      tool(tools, 'trailgate.request').handler({
        url: 'https://x.example.com',
        permissions: ['tg.a.b'],
        wait: true,
      }),
      tool(tools, 'trailgate.status').handler({
        url: 'https://x.example.com',
        grantId: 'grt_1',
      }),
      tool(tools, 'trailgate.fetch').handler({ url: 'https://x.example.com', target: '/api' }),
      tool(tools, 'trailgate.grants').handler({}),
      tool(tools, 'trailgate.redeem').handler({ requestId: 'req_1' }),
    ]);
    for (const result of results) {
      const text = serialized(result);
      for (const marker of forbidden) {
        assert.ok(!text.includes(marker), `tool result leaked ${marker}: ${text.slice(0, 200)}`);
      }
    }
  });

  it('maps failures to typed error results, never throws', async () => {
    const result = await tool(tools, 'trailgate.redeem').handler({ requestId: 'req_1' });
    assert.equal(result.isError, true);
    const parsed = JSON.parse(serialized(result)) as { error: { code: string } };
    assert.ok(parsed.error.code.startsWith('agent.'));
  });

  it('validates required arguments locally', async () => {
    const result = await tool(tools, 'trailgate.discover').handler({});
    assert.equal(result.isError, true);
  });
});
