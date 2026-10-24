import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import { createAgentClient, ProcessKeyProvider } from '@trailgate/agent';
import { handleMcpMessage, serveMcpStdio } from './server.ts';
import { createTrailGateTools, type ToolDefinition } from './tools.ts';

const INFO = { name: 'trailgate-mcp-test', version: '0.0.0' };

function toolsWith(name: string): ToolDefinition[] {
  return [
    {
      name,
      description: 'test tool',
      inputSchema: { type: 'object' },
      handler: async (args) => ({
        content: [{ type: 'text', text: JSON.stringify({ echo: args }) }],
        structuredContent: { echo: args },
      }),
    },
  ];
}

function parse(line: string | undefined): Record<string, unknown> {
  assert.ok(line !== undefined);
  return JSON.parse(line) as Record<string, unknown>;
}

describe('handleMcpMessage', () => {
  it('responds to initialize with server info and tool capability', async () => {
    const line = await handleMcpMessage(
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05' },
      },
      [],
      INFO,
    );
    const res = parse(line) as {
      result: { protocolVersion: string; serverInfo: { name: string } };
    };
    assert.equal(res.result.protocolVersion, '2024-11-05');
    assert.equal(res.result.serverInfo.name, INFO.name);
  });

  it('lists tool descriptors', async () => {
    const line = await handleMcpMessage(
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      toolsWith('demo.ping'),
      INFO,
    );
    const res = parse(line) as { result: { tools: { name: string }[] } };
    assert.equal(res.result.tools[0]?.name, 'demo.ping');
  });

  it('dispatches tools/call to the handler', async () => {
    const line = await handleMcpMessage(
      {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'demo.ping', arguments: { a: 1 } },
      },
      toolsWith('demo.ping'),
      INFO,
    );
    const res = parse(line) as { result: { structuredContent: { echo: { a: number } } } };
    assert.equal(res.result.structuredContent.echo.a, 1);
  });

  it('returns an error for unknown tools and methods', async () => {
    const badTool = parse(
      await handleMcpMessage(
        { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'nope' } },
        [],
        INFO,
      ),
    ) as { error: { code: number } };
    assert.equal(badTool.error.code, -32602);
    const badMethod = parse(
      await handleMcpMessage({ jsonrpc: '2.0', id: 5, method: 'resources/list' }, [], INFO),
    ) as { error: { code: number } };
    assert.equal(badMethod.error.code, -32601);
  });

  it('ignores notifications', async () => {
    const line = await handleMcpMessage(
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      [],
      INFO,
    );
    assert.equal(line, undefined);
  });
});

describe('serveMcpStdio', () => {
  it('serves newline-delimited JSON-RPC over streams', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const lines: string[] = [];
    output.on('data', (chunk) => {
      for (const line of String(chunk).split('\n')) {
        if (line !== '') {
          lines.push(line);
        }
      }
    });
    const done = serveMcpStdio(toolsWith('demo.ping'), {
      serverInfo: INFO,
      input,
      output,
      log: () => {},
    });
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })}\n`);
    input.write('not json\n');
    input.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'demo.ping', arguments: {} } })}\n`,
    );
    await new Promise((resolve) => setImmediate(resolve));
    input.end();
    await done;
    assert.equal(lines.length, 3);
    // Dispatch is concurrent: responses may arrive in any order.
    const messages = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    const parseError = messages.find((m) => m.error !== undefined) as
      | { error: { code: number } }
      | undefined;
    assert.equal(parseError?.error.code, -32700);
    const ids = messages.filter((m) => m.result !== undefined).map((m) => m.id);
    assert.deepEqual(ids.sort(), [1, 2]);
  });
});

describe('end to end through the adapter', () => {
  it('trailgate.discover surfaces an agent-side error as a tool result', async () => {
    const client = createAgentClient();
    const keys = new ProcessKeyProvider();
    client.useKey(await keys.generate('ed25519'));
    const tools = createTrailGateTools(client);
    const line = await handleMcpMessage(
      {
        jsonrpc: '2.0',
        id: 9,
        method: 'tools/call',
        params: { name: 'trailgate.discover', arguments: { url: 'http://insecure.test' } },
      },
      tools,
      INFO,
    );
    const res = parse(line) as {
      result: { isError: boolean; structuredContent: { error: { code: string } } };
    };
    assert.equal(res.result.isError, true);
    assert.equal(res.result.structuredContent.error.code, 'tg.discovery.invalid');
  });
});
