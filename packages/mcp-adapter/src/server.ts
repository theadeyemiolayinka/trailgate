import type { ToolDefinition, ToolResult } from './tools.ts';

/**
 * Minimal MCP server over stdio: newline-delimited JSON-RPC 2.0 per the
 * MCP stdio transport. Implemented without `@modelcontextprotocol/sdk` so
 * the adapter stays dependency-free; the method surface covers exactly
 * what tool-using hosts need (`initialize`, `tools/list`, `tools/call`,
 * `ping`). Notifications are ignored; every response is one JSON line on
 * stdout, which is reserved for protocol traffic - all logging goes to
 * stderr.
 */

export const MCP_PROTOCOL_VERSION = '2024-11-05';

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

interface McpServerInfo {
  name: string;
  version: string;
}

function result(id: string | number | null, value: unknown): string {
  return JSON.stringify({ jsonrpc: '2.0', id, result: value });
}

function rpcError(id: string | number | null, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
}

/**
 * Handles one parsed JSON-RPC message. Returns the response line, or
 * undefined for notifications and responses (which get no reply).
 */
export async function handleMcpMessage(
  message: JsonRpcRequest,
  tools: readonly ToolDefinition[],
  serverInfo: McpServerInfo,
): Promise<string | undefined> {
  const id = message.id;
  if (id === undefined || id === null) {
    return undefined; // notifications produce no response
  }
  const method = message.method;
  switch (method) {
    case 'initialize': {
      const requested = message.params?.['protocolVersion'];
      return result(id, {
        protocolVersion: typeof requested === 'string' ? requested : MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo,
      });
    }
    case 'ping':
      return result(id, {});
    case 'tools/list':
      return result(id, {
        tools: tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        })),
      });
    case 'tools/call': {
      const params = message.params ?? {};
      const name = params['name'];
      const tool = tools.find((t) => t.name === name);
      if (tool === undefined) {
        return rpcError(id, -32602, `unknown tool ${String(name)}`);
      }
      const args = params['arguments'];
      try {
        const out: ToolResult = await tool.handler(
          typeof args === 'object' && args !== null ? (args as Record<string, unknown>) : {},
        );
        const value: Record<string, unknown> = { content: out.content };
        if (out.structuredContent !== undefined) {
          value['structuredContent'] = out.structuredContent;
        }
        if (out.isError === true) {
          value['isError'] = true;
        }
        return result(id, value);
      } catch (err) {
        return result(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: {
                  code: 'agent.error',
                  message: err instanceof Error ? err.message : String(err),
                },
              }),
            },
          ],
          isError: true,
        });
      }
    }
    default:
      return rpcError(id, -32601, `method not supported: ${String(method)}`);
  }
}

/**
 * Serves MCP on stdin/stdout until stdin closes. `log` receives
 * human-facing lines destined for stderr; never write them to stdout.
 */
export async function serveMcpStdio(
  tools: readonly ToolDefinition[],
  options: {
    serverInfo: McpServerInfo;
    input?: NodeJS.ReadableStream;
    output?: NodeJS.WritableStream;
    log?: (line: string) => void;
  },
): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const byName = tools;
  input.setEncoding('utf8');
  let buffer = '';
  for await (const chunk of input) {
    buffer += chunk as string;
    let newline = buffer.indexOf('\n');
    while (newline !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf('\n');
      if (line === '') {
        continue;
      }
      let message: JsonRpcRequest;
      try {
        message = JSON.parse(line) as JsonRpcRequest;
      } catch {
        output.write(`${rpcError(null, -32700, 'parse error')}\n`);
        continue;
      }
      try {
        const response = await handleMcpMessage(message, byName, options.serverInfo);
        if (response !== undefined) {
          output.write(`${response}\n`);
        }
      } catch (err) {
        log(`handler failure: ${err instanceof Error ? err.message : String(err)}`);
        if (message.id !== undefined && message.id !== null) {
          output.write(`${rpcError(message.id, -32603, 'internal error')}\n`);
        }
      }
    }
  }
}
