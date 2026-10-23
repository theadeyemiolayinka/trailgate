# @trailgate/mcp-adapter

Optional MCP integration for agent runtimes, built on `@trailgate/agent`.

Owner: D2 (see `internal/TEAM.md`).

Status: Phase 4 boundary draft. The tool surface is defined and tested here; wiring to `@modelcontextprotocol/sdk` lands in Phase 4 per `internal/PHASES.md`.

## What this package is

`createTrailGateTools(client)` returns plain tool descriptors (`name`, `description`, `inputSchema`, `handler`) that a thin adapter maps onto an MCP server's `tool()` registration. Keeping the boundary MCP-SDK-free means the protocol and the ordinary SDK carry no dependency on a particular agent runtime.

Tools: `trailgate.discover`, `trailgate.request`, `trailgate.status`, `trailgate.fetch`, `trailgate.grants`, `trailgate.redeem`.

## Boundary rules (not provisional)

- No tool result ever contains private key material, `code_verifier` values, or grant tokens. Tests assert this directly.
- `trailgate.fetch` targets are pinned to the discovered site origin; the adapter cannot be used as an arbitrary URL fetcher.
- Failures are typed results (`{ error: { code, message } }`, `isError: true`), not thrown exceptions.
- `options.beforeAction` gates `request`, `fetch`, `redeem`, and `revoke` so the runtime can enforce user consent or local policy before the adapter acts.

## Using with an MCP runtime

```ts
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';
import { createTrailGateTools } from '@trailgate/mcp-adapter';

const client = createAgentClient();
client.useKey(SoftwareKeyProvider.generate());

const tools = createTrailGateTools(client, {
  beforeAction: async (toolName) => {
    // Require user confirmation before consent or signed actions.
    if (!(await userConfirms(toolName))) throw new Error('denied by user policy');
  },
});

// Map onto your MCP SDK of choice, for example:
// for (const t of tools) {
//   server.tool(t.name, t.description, t.inputSchema, async (args) => {
//     const r = await t.handler(args);
//     return { content: r.content, structuredContent: r.structuredContent, isError: r.isError };
//   });
// }
```

## Limits of this integration

- MCP is an adapter, not the protocol. An MCP host must be TrailGate-aware: consent happens on the site's own surface, which the runtime must open for the user (`consent_url` is returned by `trailgate.request`).
- Not every model supports this automatically. The model only sees tool names, schemas, and results; delegation exists because the runtime registers these tools.
- `grant_status` and `trailgate.grants` are informational; only the site's enforcement decides access.
- Key custody follows `packages/agent/KEYS.md`: `SoftwareKeyProvider` is process memory; production runtimes should inject an OS-keystore-backed `AgentKeyProvider`.

