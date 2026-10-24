# @trailgate/mcp-adapter

Optional MCP integration for agent runtimes, built on `@trailgate/agent`.

## What this package is

Two layers:

1. `createTrailGateTools(client)` returns plain tool descriptors (`name`, `description`, `inputSchema`, `handler`) - transport-neutral, MCP-SDK-free.
2. `serveMcpStdio(tools, opts)` / the `trailgate-mcp` bin host those tools as a real MCP server: newline-delimited JSON-RPC 2.0 on stdio implementing `initialize`, `tools/list`, `tools/call`, `ping`. No external MCP SDK dependency; the adapter speaks the protocol subset tool hosts need.

Tools: `trailgate.discover` (validated capability document), `trailgate.actions` (action catalog annotated with stored-grant coverage), `trailgate.request` (grant request, returns `consentUrl`), `trailgate.status` (grant request status), `trailgate.access` (local access check against stored grants), `trailgate.fetch` (signed request to a discovered site), `trailgate.grants` (stored grant metadata), `trailgate.redeem` (redeem an approved request), `trailgate.revoke` (revoke a grant).

### Escalation contract

Existing grants are the only authority for ordinary work. The tool layer enforces this, not just descriptions:

- `trailgate.request` requires `user_authorized: true`, which the model may only set when the user's latest message explicitly asked for new or expanded access. Missing or false rejects the call before any consent URL exists. The `beforeAction` gate runs on top of that check.
- Denials (`tg.request.permission_denied`, `tg.request.resource_denied`, expired/revoked/invalid grants, `agent.no_grant`) return an `error.guidance` field telling the model to report the shortfall and wait, not self-escalate.
- The consent page lets the user uncheck permissions before approving, so approved scope is always a subset of the requested scope. An approve with nothing checked is rejected rather than granting broad access. The user can also change permissions later on the site's own grant-management surface - both removing and re-adding - and enforcement reads that current scope on every request. Only the site can change a grant's scope; the agent can never modify its own.
- Successful `trailgate.request` results carry a `note` instructing the model to relay only the consent URL and no protocol internals.
- Results are layman-readable: every error carries a plain `summary` ("You haven't allowed that yet.") alongside the machine `code`, actions carry a plain `name`, and access checks report `summary` text. The model should relay those, not protocol jargon.
- The site's grant-request endpoint rate-limits per agent key (bounded open requests plus a per-minute cap, `tg.request.rate_limited`), so a misbehaving agent cannot mint unbounded consent URLs.

## Boundary rules (not provisional)

- No tool result ever contains private key material, `code_verifier` values, or grant tokens. Tests assert this directly.
- `trailgate.fetch` targets are pinned to the discovered site origin; the adapter cannot be used as an arbitrary URL fetcher.
- Failures are typed results (`{ error: { code, message } }`, `isError: true`), not thrown exceptions.
- `options.beforeAction` gates `request`, `fetch`, `redeem`, and `revoke` so the runtime can enforce user consent or local policy before the adapter acts.

## Running the server

```sh
pnpm build                      # once, from the repo root
node packages/mcp-adapter/dist/mcp.js
```

Environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRAILGATE_STATE_DIR` | `.trailgate` (cwd) | keys, grants, pending sessions, discovery cache - same layout as the `trailgate` CLI, so both share state |
| `NODE_EXTRA_CA_CERTS` | unset | trust a dev CA such as `apps/example-shop/dev-certs/ca.crt` |

On first run the server generates an ed25519 agent key into the state dir
(dev-grade custody, mode 0600). stdout carries JSON-RPC only; logs go to
stderr.

MCP host configuration (example shape; consult your host's docs):

```json
{
  "mcpServers": {
    "trailgate": {
      "command": "node",
      "args": ["<repo>/packages/mcp-adapter/dist/mcp.js"],
      "env": {
        "TRAILGATE_STATE_DIR": "<repo>/.trailgate",
        "NODE_EXTRA_CA_CERTS": "<repo>/apps/example-shop/dev-certs/ca.crt"
      }
    }
  }
}
```

## Using with a custom MCP runtime

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

