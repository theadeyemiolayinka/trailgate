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
