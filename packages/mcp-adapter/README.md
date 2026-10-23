# @trailgate/mcp-adapter

Optional MCP integration for agent runtimes, built on `@trailgate/agent`.

Owner: D2.

Status: scaffolded. Implementation lands in Phase 4.

Rules: MCP is an adapter for compatible runtimes, not part of the protocol. The protocol and the ordinary SDK must work without it, and the adapter must not expose private keys or unrestricted credentials to the model.
