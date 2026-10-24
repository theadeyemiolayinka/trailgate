# Final implementation audit

Snapshot of the repository as it exists, and the sprint sequence this
audit drives. Honest labels; nothing here is aspirational.

## Actual architecture

- `packages/core` - wire formats, schemas, grants, JWS, HTTP message
  signatures, constraints evaluator, discovery validation and signing.
- `packages/server` - `createTrailGateServer`: discovery (signed), grant
  lifecycle (request, consent, PKCE redemption, status, revocation),
  `protect()` enforcement pipeline, per-request approvals, receipts,
  audit, storage ports with in-memory reference stores.
- `packages/agent` - `createAgentClient`: discovery + key-continuity
  pinning, grant request/redemption/status, `checkAccess`, `fetchProtected`
  (message signatures + content digest + idempotency), receipt
  verification, key providers (process, software, file).
- `packages/agent-cli` - `trailgate` bin: keygen, keys, discover, actions,
  request, redeem, status, access, fetch, grants, revoke.
- `packages/mcp-adapter` - nine tool descriptors over an AgentClient.
  No runnable server existed before this sprint; `server.ts` now adds a
  stdio JSON-RPC host and a `trailgate-mcp` bin.
- `packages/conformance` - `runPortContractSuite` for all storage ports.
- `packages/test-fixtures` - shared factories and keys.
- `apps/example-shop` - node:http + node:sqlite storefront with full UI:
  home, catalog, product, cart, checkout, orders, invoices, wallet with
  simulated top-up, addresses, connections (grant list + revoke),
  receipts + verify, activity/audit view, consent, request approval,
  auth. TG-protected JSON API under /api with an action catalog.

## Working entry points

- `pnpm install && pnpm verify` - clean checkout passes (build, typecheck,
  check, 461 tests).
- `cd apps/example-shop && pnpm dev` - shop on http://127.0.0.1:3300;
  TLS on https://localhost:3443 after `pnpm certs`.
- `trailgate` CLI works end to end over real TLS with
  `NODE_EXTRA_CA_CERTS=<repo>/apps/example-shop/dev-certs/ca.crt`.
- Demo account: ada@example.com / demo-pass-1234 (seeded, labeled demo).

## Critical missing pieces (before this sprint)

1. No runnable MCP server: tools were descriptors only. Fixed: stdio
   JSON-RPC server (`server.ts`) + `trailgate-mcp` bin sharing the CLI
   `.trailgate` state dir so keys and grants carry over.
2. No Windows guide. `dev-certs.sh` is bash: works under Git Bash on
   Windows; a pure-Node fallback is now documented.
3. No storefront product search: `/products?q=` added.
4. No single demo runbook or copy-paste agent prompt. Added.

## Commands that work (verified on macOS)

- `pnpm install`, `pnpm build`, `pnpm typecheck`, `pnpm check`,
  `pnpm test`, `pnpm verify`.
- `cd apps/example-shop && pnpm certs && pnpm dev`.
- `node packages/agent-cli/dist/cli.js <command>` after `pnpm build`.
- `node packages/mcp-adapter/dist/mcp.js` (stdio MCP server).

## Commands that fail or are unverified

- Nothing currently fails on a clean macOS/Linux checkout.
- Windows-specific commands in docs/GETTING_STARTED_WINDOWS.md are
  derived from the verified commands; PowerShell equivalents are marked.
- Claude API example host (`examples/claude-host`) is implemented but
  untested end to end: no API key is available in this environment.

## Integration boundaries

- Host web framework <-> Server SDK: `HostRequest`/`HostResponse`.
- Storage <-> Server SDK: ports in `packages/server/src/ports.ts`;
  `runPortContractSuite` proves a store implementation.
- Agent runtime <-> Agent SDK: `AgentClient`, `AgentKeyProvider`,
  `HttpTransport`, `DiscoveryCache`.
- MCP host <-> adapter: stdio JSON-RPC; tool descriptors are transport
  neutral.

## Sequence followed

1. Audit + baseline verification (this file).
2. MCP stdio server + `trailgate-mcp` bin + tests.
3. Product search.
4. Claude API example host (best-effort, flagged untested).
5. Docs: Windows guide, agent integration guide, demo runbook,
   implementation status, agent prompt.
6. Full gates + live TLS verification.
