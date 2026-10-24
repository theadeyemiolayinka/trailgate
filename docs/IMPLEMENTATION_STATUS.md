# Implementation status

Feature-level state of the repository. "Tested" means automated tests or a
verified live run against this code, not just compiled code.

## Protocol and core

| Feature | Status |
| --- | --- |
| Discovery document + schema + same-origin rules | Implemented and tested |
| `trailgate-discovery-signature` header + key-continuity pinning (5.5) | Implemented and tested |
| Version negotiation + `critical` handling | Implemented and tested |
| Grant lifecycle: request, consent, PKCE redemption, status, revocation | Implemented and tested |
| Message signatures, content digest, replay + idempotency | Implemented and tested |
| Constraints: `max_amount`, `cumulative_budget`, `rate_limit`, `valid_window`, `spend_window`, `approval_threshold` | Implemented and tested |
| Atomic spend reservations + refund offsets | Implemented and tested (incl. multi-process) |
| Signed allowed/denied receipts + verification | Implemented and tested |
| Append-only audit events | Implemented and tested |
| Grant refresh / post-issuance attenuation | Not implemented (open spec items) |

## Server SDK and storage

| Feature | Status |
| --- | --- |
| `protect()` pipeline, error envelopes, receipts | Implemented and tested |
| Request approval store + lifecycle | Implemented and tested |
| In-memory reference stores | Implemented and tested |
| SQLite port implementations (ExampleShop) | Implemented and tested |
| `runPortContractSuite` across all ports | Implemented and tested |
| Postgres/MySQL stores | Not implemented (deployer implements ports + runs the suite) |
| Framework adapters beyond node:http | Not implemented |

## Agent side

| Feature | Status |
| --- | --- |
| `createAgentClient` full flow | Implemented and tested |
| `trailgate` CLI (11 commands) | Implemented and tested, live over TLS |
| `trailgate-mcp` stdio MCP server | Implemented and tested (live initialize/tools/discover over TLS) |
| `claude-host` Anthropic example host | Implemented; live API call unverified (no key in this environment) |
| OS-keystore/hardware key custody | Not implemented (file + memory providers only) |
| Hosted-agent (Devin-class) integration | Not currently supported; needs a runtime that can spawn or reach the MCP server |

## ExampleShop

| Feature | Status |
| --- | --- |
| Storefront: home, catalog + search, product, cart, checkout | Implemented and tested |
| Orders, invoice, pay, cancel, refund | Implemented and tested |
| Wallet with simulated top-up + ledger | Implemented and tested |
| Account, addresses | Implemented and tested |
| Connections (grant list + revoke), receipts + verify, activity | Implemented and tested |
| Consent + per-request approval UI | Implemented and tested |
| TG-protected `/api` action catalog (11 actions) | Implemented and tested |
| Product imagery | SVG marks, local only; no photography (licensing/offline constraint) |
| HTTPS dev setup | Implemented and tested (`pnpm certs` + localhost:3443) |
