# External developer quickstart

Everything below was executed against a clean clone of this repository.
TrailGate is experimental draft 0.1; nothing here is production-ready.

## Prerequisites

- Node.js 22.18 or later (`node --version`; `node:sqlite` and unflagged TypeScript type stripping are required)
- pnpm 11.3 or later (`corepack enable` gives you the pinned version from `packageManager`)
- Git
- openssl, only if you want TLS mode (`pnpm certs`)

## 1. Install and verify

```sh
git clone <repo-url> trailgate && cd trailgate
pnpm install
pnpm verify    # check -> build -> typecheck -> test
```

`pnpm verify` exits non-zero on any failure. Build runs before typecheck
and test because workspace packages resolve each other through `dist/`;
on a clean tree `typecheck` without a build cannot find `@trailgate/core`.

Expected on a clean checkout: all gates pass, ~450 tests, zero failures.

## 2. Run the reference site

```sh
cd apps/example-shop
pnpm dev                   # http://127.0.0.1:3300
```

The SQLite database is created, migrated, and seeded on first run under
`data/`. Sign in with the seeded demo account `ada@example.com` /
`demo-pass-1234`. The wallet balance is simulated; no real money moves.

Optional full-fidelity TLS:

```sh
pnpm certs                 # writes dev-certs/ca.crt + server cert (needs openssl)
pnpm dev                   # now also serves https://localhost:3443
```

## 3. Exercise the agent flow

Scripted end-to-end walkthrough (12 scenarios including consent,
constraint denials, idempotency, revocation, receipts):

```sh
cd apps/example-shop
pnpm demo                  # add --manual to approve in the browser yourself
```

Or drive the real CLI against TLS mode:

```sh
export NODE_EXTRA_CA_CERTS=apps/example-shop/dev-certs/ca.crt
node packages/agent-cli/src/cli.ts keygen
node packages/agent-cli/src/cli.ts discover https://localhost:3443
node packages/agent-cli/src/cli.ts actions https://localhost:3443
node packages/agent-cli/src/cli.ts request https://localhost:3443 \
  --permission tg.cart.read --wait
# prints a consent_url -> open it, sign in, approve (this step is a human
# decision by design; there is no flag to skip it)
node packages/agent-cli/src/cli.ts fetch https://localhost:3443 /api/cart
```

## 4. Read the contract

| If you want to | Start at |
| --- | --- |
| Understand the wire protocol | `spec/protocol.md`, `spec/errors.md`, `spec/schemas/`, `spec/vectors/` |
| Integrate a website | `packages/server/INTEGRATION.md` (+ `packages/server/examples/photo-host.ts`) |
| Build an agent | `packages/agent/README.md`, `docs/guides/agent-actions.md` |
| Use the CLI | `packages/agent-cli/README.md` |
| Wire an MCP runtime | `packages/mcp-adapter/README.md` (9 tools, boundary rules) |
| See a full demo | `apps/example-shop/docs/DEMO.md` |
| Judge security claims | `docs/security-guarantees.md`, `docs/threat-model.md`, `docs/release-review-0.1.md` |
| Check limits | `docs/limitations.md` |

## 5. Reproduce the security evidence

```sh
pnpm test                                                  # everything
node --test apps/example-shop/src/milestone-a.test.ts      # live e2e: real process, real db, real SDKs
node --test apps/example-shop/src/milestone-b.test.ts      # policy lifecycle, approval_threshold, refunds
node --test apps/example-shop/src/tg/concurrency.test.ts   # cross-process overspend proof
node --test apps/example-shop/src/tg/conformance.test.ts   # port-contract suite on SQLite stores
```

The port-contract suite (`runPortContractSuite` in
`@trailgate/conformance`) is the check you run against your own storage
implementation before trusting it.
