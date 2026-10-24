# ExampleShop

The TrailGate reference storefront: a working ecommerce site where AI agents can shop with explicit, scoped, user-approved delegation. Built on `@trailgate/server` for all protocol enforcement; the app supplies business logic, persistence, and the consent surface.

Owner: D3 (see `internal/TEAM.md`).

## Stack

Deliberately minimal, per `docs/decisions/0001`:

- `node:http` (+ optional `node:https`) server, hand-rolled router and form handling. No web framework.
- `node:sqlite` (`DatabaseSync`) for all persistence: catalog, users, sessions, cart, orders, the simulated wallet, and every TrailGate store the SDK needs.
- Server-rendered HTML and a bespoke stylesheet. No runtime dependencies beyond `@trailgate/core` and `@trailgate/server`.
- `node:crypto` scrypt for password hashing, synchronizer-token CSRF, `HttpOnly`+`SameSite=Lax` session cookies.

Requires Node.js 22.18+ (unflagged `node:sqlite` and type stripping) and pnpm 11.3+.

## Quick start

```sh
corepack pnpm install
corepack pnpm -r build        # build the workspace SDKs once
cd apps/example-shop
corepack pnpm dev             # serves http://127.0.0.1:3300
```

The database (`data/example-shop.db`) is created, migrated, and seeded on first run. Seeded demo account:

- Email: `ada@example.com` — Password: `demo-pass-1234` — Wallet: USD 250.00 (simulated)

Ports and identity:

| Setting | Env | Default |
| --- | --- | --- |
| HTTP listener (UI + dev protocol traffic) | `SHOP_PORT` | `3300` |
| TLS listener port | `SHOP_TLS_PORT` | `3443` |
| TrailGate issuer identity | `SHOP_ISSUER` | `https://localhost:3443` |
| Database path | `SHOP_DB` | `data/example-shop.db` |
| Disable seeding | `SHOP_SEED=0` | seeded |
| Cert directory | `SHOP_CERTS_DIR` | `dev-certs/` |

The issuer is the protocol identity the SDK signs URIs against (a bare https origin, per spec section 5.3). In plain-HTTP dev mode the transport is cleartext loopback while signed URIs carry the issuer identity — the same pattern as `packages/server/examples/photo-host.ts`.

## Try the agent flow

Terminal 1: `pnpm dev`. Terminal 2:

```sh
corepack pnpm demo
```

The script uses the real Agent SDK (`createAgentClient`) over real HTTP with a loopback transport that maps the https issuer onto the HTTP listener — request signatures verify exactly as they would over TLS. It requests a grant with `max_amount` and `cumulative_budget` constraints, prints a consent URL, and waits. Open the printed URL, sign in as the demo user, review the terms, and approve. The agent then browses the catalog, adds an item, places the order, pays (`tg.wallet.charge`), attempts a denied charge, and reads the wallet plus grant ledger state.

Constraint flags: `pnpm demo -- --budget 8000 --max 3000` (minor units).

## Reset

```sh
# stop the server, then:
rm -rf data dev-certs
pnpm dev   # re-migrates and re-seeds deterministically
```

## Judge walkthrough

`docs/DEMO.md` has the full 12-scenario demonstration guide with expected
outcomes, reproducible setup, and an honest statement of guarantees.

## What the site demonstrates

- **Permission vocabulary**: `tg.catalog.read`, `tg.cart.read`, `tg.cart.write`, `tg.order.create`, `tg.order.read`, `tg.wallet.read`, `tg.wallet.charge`.
- **Resource selectors**: `cart:cart_<user-id>`, `wallet:wlt_<user-id>`, `order:ord_<id>` — exact match, cross-user isolation enforced at stage 11 by a real ownership resolver.
- **Constraint enforcement**: the registered types (`max_amount`, `cumulative_budget`, `rate_limit`, `valid_window`, `spend_window`) evaluated by the SDK against SQLite-backed ledger state; `reserve` runs the headroom check and insert inside one `BEGIN IMMEDIATE` transaction.
- **Action catalog**: discovery advertises an `actions` list (`products.*`, `cart.*`, `orders.*`, `wallet.read`) generated from the same `tg.protect` declarations that enforce the routes, so agents can map intent to endpoints and permissions without out-of-band knowledge (spec section 5.2).
- **The consent surface** (`/tg/consent`): renders requested and effective scope verbatim from the stored grant request (spec section 10.3), behind the site's own session auth and CSRF protection.
- **User inspection and revocation**: `/account/connections` lists issued grants with scope detail and revokes via `tg.revokeGrant` (effective next request); `/account/activity` renders the append-only audit trail and agent-placed orders.
- **Simulated wallet, real accounting**: append-only entries, transactional balance updates, refunds that post offsetting grant-ledger entries (spec section 12). Clearly labeled as simulated; no real funds move.

## TLS mode (full-fidelity demo)

```sh
corepack pnpm certs   # generates dev-certs/ca.crt + server cert (needs openssl)
corepack pnpm dev     # now also serves https://localhost:3443
```

With certs present, the issuer origin is real TLS: browsers can reach consent URLs directly, and the stock `trailgate` CLI works end to end with `NODE_EXTRA_CA_CERTS=<repo>/apps/example-shop/dev-certs/ca.crt`. Import `ca.crt` into your browser/OS trust store to remove the warning.

## Tests

```sh
corepack pnpm test
```

Covers: money handling, auth/sessions, cart, wallet accounting invariants (entries sum to balance), order lifecycle (create/pay/cancel/refund, stock, cross-user isolation), every SQLite port implementation (CAS transitions, atomic nonce claims, ledger reserve/consume/release/refund/TTL, idempotency conflicts, rate windows, audit), and an end-to-end suite driving the real Agent SDK through consent, scoped spending, budget denials, receipts, and revocation, all against the live enforcement pipeline.

`src/milestone-a.test.ts` is the integration milestone: it spawns the real `server.ts` as a child process over real HTTP against a real SQLite file, then drives the stock Agent SDK through discovery (schema + action catalog), no-grant check, consent via the site's own login and CSRF form, redemption with `cnf.jkt` binding, a signed cart read with a verified receipt, and three denials (missing grant, out-of-scope permission, wrong key), finishing with audit and receipt assertions against the same database file.

## Layout

| Path | Contents |
| --- | --- |
| `src/server.ts` | Entry point: HTTP + optional HTTPS listeners, static assets, security headers |
| `src/app.ts` | Route table: storefront UI, auth, consent, connections, protocol endpoints |
| `src/api/routes.ts` | Agent JSON API; every route wrapped in `tg.protect` |
| `src/tg/` | Site vocabulary (`vocabulary.ts`), SQLite port stores (`stores.ts`), SDK wiring (`server.ts`) |
| `src/domain/` | users/auth, catalog, cart, orders, wallet — business logic only |
| `src/db/` | `node:sqlite` open/migrate, deterministic seed, id generation |
| `src/ui/` | Page shell, components, per-page renderers; `public/app.css` design system |
| `src/dev/` | `demo-agent.ts` walkthrough, `loopback.ts` dev transport |
| `scripts/dev-certs.sh` | Local CA + localhost certificate generation |

## Security notes and limitations

- This is a reference app for an experimental protocol, not a production template. Private key material (the site signing JWK) is stored in the app database for demo continuity — a real deployment sources `signingKeys` from a KMS.
- CSRF tokens are per-session; SameSite=Lax is a second layer, not the primary defense.
- `grant_revocation` accepts agent self-revocation (a section 11 signed request carrying the grant being revoked, spec section 13) and the site's own UI calls `revokeGrant` directly. No `revocationAuthorizer` is configured, so unsigned external callers are denied.
- Session cookie `Secure` is set only in TLS mode; HTTP dev mode omits it deliberately.
