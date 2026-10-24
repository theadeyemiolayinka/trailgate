# ExampleShop Demonstration Guide

This guide reproduces the full TrailGate flow on a clean checkout. Every
step runs through the real Server SDK, Agent SDK, core package, and the
SQLite database. Nothing is stubbed: denials are produced by the same
enforcement pipeline that serves real requests.

## Setup (deterministic, no secrets)

```sh
corepack pnpm install
corepack pnpm -r build
cd apps/example-shop
corepack pnpm dev        # http://127.0.0.1:3300
```

The database is created, migrated, and seeded on first run. Seeded
accounts and objects:

| Object | Value |
| --- | --- |
| Demo user | `ada@example.com` / `demo-pass-1234` (`usr_demo`) |
| Second user | `bill@example.com` / `demo-pass-1234` (`usr_bill`) |
| Second user's order | `ord_bill_seed01` (used for cross-user denial) |
| Demo wallet | USD 250.00, simulated, integer minor units |
| Catalog | 12 deterministic products |

Reset to a clean state (safe, explicit):

```sh
# stop the server, then:
rm -rf data dev-certs
corepack pnpm dev        # re-migrates and re-seeds
```

Environment variables (all optional; no secrets):

| Var | Default | Purpose |
| --- | --- | --- |
| `SHOP_PORT` | `3300` | HTTP listener |
| `SHOP_TLS_PORT` | `3443` | TLS listener |
| `SHOP_ISSUER` | `https://localhost:3443` | TrailGate issuer identity |
| `SHOP_DB` | `data/example-shop.db` | Database file (`:memory:` for tests) |
| `SHOP_SEED` | `1` | `0` disables seeding |
| `SHOP_MAX_CHARGE_MINOR` | `10000` | Site per-charge policy cap |
| `SHOP_MAX_GRANT_BUDGET_MINOR` | `50000` | Site cumulative-budget policy cap |

## The scripted walkthrough

```sh
corepack pnpm demo
```

Add `--manual` to pause at step 3 and approve in the browser instead of
the script auto-approving through the real login + consent form.

Expected output per step:

1. **Discovery** - `GET /.well-known/trailgate` returns issuer,
   advertised permissions, constraint types, and signing keys.
2. **No grant** - `GET /api/products` unsigned returns
   `400 tg.request.malformed`. No grant token, no request considered.
3. **Consent** - grant request asks for a narrow permission set
   (`order.read` deliberately omitted), resource selectors
   (`cart:cart_usr_demo`, `wallet:wlt_usr_demo`,
   `order:ord_bill_seed01`), and two constraints
   (`max_amount` USD 60.00, `cumulative_budget` USD 120.00). Approval
   happens through the site's own login, CSRF-protected form, and
   `decideConsent`. The issued grant carries the effective terms.
4. **Allowed** - catalog read and cart write succeed (200) and the
   allowed response carries a verified `trailgate-receipt`.
5. **Outside scope** - `GET /api/orders` returns
   `403 tg.request.permission_denied` because `tg.order.read` was never
   granted. The denial itself is receipted and the receipt verifies.
6. **Another user's resource** - `GET /api/orders/ord_bill_seed01`
   returns `403 tg.request.permission_denied`: the selector is in the
   grant but ownership resolution (`order:ord_bill_seed01` -> `usr_bill`,
   not the grant's subject `usr_demo`) fails at enforcement stage 11.
7. **Tampered request** - the demo corrupts the request body after
   signing. `400 tg.request.body_digest_mismatch`.
8. **Over limit** - an 8900-minor-unit charge against `max_amount`
   6000: `403 tg.constraint.violated`, verified denial receipt.
9. **Idempotency + concurrency** - two sequential `POST /api/orders`
   with the same `idempotency-key` return the same order id (stored
   outcome replay); two concurrent `pay` calls on one order yield
   exactly one wallet debit (the second sees an already-paid order).
10. **Revocation** - the user revokes from the grant detail page;
    the very next signed request returns `403 tg.grant.revoked`.
11. **Activity + receipts** - `/account/activity` shows the append-only
    audit trail; `/account/receipts` lists stored receipt JWSs;
    the demo prints a verified receipt's claims
    (`decision=allowed`, grant id, audit id binding).
12. **Tampered receipt** - a one-character edit to the JWS fails
    `jws signature verification failed`.

## Protocol denial vs business failure

The demo prints both classes explicitly:

- `tg.*` codes are **protocol denials** from the Server SDK enforcement
  stages (signature, permission, resource, constraint, revocation).
  They carry a denial receipt binding the decision to the request.
- `shop.*` codes are **business outcomes** from ExampleShop's own logic
  (empty cart, insufficient wallet funds, already-paid order). The
  request was authorized; the shop said no.

## What the security controls establish

- Every protected request proves possession of the grant-bound agent
  key (HTTP signatures + Content-Digest + nonce replay protection).
- Permission, resource-ownership, and constraint checks are
  server-authoritative; changing a request payload cannot widen a grant.
- Spending limits are enforced in a single database transaction against
  the ledger; concurrent attempts cannot overspend.
- Receipts bind a decision to a signed request and audit event; they are
  verifiable artifacts, not proof of settlement or fulfillment.

## What is NOT established

- This is a draft protocol and a reference app, not a finished standard.
  Do not deploy as-is.
- The wallet is simulated; no real money or fraud analysis exists.
- Agent identification is key-based only; nothing here detects or
  prevents all bot abuse, account compromise, or prompt injection.
- Local key storage (site JWK in `app_settings`, agent key in the SDK's
  software provider) is development-grade only.
