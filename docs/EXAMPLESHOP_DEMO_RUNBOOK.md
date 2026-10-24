# ExampleShop demo runbook

The end-to-end sequence, verified against this repository. Everything runs
locally; the only human step is the consent decision, which is the point
of the demo.

## One-time setup

```sh
pnpm install
pnpm build                     # needed once: CLI and MCP server run dist/
pnpm verify                    # optional but cheap confidence: all gates

cd apps/example-shop
pnpm certs                     # dev CA + server cert (Git Bash on Windows)
pnpm dev                       # keep this running
```

Trust for Node tools in any new shell:

```sh
export NODE_EXTRA_CA_CERTS=$PWD/dev-certs/ca.crt
```

## The demo (CLI path, fully verified)

Terminal A: `cd apps/example-shop && pnpm dev` (leave running).
Terminal B, from the repo root:

```sh
export NODE_EXTRA_CA_CERTS=$PWD/apps/example-shop/dev-certs/ca.crt
TG="node packages/agent-cli/dist/cli.js"

$TG keygen                                            # one-time: agent key
$TG discover https://localhost:3443                   # "is this TrailGate?"
$TG actions  https://localhost:3443                   # intent catalog
$TG access   https://localhost:3443 --permission tg.cart.read
# -> no_grant. Initiate consent:
$TG request https://localhost:3443 \
    --permission tg.catalog.read --permission tg.cart.read \
    --permission tg.cart.write --permission tg.order.create \
    --permission tg.order.read --permission tg.wallet.charge \
    --resource 'cart:{user}' --resource 'wallet:{user}' \
    --constraint '{"type":"cumulative_budget","params":{"amount":20000,"currency":"USD"}}' \
    --constraint '{"type":"approval_threshold","params":{"amount":5000,"currency":"USD"}}'
# prints consentUrl + requestId
```

`cart:{user}` and `wallet:{user}` are subject-derived templates from the
action catalog: the agent cannot know the concrete selector before the
site knows who is consenting. At approval, ExampleShop binds them to that
user's selectors (`cart:cart_usr_demo`, `wallet:wlt_usr_demo`) and the
issued grant carries the concrete selectors. `orders.list` and
`orders.create` are permission-only; per-order reads use `order:<id>`
selectors learned from the list response.

Browser: open the consent URL, sign in as `ada@example.com` /
`demo-pass-1234` if asked, review permissions and the budget and approval
threshold, approve.

```sh
$TG redeem https://localhost:3443 --request-id <requestId>
$TG fetch https://localhost:3443 /api/cart                      # read cart
$TG fetch https://localhost:3443 /api/cart/items \
    --method POST --body '{"sku":"drk-mug-01","qty":1}' \
    --idempotency-key demo-add-1
$TG fetch https://localhost:3443 /api/orders \
    --method POST --body '{}' --idempotency-key demo-order-1   # checkout
```

Pay the order (order id from the response). Two branches:

- Under the threshold (mug, USD 24): charges immediately.
- Over the threshold (e.g. task lamp USD 98): `tg.constraint.approval_required`
  with `approval_url`; open it, approve as the same user, re-run the fetch
  with the same idempotency key and it completes.

```sh
$TG fetch https://localhost:3443 /api/orders/<id>/pay \
    --method POST --body '{}' --idempotency-key demo-pay-1
$TG fetch https://localhost:3443 /api/orders/<id>              # verify paid
```

Denials to show:

```sh
$TG fetch https://localhost:3443 /api/orders/ord_bill_seed01   # another user's
# -> tg.request.resource_denied
$TG fetch https://localhost:3443 /api/wallet                  # if not granted
# -> tg.request.permission_denied
```

Revocation:

```sh
$TG grants                                                     # find the jti
$TG revoke https://localhost:3443 --grant-id <jti>
$TG fetch https://localhost:3443 /api/cart                     # -> denied
```

Or revoke in the UI: Account -> Agent connections -> Revoke.

## The demo (MCP path, verified over live TLS)

Point a compatible host at:

```json
{
  "command": "node",
  "args": ["<repo>/packages/mcp-adapter/dist/mcp.js"],
  "env": {
    "TRAILGATE_STATE_DIR": "<repo>/.trailgate",
    "NODE_EXTRA_CA_CERTS": "<repo>/apps/example-shop/dev-certs/ca.crt"
  }
}
```

Then give the agent the prompt from `docs/AGENT_INTEGRATION_GUIDE.md` and
ask it to check the cart; it will return a `consent_url` on first use.
Sharing `.trailgate` with the CLI means grants persist across both.

## What the browser shows during the demo

- `https://localhost:3443/` storefront; `/products`, `/cart`, `/checkout`.
- `/account/connections` lists grants; revoke there.
- `/account/activity` shows the audit trail (requests, consents, approvals).
- `/account/receipts` lists signed receipts; `/account/receipts/verify`
  verifies one.
- `/account/wallet` shows balance, simulated test-credit top-ups, ledger.

## Reset

```sh
rm -f apps/example-shop/data/example-shop.db*   # reseeds on next start
rm -rf .trailgate                               # wipe agent keys/grants
```

Manual steps remaining: the browser consent decision and any
`approval_url` decision are inherently human; everything else is commands.
