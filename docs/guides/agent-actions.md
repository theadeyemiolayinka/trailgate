# Guide: giving an agent intent-to-endpoint capability

How an agent runtime answers "check my cart" on a site it has never seen,
without hardcoded routes and without silently granting itself access.

## The flow

1. **Resolve and discover.** `client.discover(url)` fetches
   `/.well-known/trailgate` over HTTPS, validates it against the schema and
   the same-origin rules, and negotiates a protocol version. A site without
   TrailGate fails with `tg.discovery.invalid` or `tg.discovery.unsupported`.
   There is no fallback path; do not synthesize endpoints.
2. **Read the action catalog.** `document.actions` (spec section 5.2) lists
   advertised routes: `id`, `method`, `path`, `permission`, `description`,
   `mutates`, `resource`, `spend`. `client.listActions(url)` returns the same
   catalog annotated with local grant coverage.
3. **Check access.** `client.checkAccess(url, { permissions })` reports
   `ready`, `no_grant`, `insufficient_permission`, `expired`, `wrong_key`,
   `revoked`, or `unsupported_version`. Each is a different next step;
   `insufficient_permission` lists the exact `missing` permissions to
   include in a grant request.
4. **Human-in-the-loop binding.** `client.requestGrant` returns a
   `consent_url`. The agent's job ends at presenting that URL: the user opens
   it, authenticates on the site's own surface, and approves or denies.
   An agent MUST NOT approve, pre-fill, or auto-confirm consent. Until the
   user acts, `grant_status` stays pending; after approval,
   `awaitApproval(requestId)` redeems the grant against the PKCE verifier
   the client held internally.
5. **Act.** `client.fetchProtected(url, { method, target })` signs and sends
   the request. Grant tokens, private keys, and PKCE verifiers never appear
   in any returned shape.
6. **Interpret failures.** `ProtectedResponse.error.code` carries the `tg.*`
   wire code (e.g. `tg.request.permission_denied`,
   `tg.constraint.spend_window`, `tg.grant.revoked`). Branch on codes, never
   message text. A verified receipt (`response.receipt.verified === true`)
   is durable evidence of the decision.

## Mapping intent

The catalog is designed for models: descriptions say what each action does
in plain terms. ExampleShop advertises, among others:

| Intent | Action | Request |
| --- | --- | --- |
| "check my cart" | `cart.read` | `GET /api/cart` |
| "add sku X" | `cart.items.set` | `POST /api/cart/items` |
| "check out my cart" | `orders.create` | `POST /api/orders` |
| "pay order X" | `orders.pay` | `POST /api/orders/{id}/pay` (`spend: true`) |
| "what's my balance" | `wallet.read` | `GET /api/wallet` |

Request the narrowest scope the action needs: its declared `permission`
plus a `resource` matching the template (`cart:{user}` maps to the user's
cart selector; the site binds `{user}` to the approving subject at consent
time, so the agent requests the template's namespace, not a guessed id).

## High-impact actions require confirmation

`mutates: true` (the default when absent) and `spend: true` mark actions
that change state or move money. Even with a technically sufficient grant,
the runtime SHOULD confirm with the user before executing them. The MCP
adapter's `beforeAction` hook is the enforcement point for host-level
policy such as "always ask before `trailgate.fetch` on a `spend` action";
the catalog gives the hook enough metadata to decide.

## Caching and staleness

Discovery results cache per origin per spec section 5.4 (`fetchedAt` +
`cacheMaxAgeSeconds`, capped at 24h). The client refreshes automatically
when stale; `discover(url, { refresh: true })` forces it. For
cross-process caching pass `new FileDiscoveryCache(path)` as
`createAgentClient({ discoveryCache })`; the CLI uses
`.trailgate/discovery.json`. If a request fails because the document
changed, refetch discovery rather than retrying the stale shape.

## Surfaces

- Agent SDK: `siteActions`, `client.listActions`, `client.checkAccess`,
  `client.ensureGrant`, `client.fetchProtected`.
- CLI: `trailgate discover <url> [--refresh]`, `trailgate actions <url>`,
  `trailgate access <url>`, `trailgate request <url> --permission ...`,
  `trailgate fetch <url> <target>`.
- MCP: `trailgate.discover`, `trailgate.actions`, `trailgate.access`,
  `trailgate.request` (returns `consent_url` for the human),
  `trailgate.fetch` (gated by `beforeAction`).
