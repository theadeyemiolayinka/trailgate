# Integrating TrailGate into a website

Draft 0.1 foundation. This guide describes the intended setup for the Server
SDK. Items marked **provisional** depend on spec questions that are not yet
decided; items under "Not yet implemented" are absent and must not be assumed.

The SDK never replaces the site's authentication, consent surface, or business
logic. It exposes framework-neutral `HostRequest`/`HostResponse` values; the
host adapts its own framework.

## Setup outline

```ts
import { createTrailGateServer } from '@trailgate/server';

const tg = createTrailGateServer({
  issuer: 'https://shop.example.com',          // the site's origin, bare https
  signingKeys: [{ privateJwk: sitePrivateJwk }], // stays server-side; public half is published
  permissions: ['tg.cart.read', 'tg.order.create', 'tg.wallet.charge'],
  stores: { /* durable implementations; see "Stores" below */ },
  subjectFor: (userId) => userId,               // map host user id to grant sub
  resourceOwners: {
    ownerOf: async (selector) => lookupOwner(selector),
  },
  policy: {
    authorize: async (ctx) => {
      // site rules, after every protocol check (spec section 11.3 stage 13)
      // throw new TrailGateError('tg.authorization.denied', 'reason') to deny
    },
  },
});
```

## Endpoints to wire

| Host route | SDK call | Spec |
| --- | --- | --- |
| `GET /.well-known/trailgate` | `tg.discoveryDocument()` | section 5 |
| `POST /tg/grant-request` | `tg.handleGrantRequest(req)` | section 10.2 |
| consent page (host UI) | `tg.getConsent(requestId)` then `tg.decideConsent(...)` | section 10.3 |
| `POST /tg/grant-redemption` | `tg.handleRedemption(req)` | section 10.4 |
| `GET /tg/grant-status` | `tg.handleStatus(req)` | section 10.5 |
| `POST /tg/grant-revocation` | `tg.handleRevocation(req)` | provisional |
| site admin / user settings | `tg.revokeGrant(jti, { reason, actor })` | section 13 |
| protected routes | `tg.protect(route, handler)` | section 11 |

`HostRequest` is `{ method, url, headers, body? }`. `url` must be the absolute
request URI exactly as received; the request signature covers method,
authority, path, and query. `headers` use lowercased names.

## Consent integration

Consent runs on the site's own authenticated pages:

1. The agent POSTs a grant request; `handleGrantRequest` returns
   `{ request_id, consent_url, expires_at }`. `consent_url` points at
   `issuer + paths.consent` carrying `request_id`.
2. The host authenticates the user by its existing mechanism and renders the
   verbatim terms from `tg.getConsent(requestId)`: requested permissions,
   resources, constraints, and lifetime, plus the effective scope the site
   will actually issue (spec section 10.3).
3. On the user's choice the host calls
   `tg.decideConsent(requestId, 'approve' | 'deny', siteUserId)`. Approving
   requires the host's authenticated user id; it is mapped to the grant's
   pseudonymous `sub` through `subjectFor`.
4. If the request registered a `redirect_uri`, the outcome carries
   `redirectTo`; the host 302s there. Otherwise the agent polls
   `grant_status`.

## Protecting routes

```ts
const chargeWallet = tg.protect(
  {
    permission: 'tg.wallet.charge',
    amount: (req) => parseAmount(req),   // Money in integer minor units
  },
  async (req, ctx) => {
    // ctx: grant payload, grant id, subject, permissions, request digest
    return { status: 200, body: await runCharge(ctx) };
  },
);
```

`protect` returns a `(req: HostRequest) => Promise<HostResponse>` covering the
whole spec section 11.3 checklist, then:

- records an `request.authenticated` audit event and counts the request for
  the `rate_limit` constraint,
- serves the stored outcome on an idempotent replay,
- reserves `amount` against `cumulative_budget` when the route declares one,
  consumes on a handler response below 400, releases on a throw or a 400+,
- stores an idempotency record for mutating routes (`mutating: false` opts out
  for read-only endpoints),
- returns a signed receipt in the `trailgate-receipt` response header
  (**provisional** delivery channel, see "Open questions"),
- returns signed denial receipts when the request was parseable enough to
  bind one (spec section 14.4).

Denials return the spec error envelope
(`{ "error": { "code", "message", "detail?" } }`) with the registry's advisory
HTTP status.

## Stores

All stores default to in-memory implementations suitable for development and
single-process demos only. For deployment, implement the ports in
`src/ports.ts` over the site's database:

| Port | Requirement |
| --- | --- |
| `GrantRequestStore` | `transition` must be a real compare-and-swap; it is what makes redemption single-use. |
| `GrantRegistry` | `revoke` atomic; `isRevoked` reads current state at every enforcement pass. |
| `AgentKeyDirectory` | Maps agent `jkt` to registered public JWKs. |
| `NonceStore` | `claim` must be an atomic insert-if-absent (unique key). |
| `RequestIdempotencyStore` | `record` must not overwrite a record with a different operation digest; claim at lookup time to stop concurrent duplicates. |
| `SpendingLedger` | `reserve` must check headroom and insert in one atomic operation; TTL release for abandoned reservations. |
| `RequestRateLimiter` | Rolling-window per-grant request count. |
| `AuditSink` | Append-only; returns the event id embedded in receipts. |

Fail closed: when a security-critical store cannot be consulted, the pipeline
denies with `tg.internal.unavailable`.

## Provisional surfaces

Pending D0 decisions; do not treat as normative.

- `trailgate-receipt` response header as the receipt delivery channel.
- `POST grant_revocation` body `{ grant_id, reason? }` gated by a configured
  `revocationAuthorizer`. The endpoint denies every call when unconfigured.
- `grant_status` returns plainly informational JSON; signed status is an open
  spec question.
- Error-code choices where draft 0.1 has no named code: unknown
  `request_id`/`grant_id` (`tg.request.malformed`), redemption before consent
  (`tg.authorization.denied`), S256 verifier mismatch
  (`tg.authorization.denied`), expired grant request (`tg.grant.expired`),
  unsupported protocol version in a grant request (`tg.grant.scope_rejected`).

## Not yet implemented

- Site signing key rotation flow (`key.rotated` events and multi-key
  verification for outstanding grants are not wired; configuring multiple
  `signingKeys` publishes them but only the first signs).
- Idempotency pending-state records for in-flight duplicate suppression
  (a lookup-then-record window remains; production stores must enforce
  uniqueness).
- `trailgate-agent` client-identification header (referenced in spec
  section 18 but not profiled).
- Signed grant-status responses.
- Grant refresh and attenuation (open spec issues).
- Framework adapters (Express/Fastify/Hono). `HostRequest`/`HostResponse` is
  deliberately thin; adapters belong to the host or a future helper package.
