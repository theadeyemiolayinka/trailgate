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

## Configuration reference

| Option | Required | Default | Notes |
| --- | --- | --- | --- |
| `issuer` | yes | | Bare https origin; also `aud` for grants and receipts. |
| `signingKeys` | yes | | One or more private JWKs (`Ed25519` or `P-256`). First key signs; all are published and verify. Rotate with `rotateSigningKey`. |
| `permissions` | yes | | `tg.<domain>.<action>` identifiers the site honors; advertised verbatim. |
| `constraintTypes` | | all registered | Constraint types the site evaluates. |
| `paths` | | `/tg/*` | Endpoint paths for the four protocol endpoints plus `consent`. |
| `capabilities` | | `{}` | Discovery capabilities; `max_grant_seconds` also set from `maxGrantSeconds`. |
| `stores` | | in-memory | See "Stores". |
| `subjectFor` | | identity | Maps host user id to grant `sub`. |
| `policy` | | none | Stage-13 site authorization callback. |
| `resourceOwners` | | none | `ownerOf(selector)` for cross-user isolation. Required for resource-scoped routes. |
| `resourcePolicy` | | accept all | Intake-time selector namespace check. |
| `refineScope` | | pass-through | Narrows requested scope; SDK enforces subset rules. |
| `revocationAuthorizer` | | deny all | Authorizes `handleRevocation` calls (provisional). |
| `clock` | | system | Injectable for tests. |
| `toleranceSeconds` | | 60 | Max 120 (spec cap). |
| `grantRequestTtlSeconds` | | 900 | Max 900 (spec cap). |
| `defaultGrantSeconds` | | 3600 | Grant lifetime when the agent does not request one. |
| `maxGrantSeconds` | | none | Ceiling on grant lifetime; advertised when set. |
| `reservationTtlSeconds` | | 300 | Reservation auto-release TTL. |

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

### Storage requirements

Suggested schema per store. Times are integer unix seconds.

- `grant_requests`: `request_id` PK, `created_at`, `expires_at`, `status`,
  serialized `body` (JSON), `agent_jkt`, `subject`, `decided_at`,
  `grant_id`, effective scope fields. Unique index on `request_id`.
  `transition` is `UPDATE ... WHERE request_id=? AND status=?`.
- `issued_grants`: `jti` PK, `issued_at`, `expires_at`, `agent_jkt`,
  `subject`, `request_id`, `status`, revocation fields.
- `agent_keys`: `jkt` PK, `jwk` (JSON).
- `nonces`: composite PK `(grant_id, nonce)`, `expires_at`; claim is insert
  or fail on conflict, plus expiry sweep.
- `idempotency`: composite PK `(grant_id, key)`, `request_digest`, serialized
  `outcome`.
- `ledger`: consumed entries `(grant_id, amount, currency, at)` and
  reservations `(reservation_id, grant_id, amount, state, expires_at)`;
  `reserve` must run the headroom check and insert in one transaction.
- `rate_hits`: `(grant_id, at)` appended per authenticated request;
  `countInWindow` is a range count.
- `audit`: append-only `(id, event)` rows; never updated or deleted.

## Framework integration notes

The SDK has no framework dependency. A host adapts its request type into
`HostRequest` and sends back `HostResponse`. A working `node:http` adapter
exists in `src/host.test.ts` and demonstrates a complete lifecycle over real
HTTP; it is the only adapter exercised by the test suite.

Adapter rules that must hold on every framework:

- `url` must be the absolute request URI exactly as received, including raw
  query. The signature covers `@authority`, `@path`, and `@query`; a
  normalized or reconstructed URI breaks verification.
- `headers` must contain lowercased names and the raw field values.
- `body` must be the exact received bytes; `Content-Digest` verification
  fails on re-encoded bodies.
- Responses carry `content-type: application/json` and, on protected routes,
  the `trailgate-receipt` header (provisional channel).

TLS termination upstream is fine as long as the `url` seen by the SDK still
matches the URI the agent signed (scheme and authority included).

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

- Idempotency pending-state records for in-flight duplicate suppression
  (a lookup-then-record window remains; production stores must enforce
  uniqueness).
- `trailgate-agent` client-identification header (referenced in spec
  section 18 but not profiled).
- Signed grant-status responses.
- Grant refresh and attenuation (open spec issues).
- Framework adapters (Express/Fastify/Hono). `HostRequest`/`HostResponse` is
  deliberately thin; adapters belong to the host or a future helper package.
