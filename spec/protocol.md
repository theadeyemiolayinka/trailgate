# TrailGate protocol specification

Version: 0.1-draft. Status: experimental.

TrailGate is an experimental protocol for user-consented delegation from users to AI agents and automated clients. This document is the normative contract for draft 0.1. It is not a proven security standard, has not been formally verified or certified, and is not ready for production use or real funds.

This specification is language-neutral. JSON Schemas in `spec/schemas/` define data shapes; nothing here requires TypeScript or this repository's SDKs.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

## 1. Actors and trust boundaries

| Actor | Role |
| --- | --- |
| User | The person delegating authority. Authenticates on the site; approves or denies consent. |
| Site | The website implementing TrailGate. Issuer of grants, enforcer of constraints, signer of receipts. |
| Agent | The client requesting and holding a grant. Signs protected requests with its private key. |
| Agent runtime | The software driving the agent (for example an LLM orchestrator). Never sees private keys. |

Trust boundaries (authoritative list):

1. Agent to site: every protocol message crosses an untrusted boundary. Both sides validate everything.
2. Site to user: the site's existing authentication and consent UI. TrailGate does not replace it.
3. Agent process to agent runtime: private keys and the grant are handled by the agent's key and request layer; the runtime sees structured results only.
4. Discovery fetch path: the discovery document is untrusted until validated per section 5.
5. Site persistence: grant store, ledger, and audit log are authoritative state.

## 2. Protocol overview

1. The agent fetches the site's discovery document and validates it.
2. The agent POSTs a grant request describing the authority it wants.
3. The user approves or denies on the site's consent surface.
4. The agent redeems the approved request for a signed grant (a JWT).
5. The agent makes protected requests: HTTP Message Signatures over the request plus the grant.
6. The site verifies, enforces, and returns a signed receipt for every protected request.
7. Either side can inspect status; the site can revoke at any time.

## 3. Conventions

- Timestamps: integer seconds since the Unix epoch (JWT `NumericDate` semantics). Fields are named `*_at` or use standard JWT claim names.
- Identifiers: opaque strings with at least 128 bits of entropy. UUIDv7 or base64url-encoded random values are RECOMMENDED. Identifiers carry no personal information.
- Money: integer minor units plus an ISO 4217 currency code, represented as `{ "amount": <integer>, "currency": "XXX" }`. Floating-point values MUST NOT appear in authoritative contexts.
- Key representation: JWK (RFC 7517). Public keys only appear in protocol messages. A key is identified by its SHA-256 JWK thumbprint (RFC 7638), base64url-encoded, written `jkt`.
- Signature algorithms: Ed25519 signing is REQUIRED to implement; ECDSA P-256 with SHA-256 is OPTIONAL. Two registries apply and their names MUST NOT be interchanged: JWS `alg` values for grants and receipts are JOSE names `EdDSA` and `ES256`; RFC 9421 `alg` signature parameters for request signatures are `ed25519` and `ecdsa-p256-sha256`. Any other algorithm MUST be rejected unless a future spec version registers it.
- Error handling: failures produce structured error responses per `spec/errors.md`. Codes are stable strings of the form `tg.<domain>.<name>`.

## 4. Versioning

- The discovery document declares `version` (the document schema version) and `protocol_versions` (an array of protocol versions the site supports, for example `["0.1"]`).
- Every grant carries `tg.version` naming the protocol version it was issued under.
- The agent MUST use a protocol version present in the site's `protocol_versions`. If no common version exists, the agent MUST abort with `tg.discovery.unsupported_version` locally; it MUST NOT fall back to guessing.
- Pre-1.0 drafts may break compatibility between minor versions. Breaking changes bump the draft version and are recorded in `docs/decisions/`. Semver commitments begin at 1.0, which is not declared yet.
- Documents MAY contain extension fields. Consumers MUST ignore fields they do not understand unless the field is listed in a `critical` array; any member of `critical` that is not understood causes rejection of the whole document. `critical` is itself a reserved top-level field.

## 5. Discovery

### 5.1 Location

The discovery document is served at `GET /.well-known/trailgate` on the site's origin, over HTTPS, with `Content-Type: application/json`. The well-known suffix is not registered with IANA; see section 18.

### 5.2 Document

Schema: `spec/schemas/discovery.schema.json`. Required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | Discovery document schema version, currently `"0.1"`. |
| `protocol_versions` | string[] | Protocol versions the site accepts. |
| `issuer` | string (https URL) | The site's issuer identifier; MUST equal the discovery document's origin. |
| `endpoints` | object | Endpoint URLs; see table below. |
| `signing_keys` | object | A JWKS object (`{ "keys": [JWK...] }`) containing the site's public keys used for grant and receipt signatures. |
| `permissions` | string[] | The permission identifiers the site honors (section 7). |
| `constraint_types` | string[] | The constraint types the site evaluates (section 9). |

`endpoints` required members:

| Member | Purpose |
| --- | --- |
| `grant_request` | POST a grant request (section 10.2). |
| `grant_redemption` | POST redemption for an approved request. |
| `grant_status` | GET grant status by `request_id` or grant `jti`. |
| `grant_revocation` | POST revocation (site-side and user-initiated flows). |

Optional `capabilities` object: `supports_redirect` (boolean), `supports_receipts_unsigned` (boolean, default false), `max_grant_seconds` (integer ceiling on grant lifetime), `rate_limits` (site-wide defaults, informational).

Optional `actions` array: declarative descriptors of the site's protected routes, so an agent can map intent ("check my cart") to a concrete signed request before holding a grant. Action descriptors are advisory metadata: they carry no authority, authorize nothing by themselves, and are never a substitute for the section 11 pipeline. A site that advertises an action MUST enforce the declared permission on the named route, and MUST keep the descriptor consistent with the route's actual protection (a descriptor that names a permission the route does not enforce is a conformance bug, not an escalation path). Agents MUST treat every entry as untrusted site input until the document validates per section 5.4.

| Member | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable action identifier (for example `cart.read`); unique within the document. |
| `method` | yes | Uppercase HTTP method of the protected route. |
| `path` | yes | Absolute path template. `{name}` marks a path parameter the caller substitutes; all other segments are literal. The substituted path MUST resolve inside the site origin. |
| `permission` | yes | The `tg.*` permission the request must hold; MUST appear in the document's `permissions`. |
| `description` | yes | Short statement of what the action does, for humans and models. Required because it is the primary signal an agent uses to match intent to endpoint; sites MUST NOT publish vague placeholders. |
| `mutates` | no | Whether the action changes state. When absent, agents MUST treat the action as mutating (the safe default). |
| `resource` | no | Resource selector template the action touches (for example `cart:{user}`); `{user}` denotes the subject-derived part resolved at enforcement. |
| `spend` | no | When true, the action may charge money, so spend constraints such as `max_amount`, `cumulative_budget`, or `spend_window` can deny it. |

### 5.3 Origin rules

- `issuer` MUST equal the discovery document's origin exactly (scheme, host, port).
- Every URL inside `endpoints` and every `jwks_uri`-style member MUST share the discovery document's origin. A document violating this MUST be rejected with `tg.discovery.invalid`.
- The agent MUST NOT follow redirects when fetching the discovery document; the fetch MUST be a direct HTTPS GET to `/.well-known/trailgate`.

### 5.4 Validation and caching

Agents MUST validate the document against the schema before use, treat it as untrusted input, and honor `critical` per section 4. Documents SHOULD be cached for at most 24 hours unless HTTP caching headers say less; a site SHOULD send explicit cache headers. A document that fails validation MUST NOT be used and yields `tg.discovery.invalid`.

## 6. Grants

### 6.1 Representation

A grant is a compact JWS (JWT, RFC 7515/7519) signed by a site key present in `signing_keys` or reachable from it (key rotation per section 13.4). The protected header MUST contain `alg` (a JOSE name: `EdDSA` or `ES256`), `typ: "trailgate-grant+jwt"`, and `kid` equal to the signing key's `jkt`. Receipts use `typ: "trailgate-receipt+jwt"` with the same JOSE `alg` rules.

### 6.2 Claims

| Claim | Required | Meaning |
| --- | --- | --- |
| `iss` | yes | Site issuer identifier; equals discovery `issuer`. |
| `aud` | yes | Audience: the site origin the grant may be used against. A grant presented to a different audience MUST be rejected. |
| `iat` | yes | Issuance time, unix seconds. |
| `exp` | yes | Expiry, unix seconds. Lifetime (`exp - iat`) MUST NOT exceed the site's `max_grant_seconds` if declared. |
| `jti` | yes | Grant identifier; unique per issuer; referenced by receipts, status, revocation. |
| `sub` | no | Opaque delegated-user context identifier assigned by the site. Pseudonymous; carries no personal information. |
| `cnf` | yes | `{ "jkt": "<thumbprint>" }`: SHA-256 JWK thumbprint of the agent's public key. Requests MUST be signed by the matching private key. |
| `tg` | yes | TrailGate object, see below. |

`tg` object members:

| Member | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Protocol version string, for example `"0.1"`. |
| `permissions` | yes | Array of permission identifiers granted (subset of what was requested; a site may issue narrower than asked). |
| `resources` | yes | Array of resource selector strings (section 8). MAY be empty, meaning no resource-level grants. |
| `constraints` | yes | Array of constraint objects (section 9). MAY be empty. |
| `request_id` | yes | The grant request this grant satisfies. |

No other personal data (names, emails, identifiers beyond `sub`) MAY appear in a grant.

### 6.3 Semantics

- A grant is evidence of delegated authority, not authorization by itself. Every protected request is separately checked (section 11.3).
- A grant is bound to exactly one `aud`, one `cnf.jkt`, and one issuance. It is not transferable.
- A site MUST reject issuance of permissions it does not advertise, constraint types it does not list, and resources outside its namespace, with `tg.grant.scope_rejected`.

## 7. Permissions

- A permission is an identifier of the form `tg.<domain>.<action>` where `<domain>` and `<action>` match `[a-z0-9_]+` segments joined by dots. Examples: `tg.cart.read`, `tg.order.create`, `tg.wallet.charge`.
- Permissions name action-level capabilities. A site defines its vocabulary and advertises it in discovery `permissions`. The core spec does not standardize domain semantics beyond format; shared vocabularies may be standardized later.
- Action-level checks (does the grant contain `tg.order.create`?) are distinct from resource-level authorization (may this agent touch `order:ord_789`?). Both MUST pass; permission without resource scope is not access.
- Unknown handling: a grant request asking for a permission not in discovery `permissions` MUST be rejected with `tg.grant.unknown_permission`. A grant containing an unknown permission MUST NOT be issued; if encountered at enforcement it fails closed. Unknown non-critical fields are ignored per section 4.

## 8. Resource selectors

- `tg.resources` is an array of site-defined resource selector strings. Recommended form: `<type>:<id>` (for example `cart:cart_01H…`, `order:ord_9f2…`). Exact match only in 0.1: a request touches a resource only when its identifier equals a listed selector.
- Wildcards and prefix matching are deliberately excluded from 0.1; sites needing broader scope issue explicit selector lists.
- Cross-user isolation: a resource selector MUST resolve to resources owned by the user context (`sub`) the grant was issued under. A grant valid for user A's resources MUST NOT authorize access to user B's, even if the selector string matches. Enforcement checks ownership against authoritative state.

## 9. Constraints

### 9.1 Model

A constraint is `{ "type": "<name>", "params": { ... } }`. The `type` registry is append-only and normative; `params` is defined per type. Evaluation is conjunctive: every constraint in `tg.constraints` MUST pass. Unknown `type` at evaluation means deny (`tg.constraint.unknown_type`). There is no disjunction or override in 0.1.

### 9.2 Registered types (0.1)

| Type | Params | Semantics |
| --- | --- | --- |
| `max_amount` | `{ "amount": int, "currency": "XXX" }` | Any single request carrying a monetary amount MUST NOT exceed `amount` minor units of `currency`. Requests in a different currency fail unless the site converts at its own authoritative rate and the result complies. |
| `cumulative_budget` | `{ "amount": int, "currency": "XXX" }` | The sum of consumed ledger entries under this grant MUST NOT exceed `amount` minor units. Enforced via the reservation lifecycle in section 12. |
| `rate_limit` | `{ "max_requests": int, "window_seconds": int }` | At most `max_requests` protected requests per rolling `window_seconds` under this grant. |
| `valid_window` | `{ "not_before": int, "not_after": int }` | Requests outside `[not_before, not_after]` unix seconds are denied. Narrower than `exp`; both apply. |
| `spend_window` | `{ "amount": int, "currency": "XXX", "window_seconds": int }` | The sum of consumed ledger entries in the last `window_seconds` (rolling) plus live reservations and this request MUST NOT exceed `amount` minor units. Enforced inside the atomic reservation check per section 12. |

### 9.3 Combination and inheritance

- Constraints listed in `tg.constraints` apply to every request under the grant.
- A grant request MAY propose constraints; the site MAY tighten them (lower amounts, shorter windows) but MUST NOT loosen what the agent proposed, and MUST record the effective constraints in the grant.
- If a constraint type appears twice in one grant, both instances apply (the effective rule is the conjunction).

## 10. Consent and grant lifecycle

### 10.1 Lifecycle

`requested → pending → (approved → issued) | (denied) | (expired)`; then `issued → (active → revoked) | (expired)`.

### 10.2 Grant request

`POST <endpoints.grant_request>`, `Content-Type: application/json`. Body schema: `spec/schemas/grant-request.schema.json`. Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Protocol version requested. |
| `permissions` | yes | Permission identifiers requested. |
| `resources` | yes | Resource selectors requested (may be empty). |
| `constraints` | yes | Constraints the agent proposes (may be empty). |
| `agent_key` | yes | The agent's public JWK (`kty` `OKP`/`crv` `Ed25519`, or `EC`/`P-256`). |
| `code_challenge` | yes | `BASE64URL(SHA256(code_verifier))`. |
| `code_challenge_method` | yes | MUST be `"S256"`. |
| `redirect_uri` | no | Exact HTTPS URI to receive the post-consent redirect. |
| `state` | no | Opaque agent state, echoed back on redirect. |
| `requested_seconds` | no | Desired grant lifetime; site may shorten. |

Response `201`: `{ "request_id": "<id>", "consent_url": "<same-origin URL>", "expires_at": <int> }`. The request expires (`expires_at`, maximum 900 seconds after creation) if consent is not completed.

### 10.3 Consent

- `consent_url` is on the site origin. The user authenticates through the site's existing flow. TrailGate defines no authentication method.
- The consent page MUST render the requested permissions, resources, constraints, and lifetime verbatim from the stored grant request. The site MUST NOT alter the terms at render time, though it MAY tighten constraints (section 9.3) and MUST show the effective values.
- Approval records the decision against `request_id`. Denial records it too; both are terminal states for the request.
- If `redirect_uri` was registered: on decision the site 302-redirects to exactly that URI with `request_id` and `state` as query parameters. Any other redirect behavior is a protocol violation.

### 10.4 Redemption

`POST <endpoints.grant_redemption>`: `{ "request_id": "<id>", "code_verifier": "<verifier>" }`. The site verifies `BASE64URL(SHA256(code_verifier)) == stored code_challenge` and that the request is approved and unexpired and unredeemed. On success it returns `200` with `{ "grant": "<compact JWS>" }`. A request is redeemable exactly once; replays return `tg.grant.redeemed`.

### 10.5 Status

`GET <endpoints.grant_status>?request_id=<id>` (before issuance) or `?grant_id=<jti>` (after). Returns `{ "status": "pending|approved|denied|expired|active|revoked", "issued_at": <int?>, "expires_at": <int?> }`.

Status responses are informational, unsigned JSON in draft 0.1. They carry no authority: enforcement checks revocation and expiry against current state on every request, so a forged or stale status response cannot grant access. Agents MUST treat status as advisory. A site MAY attach a signed status representation as an extension; unsigned informational status is the baseline every implementation must support. An unknown `request_id` or `grant_id` is `tg.grant.unknown`.

## 11. Protected requests

### 11.1 Required fields

Every protected request carries:

| Field | Location | Meaning |
| --- | --- | --- |
| `trailgate-grant` | header | The compact JWS grant. |
| `Signature-Input` | header | RFC 9421 signature parameters; one signature labeled `tg`. |
| `Signature` | header | The signature value for label `tg`. |
| `Content-Digest` | header | RFC 9530, `sha-256` digest of the exact message content. REQUIRED even for empty bodies (digest of zero bytes). |
| `Idempotency-Key` | header | Unique per logical operation (draft-ietf-httpapi-idempotency-key-header-08 semantics). REQUIRED on every request because the signature profile always covers it. |

### 11.2 Signature profile

`Signature-Input` for label `tg` MUST cover, in this order:

```
("@method" "@authority" "@path" "@query" "content-digest" "trailgate-grant" "idempotency-key")
```

For requests where a component has no value (for example a bodyless GET still has `content-digest` of the empty body), the component list is unchanged. Signature parameters MUST include `created`, `expires`, `nonce`, `keyid`, `alg`, and `tag` where `tag` is `"trailgate"`. Constraints:

- `expires - created` MUST NOT exceed 300 seconds. The server clock tolerance is site-defined but MUST NOT exceed 120 seconds.
- `nonce` is an opaque string of at least 128 bits entropy, unique per request.
- `keyid` MUST equal the grant's `cnf.jkt`; the verifier resolves the agent's public key by thumbprint from the consent record or the request's `agent_key` registration.
- `alg` MUST be `ed25519` or `ecdsa-p256-sha256` per section 3.

### 11.3 Verification order

The site MUST perform these checks in order and stop at the first failure:

1. Request shape: required headers present and syntactically valid → else `tg.request.malformed`.
2. `Content-Digest` recomputation against the received bytes → else `tg.request.body_digest_mismatch`.
3. Signature-Input shape: required components and parameters → else `tg.request.signature_invalid`.
4. Time window: `created`/`expires` within tolerance → else `tg.request.expired` (also covers future `created` beyond tolerance).
5. Grant JWT: signature against `signing_keys`, `typ`, `iss`, `aud` equal to this site, `exp` not passed → `tg.grant.malformed`, `tg.request.audience_mismatch`, or `tg.grant.expired`.
6. Revocation and lifecycle state → `tg.grant.revoked`.
7. Key binding: `keyid` equals `cnf.jkt` and the signature verifies under the resolved key → `tg.request.signature_invalid` or `tg.request.key_mismatch`.
8. Replay: `nonce` not seen within the window for this grant → `tg.request.replay_detected`.
9. Idempotency: a prior request with the same `Idempotency-Key` and grant returns the stored outcome instead of re-executing → `tg.request.idempotency_conflict` if the same key was used with a different operation. The stored comparison digest covers the operation (method, target URI, content digest, grant), not the signature base, because a retried signature has a fresh nonce. A prior record with the same operation digest but no outcome yet is `tg.request.idempotency_in_flight`.
10. Permission: the request's action is covered by `tg.permissions` → `tg.request.permission_denied`.
11. Resource: every touched resource selector is listed and owned by the grant's user context → `tg.request.resource_denied`.
12. Constraints: all `tg.constraints` pass against authoritative state → `tg.constraint.violated` (with the failing constraint in `detail`).
13. Site rules: the site's own authentication and business logic → `tg.authorization.denied`.

Any required check the site cannot perform (signature verification infrastructure down, revocation state unavailable, ledger unavailable) results in denial with `tg.internal.unavailable`. Fail closed.

### 11.4 Replay and idempotency semantics

- The site caches `(jti, nonce)` pairs for the maximum signature window plus tolerance. A repeat nonce is replay and denied.
- `Idempotency-Key` dedupes logical operations, not transport retries only: a second request with the same key and an identical operation digest (method, target URI, `Content-Digest` value, grant `jti`) returns the stored response without re-executing; the same key with a different operation digest is `tg.request.idempotency_conflict`.
- Mutating endpoints MUST claim the `(grant jti, Idempotency-Key)` pair atomically at lookup time, before the operation executes. The claim inserts a record in a pending (outcome-absent) state; a concurrent duplicate claim observes the existing record and MUST NOT execute a second time. A pending record with the same operation digest but no stored outcome answers `tg.request.idempotency_in_flight` (409; the caller retries the lookup after the in-flight request completes). A pending record abandoned by a crashed request MAY be reclaimed after a site-defined TTL.
- Every request carries `Idempotency-Key` (it is a fixed covered component). Non-mutating requests may reuse a key freely since no dedupe record is stored for them unless the endpoint creates one; mutating endpoints MUST store and consult dedupe records.

## 12. Spending semantics

- Amounts are integer minor units plus ISO 4217 currency. There are no fractional minor units.
- The ledger is authoritative server state. A spending request proceeds as:
  1. `reserve`: atomically check the constraint set and the grant's remaining `cumulative_budget` and `spend_window` headroom and insert a reservation entry. Atomicity is REQUIRED: the headroom check and the reservation insert are one operation, so two concurrent requests cannot both observe the same headroom. For `spend_window`, headroom is the window limit minus consumed-in-window minus live reservations.
  2. `consume`: on successful operation, the reservation converts to a consumed entry.
  3. `release`: on failure or abandonment, the reservation converts to a released entry and its headroom returns.
- Reservations expire. A reservation not consumed or released within a site-defined TTL (RECOMMENDED: 300 seconds) releases automatically.
- Refunds post as new offsetting consumed entries (negative amounts) attributed to the grant; they restore headroom.
- Reconciliation: per-grant ledger entries are the source of truth for `cumulative_budget` evaluation and for receipt `amounts` reporting. The audit log records every transition.
- A grant with no `cumulative_budget` constraint has no spending cap from TrailGate; the site's own rules still apply.

## 13. Expiry, revocation, and rotation

- `exp` is a hard stop: an expired grant is denied at enforcement with `tg.grant.expired`. Enforcement-time checks are authoritative; agents MUST NOT rely on cached validity.
- Revocation: the site MAY revoke a grant at any time (user action, risk signal, admin). Revocation takes effect at the next enforcement check; the maximum acceptable staleness is zero for enforcement — the check runs against current revocation state, not a snapshot. The agent-facing `grant_status` endpoint MAY cache status for at most 60 seconds.
- If the revocation store or grant store is unavailable, enforcement fails closed (`tg.internal.unavailable`).
- `POST <endpoints.grant_revocation>`: body `{ "grant_id": "<jti>", "reason": "<string?>" }` (`spec/schemas/grant-revocation.schema.json`). Two caller models exist:
  - **Agent self-revocation**: the agent sends the revocation call as a section 11 protected request presenting the grant whose `jti` equals the body's `grant_id`. A bound grant may always revoke itself; no additional permission is required. A grant that fails verification cannot revoke anything.
  - **Site-initiated**: the site's own authenticated surfaces (user settings, admin tooling, risk systems) revoke through host-side calls; authentication is site-defined and outside this specification.
  A site that implements neither MUST deny every call with `tg.authorization.denied`. Unknown `grant_id` is `tg.grant.unknown`; an already-revoked grant returns the same `tg.grant.unknown`.
- Key rotation: site signing keys rotate by publishing new keys in `signing_keys` while keeping the old `kid` valid for verification of outstanding grants until they expire. Agent keys rotate by issuing a new grant bound to the new `jkt`; a grant is never re-bound mid-flight. `grant_status` exposes whether a key rotation invalidated outstanding grants.

## 14. Receipts

### 14.1 Contents

Every protected request returns a receipt. The site MUST deliver the receipt in the `trailgate-receipt` response header as a compact JWS signed by a site key from `signing_keys`, `typ: "trailgate-receipt+jwt"`, containing:

| Claim | Meaning |
| --- | --- |
| `iss`, `aud` | As in the grant. |
| `jti` | Receipt identifier. |
| `iat` | Issuance time. |
| `tg.grant_id` | The grant `jti` this receipt answers. |
| `tg.request_digest` | base64url SHA-256 of the request's signature base (RFC 9421 signature base bytes), binding the receipt to that exact request. |
| `tg.decision` | `"allowed"` or `"denied"`. |
| `tg.code` | Error code if denied; omitted if allowed. |
| `tg.amounts` | Optional object `{ "reserved": money?, "consumed": money?, "released": money? }` summarizing ledger effects this request caused. Informational. |
| `tg.audit_id` | The audit log event identifier for this request. |

### 14.2 What a receipt establishes

A verified receipt establishes that the site, holding its signing key, recorded a decision for a specific request digest at a specific time. It is an audit artifact.

A receipt does NOT establish: that a business transaction settled (payment clearing, fulfillment, delivery), that the site behaved correctly, or that the agent's request was well-formed beyond what the server checked. Settlement claims belong to the site's business records; the receipt only anchors the TrailGate decision.

### 14.3 Verification

The agent verifies the receipt signature against `signing_keys`, checks `iss`/`aud`, and may recompute `tg.request_digest` from its sent request to confirm binding. A receipt that fails verification MUST be treated as untrusted and reported locally; it is not proof of anything.

### 14.4 Receipts for denials

Denials also produce receipts, so the agent has evidence of why it was refused. If `capabilities.supports_receipts_unsigned` is true a site may return unsigned receipt-shaped JSON for denials only; allowed decisions are always signed.

## 15. Audit events

The site records audit events for security-relevant transitions. Required event types and minimum fields:

| Event | When | Minimum fields |
| --- | --- | --- |
| `grant.requested` | Grant request accepted | `request_id`, `jkt`, `permissions`, `constraints` |
| `grant.consent_decided` | User decision | `request_id`, `decision`, `sub` |
| `grant.issued` | Redemption succeeded | `jti`, `request_id`, `jkt`, `sub`, `exp` |
| `grant.revoked` | Revocation | `jti`, `reason`, `actor` |
| `request.authenticated` | Signature verification passed | `jti`, `request_digest`, `nonce` |
| `request.denied` | Any denial | `jti`, `code`, `stage` |
| `reservation.created/consumed/released` | Ledger transitions | `jti`, `amount`, `currency`, `reservation_id` |
| `idempotency.record_failed` | Outcome write failed after a successful claim; the pending record would answer `tg.request.idempotency_in_flight` to retries until reclaimed | `jti`, `detail` |
| `key.rotated` | Site or agent key rotation event | `old_jkt`, `new_jkt` |

Events are append-only, timestamped, and retained per site policy. The audit mechanism itself is implementation-defined; the event vocabulary is the contract.

## 16. Errors

Error responses use `spec/schemas/error.schema.json`: `{ "error": { "code": "tg.<domain>.<name>", "message": "<human readable>", "detail": { ... }? } }`. HTTP status is advisory and set per `spec/errors.md` mappings; the `code` is authoritative. Unknown failures map to `tg.internal.error` and never leak secrets, key material, or internal state. The registry is append-only.

## 17. Security considerations

- Everything in `docs/threat-model.md` applies; this spec exists to make those mitigations enforceable.
- Agents MUST keep private keys out of model context and out of logs. A leaked key plus a live grant equals delegation theft until revocation.
- Sites MUST treat grant contents, nonces, and idempotency keys as untrusted input at parse time even though they are signed.
- A compromised agent key is contained by: grant expiry, per-grant budgets, resource scoping, revocation, and receipts for forensics. None of these prevents misuse before revocation.
- TLS is REQUIRED on every endpoint and the discovery document. No downgrade path exists in the protocol.
- Sites SHOULD bound protected-request size: reject oversized bodies or header sets before signature verification with `tg.request.too_large`. Cheap rejection at the edge, before any cryptographic or storage work, is the protocol-level defense against request-flooding.

## 18. Registration notes

- `/.well-known/trailgate` is unregistered; registration is tracked as an open issue.
- `trailgate-grant`, `trailgate-receipt` JWT `typ` values are unregistered media-type suffixes; collision risk is noted.
- Custom headers `trailgate-grant`, `trailgate-receipt`, `idempotency-key` use the deprecated `X-`-style avoidance convention: lowercase descriptive names per RFC 9110 field naming.

## 19. Open issues

- Discovery document signing (currently relies on TLS + same-origin).
- Wildcard/hierarchical resource selectors.
- Grant attenuation and agent-to-agent redelegation (RFC 8693-informed).
- Response signatures from site to agent (RFC 9421 supports them; not yet profiled).
- Multi-step consent negotiation (GNAP-informed).
- `Idempotency-Key` is an IETF draft; final RFC may adjust semantics.
- Formal registration of the well-known suffix and JWT `typ` values.

## References

Normative: RFC 9421, RFC 9530, RFC 7519, RFC 7515, RFC 7517, RFC 7638, RFC 7800, RFC 8615, RFC 9110, RFC 9651, RFC 2119, RFC 8174, ISO 4217.
Informative: RFC 6749, RFC 6750, RFC 9700, RFC 7636, RFC 9396, RFC 9449, RFC 9635, RFC 9767, draft-ietf-httpapi-idempotency-key-header-08, draft-ietf-webbotauth-httpsig-protocol. Full applicability notes: `docs/research/protocol-references.md`.
