# Shared contract handoff: draft 0.1

The interoperable contract for this phase is `spec/protocol.md` plus the JSON Schemas in `spec/schemas/`. Status: experimental draft, not production ready. Contract changes follow ADR 0002: ADR, owner signoff, spec and vectors updated together.

## Where everything lives

| Artifact | Location |
| --- | --- |
| Normative protocol | `spec/protocol.md` |
| Error registry | `spec/errors.md` + `spec/schemas/error.schema.json` |
| JSON Schemas (draft 2020-12, language-neutral) | `spec/schemas/*.schema.json`, `$id`s `urn:trailgate:schemas:*` |
| Worked examples | `spec/examples/` |
| Conformance vectors | `spec/vectors/vectors.json` (schema cases + decision cases) |
| Standards research | `docs/research/protocol-references.md` |
| Decision records | `docs/decisions/0003` to `0007` |

## D1: Server SDK (`packages/server/`)

`packages/core` now implements the normative pipeline; the server SDK should compose it rather than reimplement it:

- `verifyProtectedRequest(req, deps)` is the section 11.3 checklist. Implement the port interfaces in `packages/core/src/ports.ts` over your real stores: `NonceStore` (atomic claim), `RevocationChecker`, `Ledger`, `RateLimiter`, `ResourceOwnerResolver`, `IdempotencyStore`, `SitePolicy`. The SDK's job is wiring, storage, and HTTP plumbing, not re-verification.
- Endpoints named in `spec/schemas/discovery.schema.json` `endpoints`: `grant_request`, `grant_redemption`, `grant_status`, `grant_revocation`. Request body: `grant-request.schema.json`. Consent and redemption semantics: `spec/protocol.md` sections 10.2 to 10.5. These are not in core; they are server flows.
- Spending ledger: `spec/protocol.md` section 12. Reservation insert plus headroom check must be one atomic operation in the `Ledger` implementation. Money shape: `constraint.schema.json` `$defs/money`.
- Receipts: `buildReceiptPayload` + `signReceipt` in core; issue receipts for denials too (`spec/protocol.md` section 14).
- Audit events: `spec/protocol.md` section 15, `audit-event.schema.json`, `AuditEvent` type in core.
- Decision vectors to satisfy: `spec/vectors/vectors.json` entries with `kind: "decision"` and every `stage` number in section 11.3.

## D2: Agent SDK (`packages/agent/`), CLI, MCP adapter

- Discovery: fetch `GET /.well-known/trailgate` (HTTPS, no redirects), then validate with `validateDiscoveryDocument` / `parseDiscoveryDocument` from core (same-origin rule per `spec/protocol.md` section 5.3, `critical` per section 4, version negotiation via `negotiateProtocolVersion`).
- Consent initiation: build grant requests per `grant-request.schema.json` (`GrantRequestBody` type in core); S256 challenge generation per section 10.2; handle redirect (`redirect_uri`, `state`) and polling (`grant_status`) modes.
- Request signing: `signRequest(req, options)` in core produces the section 11.2 profile (fixed covered components, `tag: "trailgate"`, `Content-Digest`, `Idempotency-Key`). The SDK adds transport and UX.
- Key management: `generateEd25519KeyPair` / `generateP256KeyPair` in `packages/test-fixtures` for tests; production key generation and storage are the SDK's own concern. `jkt` via `jwkThumbprint` in core. Keep private keys out of model context and out of logs.
- Receipt verification: `verifyReceipt(token, deps)` in core (`spec/protocol.md` section 14.3). Treat failed verification as untrusted, not fatal.
- Error handling: parse the `error.schema.json` envelope; branch on `code`, never on `message`. `Codes` in core mirrors `spec/errors.md`.
- Shared fixtures: `packages/test-fixtures` exports key generation, JWS signing (`signCompactJws`), and object factories (`makeDiscovery`, `makeGrantPayload`, `makeGrantRequest`, `makeConstraint`, `makeMoney`) usable without ExampleShop.

## D3: ExampleShop (`apps/example-shop/`)

You configure, not implement, the protocol surface:

- Permission vocabulary for the shop: the `permissions` array your discovery document advertises (format: `tg.<domain>.<action>`, for example `tg.cart.read`, `tg.order.create`, `tg.wallet.charge`).
- Constraint vocabulary: which of the four registered types your site supports (`max_amount`, `cumulative_budget`, `rate_limit`, `valid_window`), declared in `constraint_types`.
- Resource selector naming: `<type>:<id>` strings such as `cart:cart_01J8ZQW4`. Exact match only in 0.1.
- The wallet is simulated but must implement the real reservation lifecycle in `spec/protocol.md` section 12 (reserve, consume, release, refunds, TTL release, reconciliation) and integer minor units.
- Consent UX: render requested permissions, resources, constraints, and lifetime verbatim from the stored grant request (section 10.3).

## Unresolved issues

Tracked in `spec/protocol.md` section 19: discovery signing, wildcard selectors, grant attenuation, response signatures, GNAP-style negotiation, Idempotency-Key draft status, well-known registration.
