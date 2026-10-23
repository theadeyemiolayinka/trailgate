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

Build these surfaces against the contract, nothing else:

- Endpoints named in `spec/schemas/discovery.schema.json` `endpoints`: `grant_request`, `grant_redemption`, `grant_status`, `grant_revocation`. Request body: `grant-request.schema.json`. Consent and redemption semantics: `spec/protocol.md` sections 10.2 to 10.5.
- Protected-request verification pipeline: `spec/protocol.md` section 11.3 is the ordered checklist. Implement it in order; every stage maps to a registered error code in `spec/errors.md`.
- Constraint evaluation: `spec/protocol.md` section 9 and `constraint.schema.json`. Evaluation is conjunctive and fail-closed; unknown `type` denies.
- Spending ledger: `spec/protocol.md` section 12. Reservation insert plus headroom check must be one atomic operation. Money shape: `constraint.schema.json` `$defs/money`.
- Receipts: `spec/protocol.md` section 14, `receipt.schema.json`. Sign with the site key; issue receipts for denials too.
- Audit events: `spec/protocol.md` section 15, `audit-event.schema.json`.
- Decision vectors to satisfy: `spec/vectors/vectors.json` entries with `kind: "decision"` and every `stage` number in section 11.3.

## D2: Agent SDK (`packages/agent/`), CLI, MCP adapter

- Discovery: fetch `GET /.well-known/trailgate` (HTTPS, no redirects), validate against `discovery.schema.json`, enforce the same-origin rule (`spec/protocol.md` section 5.3), honor `critical` fields (section 4).
- Consent initiation: build grant requests per `grant-request.schema.json`; S256 challenge generation per section 10.2; handle redirect (`redirect_uri`, `state`) and polling (`grant_status`) modes.
- Request signing: RFC 9421 profile in `spec/protocol.md` section 11.2. Required covered components, parameters, window, and nonce rules are normative there. `Idempotency-Key` semantics per the cited draft.
- Key management: generate Ed25519 keys (P-256 optional), compute `jkt` thumbprints (RFC 7638), keep private keys out of model context and out of logs.
- Receipt verification: `spec/protocol.md` section 14.3. Treat failed verification as untrusted, not fatal.
- Error handling: parse the `error.schema.json` envelope; branch on `code`, never on `message`.

## D3: ExampleShop (`apps/example-shop/`)

You configure, not implement, the protocol surface:

- Permission vocabulary for the shop: the `permissions` array your discovery document advertises (format: `tg.<domain>.<action>`, for example `tg.cart.read`, `tg.order.create`, `tg.wallet.charge`).
- Constraint vocabulary: which of the four registered types your site supports (`max_amount`, `cumulative_budget`, `rate_limit`, `valid_window`), declared in `constraint_types`.
- Resource selector naming: `<type>:<id>` strings such as `cart:cart_01J8ZQW4`. Exact match only in 0.1.
- The wallet is simulated but must implement the real reservation lifecycle in `spec/protocol.md` section 12 (reserve, consume, release, refunds, TTL release, reconciliation) and integer minor units.
- Consent UX: render requested permissions, resources, constraints, and lifetime verbatim from the stored grant request (section 10.3).

## Unresolved issues

Tracked in `spec/protocol.md` section 19: discovery signing, wildcard selectors, grant attenuation, response signatures, GNAP-style negotiation, Idempotency-Key draft status, well-known registration.
