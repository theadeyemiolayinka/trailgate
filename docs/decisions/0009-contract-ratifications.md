# 0009. Contract ratifications: receipts, status, revocation, idempotency, spend_window, error codes

Status: accepted, draft 0.1 errata

## Context

Implementation surfaced six provisional surfaces that the draft 0.1 contract
left undefined (recorded in `packages/agent/DESIGN.md` Q1-Q5 and the Server SDK
integration notes). Each needed a normative decision so implementations stop carrying
`@provisional` markers.

## Decisions

1. **Receipt delivery**: the `trailgate-receipt` response header is normative
   (spec section 14.1). Both SDKs already implemented it identically; changing the
   channel would churn two implementations for zero benefit.
2. **`grant_status` is unsigned informational JSON**. It carries no authority because
   enforcement re-checks revocation and expiry on every request; a forged status cannot
   grant access. Signed status remains a permitted extension. This removes the
   ambiguous "sites choose one" wording in section 10.5.
3. **`grant_revocation` request body and caller model**: body schema is
   `{ "grant_id", "reason"? }` (`spec/schemas/grant-revocation.schema.json`). Caller
   model: a bound grant may always revoke itself by presenting the revocation call as a
   section 11 protected request, or the site revokes through its own authenticated
   surfaces. A site implementing neither denies every call.
4. **Idempotency claim-at-lookup**: mutating endpoints MUST atomically claim
   `(grant jti, Idempotency-Key)` before executing, inserting a pending record. This
   closes the documented in-flight duplicate window that a lookup-then-record design
   leaves open. Same-operation pending records answer the new
   `tg.request.idempotency_in_flight` code.
5. **`spend_window` constraint** registered (spec section 9.2): rolling-window spend
   cap `{amount, currency, window_seconds}`, enforced atomically inside `reserve`.
   Answers the "max spend per day" requirement that `cumulative_budget`
   (grant-lifetime) cannot express. Headroom checks for windowed budgets join the
   atomic reservation operation so concurrent requests cannot overspend a window.
6. **New error codes** (append-only): `tg.grant.unknown` (404, unknown request/grant
   id), `tg.request.idempotency_in_flight` (409), `tg.request.too_large` (413, DoS
   bounds).
7. **`trailgate-agent` header reference removed** from section 18: it was named in the
   registration notes but never profiled anywhere.
8. **Not ratified**: a `signRequestWithSigner` helper in core (Q4). The duplication
   between `packages/agent` and `packages/core` signing is small and pinned by an
   equivalence test; no change.
9. **No `http://` dev carve-out** (Q5): HTTPS stays mandatory. The sanctioned dev
   pattern is an https issuer identity mapped onto a loopback transport, as
   ExampleShop's `loopback.ts` does. Granting a plaintext exception in the spec would
   leak into production configurations.

## Consequences

- `RequestIdempotencyStore` gains a `claim` verb; `SpendingLedger.reserve` gains a
  `spendWindows` input. Port implementers must honor both for conformance.
- `Ledger` in core gains an optional `consumedInWindow` read; grants carrying
  `spend_window` deny with `tg.internal.unavailable` where it is absent.
- The conformance suite (`packages/conformance`) exercises the atomicity contracts
  these decisions depend on.
