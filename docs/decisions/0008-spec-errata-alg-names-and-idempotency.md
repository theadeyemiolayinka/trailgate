# 0008: Draft 0.1 errata: algorithm identifiers and Idempotency-Key

Date: 2026-05-14. Status: accepted.

## Context

Implementing `packages/core` against `spec/protocol.md` draft 0.1 surfaced three defects in the spec text, all corrected in the same change:

1. **Wrong registry for grant `alg`.** Section 3 and section 6.1 named `ed25519` and `ecdsa-p256-sha256` as the JWS `alg` values for grants and receipts. Those are RFC 9421 HTTP signature algorithm registry names; JOSE uses `EdDSA` and `ES256`. An implementation following the spec literally would emit non-conformant JWTs and an implementation following JOSE would fail the spec's algorithm check.

2. **Contradictory Idempotency-Key requirement.** Section 11.1 said `Idempotency-Key` is required only for non-idempotent methods, but section 11.2 fixes it as a covered component for every request. A covered component that is absent makes the request unverifiable, so every request must carry the header.

3. **Ambiguous idempotency comparison.** Sections 11.3 and 11.4 compared an `Idempotency-Key` record against the request, but the only defined digest (`tg.request_digest`) covers the full signature base including `nonce`. A retry has a fresh nonce, so signature-base digests never match, making dedupe useless and misclassifying retries as conflicts.

## Decision

- Section 3 now names both registries explicitly: JOSE `alg` values `EdDSA`/`ES256` for grants and receipts; RFC 9421 `alg` parameters `ed25519`/`ecdsa-p256-sha256` for request signatures. The names MUST NOT be interchanged.
- Section 11.1 now requires `Idempotency-Key` on every request; section 11.4 clarifies that non-mutating requests need no dedupe record while mutating endpoints must store and consult records.
- Idempotency comparison uses an operation digest over (method, target URI, `Content-Digest`, grant `jti`), not the signature-base digest. `tg.request_digest` in receipts keeps its section 14.1 meaning (full signature base) because receipts bind the exact signed request.

## Consequences

- `packages/core` implements JOSE allowlist `['EdDSA', 'ES256']` in `jwt.ts` and RFC 9421 allowlist `['ed25519', 'ecdsa-p256-sha256']` in `signature.ts`.
- `Idempotency-Key` is required at stage 1 of `verifyProtectedRequest` for all methods.
- The `IdempotencyStore` port compares an operation digest, documented in the core README and ports.
- Future spec edits must keep the two algorithm registries distinct; adding an algorithm means registering it in the correct registry.
