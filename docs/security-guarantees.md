# Security guarantees

What `packages/core` does and does not guarantee at draft 0.1. Every claim below is
bounded by what the test suite actually demonstrates; see the requirement-to-test matrix
in `docs/security-review-0.1.md` for evidence per claim.

This is an experimental protocol. Nothing here is formally verified, certified, or
production-ready.

## Guaranteed by core (implemented and tested)

Given correctly implemented ports, `verifyProtectedRequest` enforces, in spec order:

1. Presence of required headers (`Signature-Input`, `Signature`, `Content-Digest`,
   `Trailgate-Grant`, `Idempotency-Key`).
2. `Content-Digest` matches the actual request body (SHA-256).
3. `Signature-Input` shape: required covered components, `tag: "trailgate"`,
   `keyid`, `created`, `expires`, `nonce` of at least 22 characters.
4. Signature freshness: `created`/`expires` within the 300-second window and
   120-second clock tolerance.
5. Grant JWS: allowed algorithms (`EdDSA`, `ES256`), correct `typ`, `kid`, `cnf.jkt`,
   issuer, audience, expiry, and fail-closed `critical` handling.
6. Revocation state (through the `RevocationChecker` port).
7. `keyid` equals the grant's `cnf.jkt`, and the RFC 9421 signature verifies under the
   resolved agent public key.
8. Replay: nonce claimed atomically under `(grant jti, nonce)` through `NonceStore`.
9. Idempotency: `Idempotency-Key` dedupe on an operation digest covering method, target
   URI, content digest, and grant.
10. Permission coverage, resource selector membership, and resource ownership against
    the grant `sub` (grants without `sub` cannot touch owned resources).
11. Conjunctive constraint evaluation; unknown constraint types and unavailable
    evaluators deny.
12. Site policy hook (`SitePolicy`).
13. Fail-closed dependency handling: port failures map to `tg.internal.unavailable`
    (or `tg.internal.error` for policy crashes); registered protocol errors pass
    through unchanged.

`verifyGrant`, `validateDiscoveryDocument`, and `verifyReceipt` similarly enforce their
respective schema, signature, audience, and `critical` rules.

## Guaranteed only if the port is correct

Core's guarantees for these properties reduce to the port contract. A weak
implementation silently removes the protection:

- `NonceStore.claim` must be atomic and honor TTL, or replay protection does not exist.
- `IdempotencyStore` must be atomic, or concurrent retries execute twice.
- `RevocationChecker` must reflect real revocation state with the staleness bound the
  deployment requires.
- `KeyResolver` must return authentic keys; a resolver that trusts embedded key material
  reintroduces key substitution.
- `Ledger` and `RateLimiter` must report authoritative totals.
- `ResourceOwnerResolver` must report authoritative ownership.

## Not guaranteed by core (no implementation exists)

- Atomic spending: reservations, consume, release, refund, rollback, reconciliation,
  and concurrent-budget enforcement. The `Ledger` port is read-only; section 12
  semantics are entirely the server layer's job.
- Consent flow security: redirect URI exact matching, `state` CSRF binding, single-use
  authorization codes, challenge verification.
- Discovery transport: HTTPS fetching, redirect policy, DNS/TLS trust, cache freshness.
- Key rotation, secure storage at rest, and stale-key lifecycle.
- Audit log integrity, append-only semantics, retention, and redaction.
- Denial-of-service controls at the transport layer: body limits, endpoint quotas,
  parser resource limits.
- The `rate_limit` constraint's window semantics and counting atomicity.
- ES256 grant verification end-to-end (the algorithm is accepted; no integration test
  exercises an ES256-signed grant).

## What a receipt does and does not prove

`verifyReceipt` establishes that the named issuer signed a decision for a grant, bound
optionally to a specific request digest. It does not establish that money moved, that
goods shipped, that the decision was correct, or that the site behaved honestly. A site
can sign a false receipt; the receipt only makes the claim attributable.

## Error and disclosure guarantees

Protocol errors carry registered `tg.*` codes and do not include private keys,
credentials, or internal infrastructure detail. Port exceptions are wrapped so driver
messages and hostnames do not reach the response.
