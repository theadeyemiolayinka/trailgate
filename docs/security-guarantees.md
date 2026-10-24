# Security guarantees

What this repository does and does not guarantee at draft 0.1. Every claim below is
bounded by what the test suite actually demonstrates; see the requirement-to-test
matrix in `docs/security-review-0.1.md` for evidence per claim.

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
    evaluators deny. Registered types: `max_amount`, `cumulative_budget`, `rate_limit`,
    `valid_window`, `spend_window`.
12. Site policy hook (`SitePolicy`).
13. Fail-closed dependency handling: port failures map to `tg.internal.unavailable`
    (or `tg.internal.error` for policy crashes); registered protocol errors pass
    through unchanged.

`verifyGrant`, `signGrant`, `validateDiscoveryDocument`, `signReceipt`, and
`verifyReceipt` similarly enforce their respective schema, signature, audience, and
`critical` rules.

## Guaranteed by the server SDK (implemented and tested)

`packages/server` wires the pipeline over injected stores and adds:

- Full grant lifecycle: request intake with vocabulary and scope checks, consent
  decision, single-use redemption via CAS transition, status, revocation.
- Revocation caller model (spec section 13): a bound grant revokes itself through a
  section 11 signed request; other callers need a configured `revocationAuthorizer`;
  unsigned calls deny by default.
- Claim-at-lookup idempotency (spec section 11.4): `(grant jti, Idempotency-Key)` is
  claimed atomically before the handler runs; completed records replay, pending
  records answer `tg.request.idempotency_in_flight`, mismatched digests answer
  `tg.request.idempotency_conflict`. A failed outcome write is audited as
  `idempotency.record_failed`.
- Spending lifecycle: atomic `reserve` against `cumulative_budget` and `spend_window`
  headroom, consume on success, release on failure, refunds, reservation TTL.
- Signed receipts on allowed and parseable-denied decisions, delivered in the
  `trailgate-receipt` header (spec section 14.1).
- Request size bounds (`maxBodyBytes`, `maxHeadersBytes`) rejected before any
  cryptographic or storage work with `tg.request.too_large`.
- Denial behavior on early-malformed requests is the error envelope only: no receipt
  is issued when no grant or signature base could be bound.

## Guaranteed by the agent SDK (implemented and tested)

- Discovery: HTTPS origin normalization, no redirect following, schema and
  same-origin endpoint validation, version negotiation, `critical` handling,
  `Cache-Control`-aware caching capped at 24 h.
- Consent: `redirect_uri` exact matching, `state` binding, S256 verifier handling
  (verifier never leaves the client).
- Signed requests with the fixed covered components; receipts verified against the
  exact signature base sent.
- Key custody: `AgentSigner` has no export method; private key material never
  enters model-visible surfaces.
- Decision reporting: the client surfaces the server's typed error `code` and never
  computes or second-guesses a decision locally. Spend fields such as
  `consumed_under_grant` are informational point-in-time values from the server;
  they are not guarantees, and the only authoritative outcome is the response to
  the request itself.

## Guaranteed only if the port is correct

The pipeline's guarantees for these properties reduce to the port contract. A weak
implementation silently removes the protection:

- `GrantRequestStore.transition` must be a real compare-and-swap, or redemption is
  not single-use.
- `NonceStore.claim` must be atomic and honor TTL, or replay protection does not exist.
- `RequestIdempotencyStore.claim` must be atomic, or concurrent duplicates execute
  twice.
- `GrantRegistry.revoke`/`isRevoked` must reflect current state, or revoked grants
  keep working.
- `KeyResolver` must return authentic keys; a resolver that trusts embedded key
  material reintroduces key substitution.
- `SpendingLedger.reserve` must check and insert atomically, or concurrent requests
  overspend. `consumedInWindow` must be authoritative for `spend_window`.
- `RateLimiter` and `ResourceOwnerResolver` must report authoritative state.
- `AuditSink` must be append-only, or forensic claims are void.

`@trailgate/conformance` (`runPortContractSuite`) exercises these contracts against
any implementation. Run it against production stores before deploying.

## Not implemented anywhere in this repository

- OS-keystore or hardware key custody for agent keys (`AgentKeyProvider` interface is
  ready; only software and file providers ship).
- Site signing key custody: `signingKeys` accepts JWKs in config. ExampleShop stores
  the site JWK in SQLite for demo continuity; production sources keys from a KMS.
- Framework adapters beyond `node:http` (Express/Fastify/Hono). The
  `HostRequest`/`HostResponse` boundary is the integration point.
- Signed `grant_status` responses (permitted extension, not required; status is
  unsigned informational JSON and carries no authority).
- Discovery document signing (relies on TLS + same-origin; open spec issue).
- Grant refresh and post-issuance attenuation (open spec issues).
- Transport-level DoS controls beyond request-size bounds: connection quotas,
  global rate shaping, and parser resource limits are the host/edge layer's job.

## What a receipt does and does not prove

`verifyReceipt` establishes that the named issuer signed a decision for a grant,
bound optionally to a specific request digest. It does not establish that money
moved, that goods shipped, that the decision was correct, or that the site behaved
honestly. A site can sign a false receipt; the receipt only makes the claim
attributable.

## Error and disclosure guarantees

Protocol errors carry registered `tg.*` codes and do not include private keys,
credentials, or internal infrastructure detail. Port exceptions are wrapped so
driver messages and hostnames do not reach the response.
