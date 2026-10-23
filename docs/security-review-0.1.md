# Security review: draft 0.1

Adversarial review of the TrailGate draft 0.1 contract (`spec/protocol.md`) against the
`packages/core` implementation and its tests, plus `packages/test-fixtures`, the ADRs, and
every documented security claim.

Reviewer stance: a normative requirement counts as satisfied only where code implements it
and tests demonstrate it. Passing happy-path tests are not evidence for untested
properties. Findings are not softened for demo purposes.

## Scope

In scope:

- `spec/protocol.md`, `spec/errors.md`, `spec/schemas/`, `spec/vectors/vectors.json`
- `packages/core` (all source and tests)
- `packages/test-fixtures`
- `docs/threat-model.md`, `docs/decisions/`, `docs/handoff.md`, `packages/core/README.md`,
  `SECURITY.md`

Out of scope, because no implementation exists in this repository:

- `packages/server`, `packages/agent`, `packages/mcp-adapter`, `apps/example-shop`,
  `packages/conformance` (skeletons only)
- Consent flow endpoints, redirect handling, HTTP servers, ledgers, key stores, audit logs

Every spec requirement assigned to those layers is reported as unimplemented, not as
passed.

## Verification results

| Command | Result |
| --- | --- |
| `pnpm check` | Clean. 48 info-level diagnostics (mostly `useLiteralKeys` style), no errors. |
| `pnpm typecheck` | Clean, all 8 packages. |
| `pnpm test` | 133 core tests, 38 vector tests, 5 package smoke tests. All pass. |
| `pnpm build` | Clean, all packages. |

These results were taken after the fixes below were applied.

## Severity scale

- **Critical**: direct credential or fund theft, or bypass of the core trust model.
- **High**: authorization bypass, cross-user access, or violation of a normative
  fail-closed requirement that is exploitable in a realistic deployment.
- **Medium**: security-relevant correctness defects, missing fail-closed handling, or
  forward-compatibility weaknesses.
- **Low**: spec-conformance defects with limited security impact (wrong error codes,
  parser leniency).

## Confirmed findings

All seven confirmed defects were in `packages/core` (the reviewer's own package) and have
been fixed with adversarial regression tests. "Verified fixed" means a dedicated test
demonstrates the corrected behavior at this commit.

### F-1: grants without `sub` could touch owned resources (High, fixed)

- **Component**: `packages/core/src/resources.ts` (`assertResourceAllowed`).
- **Defect**: when the grant payload had no `sub`, the ownership comparison against the
  `ResourceOwnerResolver` result was skipped entirely. A sub-less grant whose
  `tg.resources` listed `order:ord_1` passed the resource stage even when the resolver
  reported the order owned by another user context. This contradicts spec section 8,
  which requires the selector to resolve to a resource owned by the user context `sub`.
- **Exploitability**: real but bounded. Requires a site that issues grants without `sub`
  and resolves touched resources to owners. In such a deployment an agent holding a
  sub-less grant could operate on resources belonging to any user context the selector
  named.
- **Reproduction**: grant with no `sub`, `tg.resources: ["order:ord_1"]`, resolver
  returning `"sub_1"`. Previously allowed; the added test asserts
  `tg.request.resource_denied`.
- **Remediation**: ownership comparison is now mandatory. `resourceOwner !== subject`
  denies, which also denies sub-less grants against owned resources and grants whose
  resource is unknown to the site.
- **Status**: verified fixed. Test `denies owned resources to grants without a subject`
  in `packages/core/src/request.test.ts`.

### F-2: security-critical port failures escaped as raw exceptions (High, fixed)

- **Component**: `packages/core/src/request.ts`, `grant.ts`, `receipt.ts`,
  `constraints.ts`, `resources.ts`.
- **Defect**: exceptions thrown by `RevocationChecker`, `NonceStore`, `KeyResolver`,
  `Ledger`, `RateLimiter`, `ResourceOwnerResolver`, `IdempotencyStore`, and `SitePolicy`
  propagated raw to the caller. Spec section 11.3 requires unavailable security-critical
  dependencies to deny with `tg.internal.unavailable`. Raw errors also risked leaking
  infrastructure detail (driver messages, hostnames) into error responses, violating the
  error-handling rule that details must not disclose internal state.
- **Exploitability**: no path to unauthorized access was found (a thrown error still
  fails the request), so this is a fail-closed conformance defect plus an
  information-disclosure risk, not a bypass.
- **Remediation**: a shared `callPort` helper (`ports.ts`) wraps every security-critical
  port invocation. Errors carrying a registered `TrailGateError` code pass through
  unchanged; all other failures map to `tg.internal.unavailable`, except site-policy
  crashes which map to `tg.internal.error` per section 11.3 stage 14.
- **Status**: verified fixed. Tests cover throwing revocation, nonce store, resource
  resolver, ledger, rate limiter, and policy ports in `request.test.ts`.

### F-3: JOSE headers accepted embedded key-reference parameters (Medium, fixed)

- **Component**: `packages/core/src/jwt.ts` (`checkJwsHeader`).
- **Defect**: grant and receipt JWS headers were validated for `alg`, `typ`, `kid`, and
  `crit`, but `jwk`, `jku`, `x5c`, `x5u`, and `x5t` parameters were silently accepted.
  Core resolves keys only through `KeyResolver`, so embedded material could not actually
  be substituted for verification inside core. However, accepting these parameters
  invites key-substitution behavior in downstream consumers that forward the header, and
  it contradicts the JWS best practice of ignoring or rejecting key material sourced
  from the token itself.
- **Exploitability**: not exploitable inside core; a risk amplifier elsewhere.
- **Remediation**: `checkJwsHeader` now rejects any of `jwk`, `jku`, `x5c`, `x5u`,
  `x5t`, `x5t#S256` with `tg.grant.malformed`.
- **Status**: verified fixed. Test `rejects jws headers carrying embedded key material`
  in `grant.test.ts`.

### F-4: receipts ignored `critical` fields (Medium, fixed)

- **Component**: `packages/core/src/receipt.ts` (`parseReceiptPayload`).
- **Defect**: the receipt schema permits a `critical` array and spec section 4 requires
  documents listing unknown critical members to be rejected. Grant and discovery parsing
  enforced this; receipt parsing did not. A future receipt version marking a field
  critical would have been silently accepted by 0.1 verifiers.
- **Exploitability**: forward-compatibility risk, not exploitable today.
- **Remediation**: `parseReceiptPayload` takes `knownCriticalFields`; `verifyReceipt`
  forwards it. Unknown critical members reject. `verifyReceipt` also gained an optional
  `expectedGrantId` binding check so a verifier can ensure the receipt answers the grant
  it acted under.
- **Status**: verified fixed. Test `rejects receipts declaring unknown critical fields`
  and `rejects receipts answering a different grant` in `receipt.test.ts`.

### F-5: structured-fields parser accepted malformed and ambiguous input (Medium, fixed)

- **Component**: `packages/core/src/structured-fields.ts`.
- **Defects**, each independently confirmed by test before the fix:
  - the token charset admitted `:` and `/`, which RFC 8941 does not allow in tokens;
  - inner-list items were accepted without the required separating space
    (`("@method""@path")` parsed as two components);
  - duplicate parameters silently overwrote earlier values;
  - duplicate labels in the `Signature` field silently overwrote, while `Signature-Input`
    already rejected them. Overwrites are dangerous for canonicalization because two
    headers can disagree about which value is authoritative.
- **Exploitability**: parser differentials between implementations are a canonicalization
  risk. No concrete bypass was demonstrated inside core because the strict signature
  profile re-checks the parsed components, but strict parsing is the correct posture for
  a security boundary parser.
- **Remediation**: token charset tightened to the RFC 8941 subset used by this profile,
  inner lists require SP separation, duplicate parameters and labels reject with
  `tg.request.malformed`.
- **Status**: verified fixed. Tests in `structured-fields.test.ts`.

### F-6: missing `tg` label in `Signature` mapped to the wrong error (Low, fixed)

- **Component**: `packages/core/src/signature.ts` (`getSignatureBytes`,
  `componentIdentifier`).
- **Defect**: a syntactically valid `Signature` dictionary lacking the `tg` label threw
  `tg.request.malformed`. Spec section 11.3 stage 3 assigns signature-shape failures to
  `tg.request.signature_invalid`. Component parameters were also mapped to `malformed`.
- **Exploitability**: none found; error-code correctness matters for client behavior and
  audit signal quality.
- **Status**: verified fixed. Test `rejects a signature header missing the tg label` in
  `request.test.ts`.

### F-7: allowed receipts could carry `tg.code` (Low, fixed)

- **Component**: `packages/core/src/receipt.ts` (`buildReceiptPayload`).
- **Defect**: `code` was emitted whenever the caller supplied one. Spec section 14.1
  defines `tg.code` as present only for denied decisions.
- **Remediation**: `code` is now only attached when `decision === 'denied'`.
- **Status**: verified fixed. Test `omits code on allowed decisions even when provided`
  in `receipt.test.ts`.

## Design concerns (not confirmed vulnerabilities in core)

These are real security properties the spec requires of a deployment but that core cannot
satisfy because the implementing layer does not exist yet. They are documented here, in
the threat model, and in `docs/security-guarantees.md` so they cannot be mistaken for
finished work.

- **D-1 Concurrent spending.** Section 12 requires atomic reserve/consume/release/refund
  semantics so concurrent requests cannot exceed a grant budget. Core's `Ledger` port is
  read-only (`consumedMinorUnits`, `reservedMinorUnits`) because budget evaluation only
  reads totals. There is no reservation, commit, rollback, TTL release, or
  reconciliation code anywhere in the repository. A deployed server that implements
  check-then-act spending without atomicity will allow double spend. This is the single
  largest unimplemented normative requirement.
- **D-2 Consent and redirect security.** Section 10 requires exact-match redirect URI
  validation, `state` CSRF binding, single-use authorization codes, and S256 challenge
  binding. No consent, redirect, or callback handling exists. Code interception and CSRF
  protections are entirely untested.
- **D-3 Discovery transport.** Core validates a parsed discovery document (schema, HTTPS,
  same-origin endpoints, `critical`, version). Fetching over TLS, redirect policy,
  caching, and DNS trust are outside core and untested.
- **D-4 Key lifecycle.** Core resolves agent keys by `jkt` and site keys by `kid`.
  Rotation, stale-key overlap, secure storage at rest, and key provenance belong to
  implementations. No support exists beyond the resolver port.
- **D-5 Denial of service.** The `rate_limit` constraint depends on a `RateLimiter`
  port whose counting semantics (window type, atomicity) are defined by the caller, not
  by core. Body-size limits, endpoint quotas, parser resource limits, and storage
  exhaustion protections do not exist in core. `parseSignatureInput` is linear over the
  header but header size is unbounded at this layer.
- **D-6 Audit integrity and privacy.** Section 15's audit vocabulary is defined but no
  append-only store, retention, redaction, or access control exists.
- **D-7 Receipt limits.** `verifyReceipt` proves the receipt signature, issuer,
  audience, optional request-digest binding, and (new) optional grant binding. Per spec
  section 14.3 it does not prove settlement, fulfillment, or correct site behavior. No
  mechanism prevents a site from issuing a false receipt; that is inherent to the model.
- **D-8 Idempotency store guarantees.** Core dedupes on an operation digest but the
  store's atomicity (check-and-set vs read-then-write) is the port implementer's
  responsibility. A non-atomic store permits concurrent double execution.

## Spec ambiguities observed during review

- The nonce rule (section 11.2) says "at least 128 bits of entropy" while the
  implementation enforces a minimum 22-character nonce, matching the documented intent
  that 22 base64url characters encode approximately 132 bits. Implementations in other
  languages should enforce entropy-equivalent length, not arbitrary length. Worth a
  spec clarification in a future revision.
- `rate_limit` counting semantics (fixed vs sliding window) are unspecified; section 9
  defines only the parameters. Recorded as an open question.

## Requirement-to-test matrix

Normative requirements, implementation location, and the tests that actually exercise
them. "None" means no automated evidence exists.

| Requirement (spec section) | Implementation | Tests | Evidence |
| --- | --- | --- | --- |
| Discovery schema validation (5.x) | `discovery.ts` | `discovery.test.ts` valid/invalid docs | Tested |
| Discovery endpoints HTTPS + same-origin (5.x) | `discovery.ts` | `discovery.test.ts`, vectors | Tested |
| Discovery `critical` fail-closed (4) | `discovery.ts` | `discovery.test.ts` | Tested |
| Version negotiation (4) | `version.ts` | `version.test.ts` | Tested |
| Grant JWS alg allowlist EdDSA/ES256 (6.1) | `jwt.ts`, `grant.ts` | `grant.test.ts` disallowed alg | Tested |
| Grant `typ`, `kid`, `cnf.jkt` required (6.1) | `grant.ts`, `jwt.ts` | `grant.test.ts` missing fields, wrong typ | Tested |
| Grant iss/aud/exp validation (6.x) | `grant.ts` | `grant.test.ts` issuer, audience, expiry cases | Tested |
| Grant `critical` fail-closed (4) | `grant.ts` | `grant.test.ts` unknown critical | Tested |
| JOSE embedded key params rejected | `jwt.ts` | `grant.test.ts` jwk header | Tested (new) |
| Permission vocabulary check (7) | `permissions.ts` | `request.test.ts` outside vocabulary | Tested |
| Resource selector exact match (8) | `resources.ts` | `request.test.ts` outside scope | Tested |
| Resource ownership vs `sub` (8) | `resources.ts` | `request.test.ts` other subject, sub-less | Tested (fixed F-1) |
| Required headers incl. Content-Digest, Idempotency-Key (11.2) | `request.ts` stage 1 | `request.test.ts` missing headers | Tested |
| Content-Digest recomputation (11.3 s2) | `digest.ts` | `request.test.ts` tampered body | Tested |
| Signature-Input required components/tag/params (11.3 s3) | `signature.ts`, `structured-fields.ts` | `signature.test.ts`, `structured-fields.test.ts` | Tested |
| Signature window 300s + tolerance 120s (11.3 s4) | `request.ts` | `request.test.ts` expired/future windows | Tested |
| keyid must equal cnf.jkt (11.3 s8) | `request.ts` | `request.test.ts` keyid mismatch | Tested |
| PoP signature verification EdDSA/ECDSA (11.3 s8) | `signature.ts` | `request.test.ts` wrong key, tampered URL; `signature.test.ts` both algs | Tested |
| Nonce min length (11.2) | `signature.ts`/`request.ts` | `request.test.ts` short nonce | Tested |
| Atomic nonce claim keyed by (jti, nonce) (11.3 s9) | `request.ts` + `NonceStore` port | `request.test.ts` replay, cross-grant negative | Tested against port contract; store atomicity is port responsibility |
| Idempotency operation digest (11.3 s10) | `request.ts` | `request.test.ts` replay vs conflict | Tested against port contract |
| Permission check for touched resource (11.3 s11) | `permissions.ts` | `request.test.ts` denied permission | Tested |
| Constraint evaluation, all 4 types, conjunctive (9) | `constraints.ts` | `constraints.test.ts`, `request.test.ts` | Tested |
| Unknown constraint type fails closed (9) | `constraints.ts` | `constraints.test.ts` | Tested |
| Missing evaluators fail closed (9, 11.3) | `constraints.ts` | `constraints.test.ts` ledger unavailable | Tested |
| Port failure -> tg.internal.unavailable (11.3) | `ports.ts` `callPort` + call sites | `request.test.ts` revocation, nonce, resolver, ledger, limiter throws | Tested (fixed F-2) |
| Site policy hook (11.3 s14) | `request.ts` | `request.test.ts` policy reject and crash | Tested |
| Revocation check at enforcement (11.3 s7) | `request.ts` + `RevocationChecker` port | `request.test.ts` revoked grant | Tested against port contract |
| Receipt build/sign/verify (14) | `receipt.ts` | `receipt.test.ts` round trip, wrong key/aud/digest | Tested |
| Receipt `critical` fail-closed (4, 14) | `receipt.ts` | `receipt.test.ts` unknown critical | Tested (fixed F-4) |
| Receipt `code` only on denied (14.1) | `receipt.ts` | `receipt.test.ts` | Tested (fixed F-7) |
| Stable error registry | `errors.ts`, `spec/errors.md` | `errors.test.ts` | Tested |
| Consent flow, redirects, codes (10) | none | none | Unimplemented (D-2) |
| Atomic spending lifecycle (12) | none (read-only `Ledger` port) | none | Unimplemented (D-1) |
| Audit event store (15) | none | none | Unimplemented (D-6) |
| Discovery fetch over network (5) | none | none | Unimplemented (D-3) |
| Key rotation/storage | none | none | Unimplemented (D-4) |
| ES256 grant path end-to-end | `jwt.ts` accepts ES256 | none | Partial: alg accepted, no ES256 grant/signature integration test |

## Unsupported claims identified and corrected

- `docs/threat-model.md` line 3 claimed none of the mitigations were implemented. That
  was stale: core now implements and tests most enforcement-stage mitigations. The
  threat model has been rewritten to distinguish implemented, port-dependent, and
  unimplemented controls.
- The README phrase "replay protection" was accurate only because `NonceStore.claim` is
  atomic by contract; the new `docs/security-guarantees.md` states that the guarantee
  depends entirely on the port implementation.

## Conclusion

`packages/core` is a substantially tested enforcement-stage library for draft 0.1. Seven
defects were confirmed and fixed; none were critical. The protocol's consent,
spending-atomicity, discovery-transport, key-lifecycle, and audit requirements remain
unimplemented anywhere in this repository. Nothing in this codebase supports claims of
formal verification, certification, or production readiness.
