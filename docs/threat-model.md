# Threat model

Status: updated for draft 0.1.
`packages/core` now implements and tests the enforcement-stage mitigations listed below.
Mitigations that depend on injected ports or on packages that do not exist yet are marked
accordingly; they are requirements for a deployment, not shipped guarantees.

Legend:

- **Core**: implemented and tested in `packages/core`.
- **Port**: core invokes it but correctness depends on the injected implementation.
- **Unimplemented**: no code exists in this repository; required of the SDK and
  application layers that consume `packages/core`.

## Assets

- Agent private keys and any credentials agents hold.
- Grants and the authority they carry: permissions, resource scope, budgets.
- User funds and transaction integrity, represented in integer minor units.
- User data and cross-user isolation on each website.
- Receipt and audit trail integrity.
- The consent decision itself: what the user understood and approved.

## Trust boundaries

- Agent to website protocol channel.
- Website to its own users (authentication and consent UX).
- Agent process to model runtime.
- Discovery document fetch path, including redirects.
- Server persistence: grant store, wallet ledger, audit log.

## Attackers

- Malicious or compromised agent, including a prompt-injected agent.
- Malicious or compromised website.
- Network attacker: MITM, DNS manipulation, redirect manipulation.
- Malicious user operating an otherwise honest agent.
- Site operator employing consent dark patterns (partially out of protocol scope).

## Surfaces, threats, mitigation status

| Surface | Threats | Required mitigation | Status |
| --- | --- | --- | --- |
| Discovery document | Spoofing, downgrade, malicious endpoints | Schema validation, HTTPS, same-origin endpoints, version and `critical` checks | Core (parse-time) + Agent SDK transport (HTTPS, no redirects, cache cap). Document signing: open spec issue |
| Consent redirect and callback | Open redirect, CSRF, code interception | Strict redirect URI validation, `state` binding, single-use codes, S256 challenge | Agent SDK (`validateConsentCallback`, S256) + Server SDK (single-use redemption CAS) |
| Grant issuance | Overbroad scope, confused deputy | Explicit consent, least-privilege scopes, per-resource checks at enforcement | Enforcement-side checks: Core. Consent flow: Server SDK + host UI |
| Signed requests | Replay, tampering, key substitution | RFC 9421 PoP binding method, target, body, timestamp, nonce; atomic nonce claim | Core. Nonce store atomicity: Port |
| Constraints | Agent-side tampering, concurrent overspend | Server-authoritative evaluation, atomic spending reservations, rollback | Evaluation: Core. Atomic spending lifecycle: Server SDK + Port (`cumulative_budget`, `spend_window` checked inside one atomic reserve) |
| Expiry and revocation | Stale grants used after revocation | Expiry checks, revocation at enforcement, fail closed on lookup failure | Core + Port (fail-closed on port error verified) |
| Model runtime | Credential exfiltration, prompt injection | Keys never enter model context, scoped least privilege, audited actions | Agent SDK (`AgentSigner` non-exportable, keys out of model-visible surfaces). Prompt injection itself: out of protocol scope |
| Denial of service | Resource exhaustion, policy abuse | Rate limits, body size limits, per-grant quotas | `rate_limit` constraint: Core + Port. Request size bounds (`maxBodyBytes`, `maxHeadersBytes`, `tg.request.too_large`): Server SDK. Connection-level quotas: host/edge |
| Cross-user access | IDOR through a valid grant | Per-request resource ownership checks independent of grant validity | Core + Port (sub-less grant bypass found and fixed: F-1) |
| Key lifecycle | Key theft, stale or duplicated keys | Rotation support, secure storage at rest, documented provider limitations | Site rotation: Server SDK (`rotateSigningKey`, multi-key publish/verify). Agent custody: Agent SDK (software/file providers; OS-keystore interface-ready, unimplemented). Site signing key custody: deployment responsibility (KMS) |
| Audit | Repudiation, log tampering | Signed receipts, append-only audit log | Receipts: Core. Audit sink: Port (append-only contract) |
| Spending ledger | Double spend, reservation leak, refund errors | Atomic ledger operations, reconciliation, tested rollback paths | Port contract implemented (`SpendingLedger`); atomicity: Port + conformance suite |
| Dependency failure | Silent continue, info leak | Fail closed with `tg.internal.unavailable`/`tg.internal.error` | Core (verified via throwing-port tests: F-2) |

## Unresolved risks

- Prompt injection cannot be eliminated by the protocol. Sites must treat agent-supplied
  instructions and agent-fetched content as untrusted.
- A keychain or OS secure store protects a key at rest but not against a compromised
  process that can invoke it. Provider-specific limitations must be documented per
  backend.
- Consent dark patterns are largely outside protocol scope. The spec should still define
  minimum disclosure requirements for the consent surface.
- The deniability and non-repudiation properties of receipts are undecided. A receipt
  proves the site recorded a decision; it does not prove settlement or fulfillment.
- Port implementations can silently weaken every Port-marked mitigation: a non-atomic
  `NonceStore`, a non-atomic `RequestIdempotencyStore`, a non-transactional
  `SpendingLedger`, or a `RateLimiter` with a read-then-write race each reintroduce
  the attack the port exists to prevent. `@trailgate/conformance`
  (`runPortContractSuite`) exercises these contracts against any implementation and
  must be run against production stores before deploying.
- An idempotency claim abandoned by a crashed request leaves a pending record that
  answers `tg.request.idempotency_in_flight` to retries until the site's claim TTL
  reclaims it. Stores that never expire pending records create a permanent denial
  for that key.
- Open spec questions: `rate_limit` counting semantics (fixed vs sliding window),
  replay store eviction semantics, reservation TTL, grant refresh, and whether grants
  may be attenuated after issuance.

## Non-goals

- TrailGate does not make a malicious website safe. It assumes the site enforces its own
  rules honestly once it issues a grant; receipts and audit exist so users can inspect
  what happened.
- Agent identification is not a trust signal. A valid TrailGate client may still be
  hostile or compromised.
- No CAPTCHA bypass. Sites may apply explicit, auditable automation policy to TrailGate
  clients without granting elevated privileges by default.
