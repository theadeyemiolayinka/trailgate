# Threat model

Status: analysis only. None of the mitigations below are implemented yet. The phase column shows where each is expected to land per `internal/PHASES.md`.

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

## Surfaces, threats, required mitigations

| Surface | Threats | Required mitigation | Phase |
| --- | --- | --- | --- |
| Discovery document | Spoofing, downgrade, malicious endpoints | Schema validation, origin and audience binding, explicit protocol version | 1, 2 |
| Consent redirect and callback | Open redirect, CSRF, code interception | Strict redirect URI validation, state and nonce binding, single-use codes | 2, 3 |
| Grant issuance | Overbroad scope, confused deputy | Explicit consent, least-privilege scopes, per-resource checks at enforcement | 1, 2, 3 |
| Signed requests | Replay, tampering, key substitution | Proof-of-possession signatures binding method, target, body, audience, timestamp, nonce; server replay cache | 1, 2 |
| Constraints | Agent-side tampering, concurrent overspend | Server-authoritative checks, atomic spending reservations, idempotency keys, rollback on failure | 2, 3 |
| Expiry and revocation | Stale grants used after revocation | Short expiry, revocation checked at enforcement, fail closed on lookup failure | 2 |
| Model runtime | Credential exfiltration, prompt injection | Keys never enter model context, scoped least privilege, audited actions | 2 |
| Denial of service | Resource exhaustion, policy abuse | Rate limits, body size limits, per-grant quotas; agent identification is not proof of benign behavior | 2, 3 |
| Cross-user access | IDOR through a valid grant | Per-request resource ownership checks independent of grant validity | 2 |
| Key lifecycle | Key theft, stale or duplicated keys | Rotation support, secure storage at rest, documented provider limitations | 2 |
| Audit | Repudiation, log tampering | Signed receipts, append-only audit log | 2, 3 |
| Spending ledger | Double spend, reservation leak, refund errors | Atomic ledger operations, reconciliation, tested rollback paths | 3 |

## Unresolved risks

- Prompt injection cannot be eliminated by the protocol. Sites must treat agent-supplied instructions and agent-fetched content as untrusted.
- A keychain or OS secure store protects a key at rest but not against a compromised process that can invoke it. Provider-specific limitations must be documented per backend.
- Consent dark patterns are largely outside protocol scope. The spec should still define minimum disclosure requirements for the consent surface.
- The deniability and non-repudiation properties of receipts are undecided.
- Open spec questions: replay window size, clock skew tolerance, grant refresh semantics, and whether grants may be attenuated (narrowed) after issuance.

## Non-goals

- TrailGate does not make a malicious website safe. It assumes the site enforces its own rules honestly once it issues a grant; receipts and audit exist so users can inspect what happened.
- Agent identification is not a trust signal. A valid TrailGate client may still be hostile or compromised.
- No CAPTCHA bypass. Sites may apply explicit, auditable automation policy to TrailGate clients without granting elevated privileges by default.
