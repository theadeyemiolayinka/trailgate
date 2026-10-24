# TrailGate error code registry

Draft 0.1. Append-only: codes are added or deprecated, never reused or removed. Format: `tg.<domain>.<name>`, lowercase, dot-separated.

Every error response uses the envelope in `spec/schemas/error.schema.json`:

```json
{ "error": { "code": "tg.request.expired", "message": "signature window has passed", "detail": {} } }
```

`message` is for humans and not parsed. `detail` is optional structured context (for example the failing constraint type). HTTP status is advisory; `code` is authoritative.

## Registry

| Code | HTTP | Meaning | Expected behavior |
| --- | --- | --- | --- |
| `tg.discovery.invalid` | 400 | Discovery document failed schema or origin-rule validation | Reject document; do not use any endpoint from it |
| `tg.discovery.unsupported_version` | n/a | No common protocol version | Agent-side abort; never a server response |
| `tg.discovery.signature_invalid` | n/a | `trailgate-discovery-signature` header present but no token verifies against published `signing_keys` | Reject document; possible tampering |
| `tg.discovery.key_changed` | n/a | `signing_keys` changed without a signature endorsed by a previously pinned key | Reject document; re-verify the site out of band |
| `tg.grant.malformed` | 400 | Grant is not a well-formed signed grant for this site | Deny |
| `tg.grant.expired` | 403 | Grant `exp` or `valid_window` has passed | Deny; agent should discard the grant |
| `tg.grant.revoked` | 403 | Grant is revoked | Deny; agent should discard the grant |
| `tg.grant.redeemed` | 409 | Redemption already consumed for this `request_id` | Do not retry; poll status instead |
| `tg.grant.unknown` | 404 | Unknown `request_id` or `grant_id` (status, revocation, revocation queries) | Check the identifier; do not retry |
| `tg.grant.unknown_permission` | 400 | Requested permission not in site vocabulary | Fix request; do not retry unchanged |
| `tg.grant.scope_rejected` | 403 | Site refuses the requested permission, resource, or constraint set | Narrow the request or stop |
| `tg.grant.consent_denied` | 403 | User denied consent | Do not retry the same request |
| `tg.request.malformed` | 400 | Required headers/fields missing or unparsable | Fix request construction |
| `tg.request.body_digest_mismatch` | 400 | `Content-Digest` does not match received content | Check content encoding; retry once |
| `tg.request.signature_invalid` | 403 | Signature fails, wrong covered components, or unresolvable `keyid` | Do not retry unchanged |
| `tg.request.key_mismatch` | 403 | `keyid` does not equal the grant's `cnf.jkt` | Sign with the grant-bound key |
| `tg.request.expired` | 403 | Signature outside `created`/`expires` window or tolerance | Re-sign with current time; check clock skew |
| `tg.request.replay_detected` | 403 | `nonce` already seen for this grant | Do not retry identical request |
| `tg.request.idempotency_conflict` | 409 | `Idempotency-Key` reused with a different body | Fetch the stored outcome instead |
| `tg.request.idempotency_in_flight` | 409 | Same key and operation still executing; outcome not yet recorded | Retry the lookup after a delay |
| `tg.request.too_large` | 413 | Request exceeds the site's size limits | Reduce request size; do not retry unchanged |
| `tg.request.audience_mismatch` | 403 | Grant `aud` does not match this site | Grant belongs elsewhere; do not retry |
| `tg.request.permission_denied` | 403 | Action not covered by grant permissions | Stop; the grant does not allow this |
| `tg.request.resource_denied` | 403 | Resource not in grant scope or not owned by the grant's context | Stop; cross-context access is never retried |
| `tg.constraint.violated` | 403 | A grant constraint failed; `detail.type` names it | Stop or reduce the request within the constraint |
| `tg.constraint.unknown_type` | 403 | Constraint type in the grant is not evaluable | Site bug; grant should never have been issued |
| `tg.constraint.approval_required` | 403 | `approval_threshold` exceeded; `detail.approval_url` names the site decision surface when issued | Present the URL to the user; after approval, retry the identical request |
| `tg.authorization.denied` | 403 | Site business rules or user authorization deny the action | Stop; TrailGate does not override site policy |
| `tg.action.unknown` | 404 | The pending action id is unknown or belongs to a different grant | Stop; the id or grant is wrong |
| `tg.action.state_invalid` | 409 | The pending action is not in a state that allows the requested transition (decided, expired, cancelled) | Poll `action_status`; do not retry the transition |
| `tg.internal.unavailable` | 503 | A security-critical dependency was unavailable; request denied | Retry with backoff; fail closed on the client too |
| `tg.internal.error` | 500 | Unclassified server failure | Retry with backoff; report if persistent |

## Rules for adding codes

- New codes go through the ADR 0002 contract process with the spec change that introduces them.
- Sites MUST NOT invent `tg.*` codes outside the registry. Site-specific application errors use the site's own error surface, not the TrailGate envelope.
- Deprecated codes stay documented here with a `deprecated` note; consumers keep handling them.
