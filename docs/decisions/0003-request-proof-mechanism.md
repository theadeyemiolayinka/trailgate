# 0003. Request proof mechanism: HTTP Message Signatures

Status: accepted, 2026-10-23.

## Context

Protected requests must bind the request to the grant, the agent key, the intended site, and the exact operation, including method, target, query, and body. Candidates evaluated: RFC 9449 DPoP, RFC 9421 HTTP Message Signatures, a TrailGate-specific signature envelope, and mutual TLS.

## Decision

RFC 9421 HTTP Message Signatures is the single normative request-proof scheme. The required covered components and parameters are profiled in `spec/protocol.md` section 11: `@method`, `@authority`, `@path`, `@query`, `content-digest` (RFC 9530, sha-256), `trailgate-grant`, `idempotency-key`, with signature parameters `created`, `expires`, `nonce`, `keyid`, `alg`, and `tag`.

## Alternatives rejected

- DPoP (RFC 9449): `htu` excludes the query and fragment, so query parameters are unbound; there is no body binding; and each request needs a JWT wrapper. DPoP is designed to sender-constrain OAuth tokens, not to prove the integrity of an arbitrary HTTP request.
- A bespoke signature envelope over canonicalized JSON: invents a mechanism where a reviewed standard exists, and would not interoperate with existing tooling or the emerging agent-signature ecosystem (draft-ietf-webbotauth, also built on RFC 9421).
- Mutual TLS: binds the channel, not the message; unusable through common agent runtime and proxy topologies; no per-request artifact for receipts.

## Consequences

- Implementers get IANA-registered algorithms and derived components plus existing library support.
- Replay protection is a TrailGate responsibility: the spec requires `nonce`, a bounded `created`/`expires` window, and server-side nonce caching; RFC 9421 alone does not prevent replay.
- No competing proof schemes exist in the normative path. If a future need (for example hardware-backed channel binding) appears, it arrives as a new ADR and version bump.
