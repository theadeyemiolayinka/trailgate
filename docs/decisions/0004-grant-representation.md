# 0004. Grant representation and key binding

Status: accepted, 2026-10-23.

## Context

A grant must be inspectable by the agent (so it knows its own authority), verifiable by the issuing site, and revocable. Candidates: opaque token plus introspection, CWT (RFC 8392), a custom signed JSON document, and a JWT (compact JWS).

## Decision

- A grant is a compact JWS JWT signed by the site's grant-signing key. Registered claims carry `iss`, `aud`, `exp`, `iat`, `jti`, and an optional `sub` for the delegated user context. TrailGate-specific data lives under a `tg` claim (version, permissions, resources, constraints).
- The agent key binding uses `cnf.jkt` (RFC 7800): the SHA-256 JWK thumbprint (RFC 7638) of the agent's public key. Requests prove possession via HTTP Message Signatures; the verifier recomputes the thumbprint from `keyid`-resolved key material or the presented key.
- All protocol timestamps are integer seconds since the Unix epoch (`NumericDate` semantics), including receipts and status responses. Identifiers are opaque strings with at least 128 bits of entropy; UUIDv7 or base64url-encoded random values are recommended.
- Signature algorithms: `ed25519` is REQUIRED to implement for grant, receipt, and request signatures. `ecdsa-p256-sha256` is OPTIONAL for environments where P-256 hardware support matters. No `none`, no `HS256`, no RSA PKCS#1 v1.5.

## Alternatives rejected

- Opaque token with introspection: the agent cannot inspect its own authority; adds a mandatory round trip; contradicts the inspectability requirement.
- CWT: CBOR tooling is thinner for typical web implementers; no compensating benefit at web scale.
- Custom signed JSON: reinvents JWS poorly; loses registered claim semantics and library verification.

## Consequences

- A grant is self-contained but never self-authorizing: enforcement always checks signature, expiry, revocation state, constraints, and site authorization. Possession of a valid JWT grant does not imply the action is permitted.
- `sub` is optional and pseudonymous by design; the site keeps the user mapping internally and grants carry no personal data.
