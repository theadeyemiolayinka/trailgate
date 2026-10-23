# Protocol references and prior art

Research record for the TrailGate draft 0.1 contract. Compiled 2026-10-23. Referencing a specification here does not mean TrailGate conforms to it; the applicability column states exactly what is borrowed.

## Normative building blocks

| Source | Version / status | What TrailGate uses | Applicability and limitations |
| --- | --- | --- | --- |
| RFC 9421, HTTP Message Signatures | RFC, Feb 2024 | Request proof mechanism: `Signature-Input` and `Signature` fields, covered components, signature parameters (`created`, `expires`, `nonce`, `keyid`, `alg`, `tag`) | Adopted as the single request-proof scheme. Does not itself define replay caching, grant binding, or key distribution; TrailGate layers those on top. |
| RFC 9530, Digest Fields | RFC, Feb 2024. Obsoletes RFC 3230 | `Content-Digest` header for request body integrity | Only `sha-256` and `sha-512` are considered secure; TrailGate requires `sha-256`. Covers message content, not headers; headers are covered as signature components instead. |
| RFC 7519, JWT | RFC, May 2015 | Grant and receipt wire format (compact JWS) | Used as a signed, inspectable document format. Registered claims (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`) carry their standard meanings. TrailGate is not an OAuth token profile. |
| RFC 7515, JWS; RFC 7517, JWK | RFCs, May 2015 | Signature container and public key representation | JWK used for agent and site keys in discovery, consent requests, and key rotation. |
| RFC 7800, `cnf` claim | RFC, Apr 2016 | `cnf.jkt` key binding inside grants | Standard claim for binding a token to a key. TrailGate uses only the `jkt` member. |
| RFC 7638, JWK Thumbprint | RFC, Sep 2015 | `jkt` computation and `keyid` derivation | Defines the canonical hash over required JWK members. TrailGate uses `sha-256` thumbprints. |
| RFC 8615, Well-Known URIs | RFC, May 2019 | `/.well-known/trailgate` discovery location | The `trailgate` suffix is not registered with IANA; noted as an open issue. Sites should treat the path as reserved on their origin. |
| RFC 9110, HTTP Semantics | RFC, Jun 2022 | Method semantics, status codes, field syntax | General HTTP behavior; status code usage in section 16 of `spec/protocol.md`. |
| RFC 9651, Structured Fields | RFC, Sep 2024 | Syntax of signature and digest fields | Inherited through RFC 9421 and RFC 9530. |
| RFC 2119 / RFC 8174 | Keywords | Normative requirement language | Standard usage. |

## Informed design (not adopted wholesale)

| Source | Version / status | Relationship to TrailGate |
| --- | --- | --- |
| RFC 6749 + RFC 6750, OAuth 2.0 | RFCs, 2012 | The consent flow is authorization-code-shaped (request, user approval, redirect or polling, redemption). TrailGate does not claim OAuth conformance; it borrows the proven interaction pattern. |
| RFC 9700 (BCP 240), OAuth security | RFC, Jan 2025. Updates RFC 6749/6750/6819 | Source of hardening rules adopted by reference: exact-match redirect URIs, sender-constrained artifacts, short artifact lifetimes, CSRF protection on consent. |
| RFC 7636, PKCE | RFC, Sep 2015 | The consent redemption step uses the same S256 code-challenge binding idea: the grant request carries a challenge, redemption requires the verifier. Not PKCE itself; same construction. |
| RFC 9396, RAR | RFC, May 2023 | `authorization_details` is the model for typed authorization data: arrays of objects discriminated by a `type` field. TrailGate permissions, resources, and constraints follow this typing pattern without implementing RAR. |
| RFC 9449, DPoP | RFC, Sep 2023 | Evaluated and rejected as the request proof. `htu` excludes query and fragment so query parameters are unbound; no body binding; per-request JWT adds overhead without benefit here. Recorded in ADR 0003. |
| RFC 9635, GNAP | RFC, Oct 2024 | Closest prior art: delegation to software, key-bound access tokens, typed access-rights arrays, grant lifecycle. TrailGate differs in being site-scoped and HTTP-signature-native rather than AS-mediated; GNAP informed the access-rights data model. |
| RFC 9767, GNAP RS connections | RFC, Apr 2025 | RS-side key registration and token handling patterns informed grant key binding. |
| RFC 8693, Token Exchange | RFC, Jan 2020 | Considered for agent-to-agent delegation; out of scope for 0.1. Grant attenuation (issuing a narrower grant from an existing one) is an open issue that may draw on it. |
| draft-ietf-httpapi-idempotency-key-header-08 | IETF I-D, active, Oct 2026 | `Idempotency-Key` header semantics. Limitation: still a draft; the field may change. TrailGate pins the current semantics and will track the RFC. |
| draft-ietf-webbotauth-httpsig-protocol | IETF I-D, webbotauth WG | Agent identification using HTTP signatures and `Signature-Agent`. Complementary: it identifies a client to an origin, it does not carry delegated authorization. TrailGate may later allow it alongside; agent identification is not treated as trust. |
| RFC 8252, OAuth for native apps; RFC 6819 (superseded) | RFCs | Threat input only; RFC 9700 supersedes 6819 as the current BCP. |

## Open questions raised by the research

- Whether to register `/.well-known/trailgate` with IANA once the draft stabilizes.
- Whether receipts should use a detached JWS over a canonical JSON body or a JWT payload (0.1 uses a JWT payload; a detached signature over the raw response body may compose better with RFC 9421 response signatures, which are not yet specified here).
- Cross-origin endpoint declarations in discovery are prohibited in 0.1; if real deployments need them, an explicit allowlist mechanism must be designed.
- GNAP-style grant continuation/negotiation (multi-step grants, interaction finish URIs) may replace the simpler request-consent-redeem flow if adoption shows the need.
