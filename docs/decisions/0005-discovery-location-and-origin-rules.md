# 0005. Discovery location and endpoint origin rules

Status: accepted, 2026-10-23.

## Context

Agents need a standard, verifiable way to find a site's TrailGate endpoints and keys. Prior art: RFC 8615 well-known URIs, RFC 8414 (`/.well-known/oauth-authorization-server`), OpenID Connect Discovery, and the webbotauth key-directory pattern.

## Decision

- The discovery document is served at `GET /.well-known/trailgate` with `Content-Type: application/json`. The suffix is unregistered with IANA; noted as an open issue.
- Every endpoint URL declared inside the document MUST share the document's origin (scheme, host, and port). Agents MUST reject a document whose endpoints point elsewhere. Cross-origin declarations may be added later only through an explicit mechanism, not by relaxing this rule.
- The document is versioned (`version` field, currently `0.1`), declares supported protocol versions, endpoints, the site's key set or its location, the permission vocabulary it honors, the constraint types it supports, and optional capabilities.
- Agents validate the document against `spec/schemas/discovery.schema.json` before use and treat it as untrusted input until validated. HTTPS is REQUIRED.

## Rationale

- The same-origin rule removes the entire class of attacks where a malicious or tampered discovery document points the agent's consent flow or signature verification at attacker infrastructure.
- A well-known path keeps integration to a single predictable URL and matches the deployment pattern implementers already know.

## Consequences

- Sites that genuinely need endpoints on a different origin are blocked in 0.1; this is deliberate.
- Because the document itself is fetched over TLS and all endpoints are same-origin, the TLS channel and the site's certificate anchor the document's authenticity. A signed discovery document was considered and deferred: it adds key-management complexity while TLS plus origin binding already covers the declared threat.
