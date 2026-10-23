# 0007. Consent flow shape

Status: accepted, 2026-10-23.

## Context

Consent must be explicit, run on the site's existing authentication surface, and bind the resulting grant to the agent key that requested it. Two families were considered: an OAuth-style redirect flow and a GNAP-style interaction negotiation.

## Decision

An authorization-code-shaped flow:

1. The agent POSTs a grant request (permissions, resources, constraints, its public JWK, a `code_challenge`, and an optional `redirect_uri`) to the site's grant-request endpoint.
2. The site returns a `request_id` and a `consent_url` on its own origin.
3. The user authenticates on the site and approves or denies; the consent page renders the requested permissions, resources, constraints, and expiry verbatim from the stored request.
4. If the agent registered a `redirect_uri`, the site redirects to it with `request_id` and `state`. Otherwise the agent polls the grant-status endpoint.
5. The agent redeems the grant at the grant-redemption endpoint by presenting `request_id` and the `code_verifier` matching the S256 challenge. Only then is the signed grant JWT issued.

## Rationale

- The S256 challenge binds redemption to the requesting agent, the standard defense against interception of the redirect path, without requiring OAuth conformance.
- The stored-request rendering rule means the user approves exactly what the agent asked for; the consent page cannot be used to smuggle different terms.
- Redirect is optional so CLI agents and MCP adapters that cannot run a browser callback can still poll.
- GNAP's richer interaction negotiation was considered and deferred: it is more general than 0.1 needs. If multi-step interaction is required later, it arrives as a spec revision informed by RFC 9635.

## Consequences

- Redirect URIs are exact-match HTTPS URIs registered in the grant request; no patterns, no open redirects, per RFC 9700 guidance.
- A grant is issuable exactly once per request; replayed redemption fails.
