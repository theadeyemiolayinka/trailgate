# Architecture

Status: proposed design. Except where noted, nothing described here is implemented. The normative contract will live in `spec/`; this document explains the intended shape and trust boundaries.

## Components

| Component | Purpose | Owner | Status |
| --- | --- | --- | --- |
| `spec/` | Language-neutral protocol contract: document, schemas, wire formats, error codes, vectors. | D0 | planned |
| `packages/core/` | Shared types, validation, permission semantics, crypto verification abstractions, request binding, receipt verification. | D0 | scaffolded |
| `packages/server/` | Website integration SDK: discovery endpoint, consent/grant endpoints, grant lifecycle, policy hooks, audit hooks, constraint enforcement. | D1 | scaffolded |
| `packages/agent/` | Client SDK: discovery, key management, consent initiation, signed requests, grant status, receipt verification. | D2 | scaffolded |
| `packages/agent-cli/` | Developer CLI on the Agent SDK. | D2 | scaffolded |
| `packages/mcp-adapter/` | Optional MCP adapter on the Agent SDK. Never required by the protocol. | D2 | scaffolded |
| `packages/conformance/` | Runnable conformance checks for third-party implementers. | D0 | scaffolded |
| `packages/test-fixtures/` | Shared test vectors and fixtures. | D0 | scaffolded |
| `apps/example-shop/` | Reference ecommerce site: consent UX, simulated wallet with real accounting semantics. | D3 | reserved, framework undecided |
| `tests/` | Cross-component suites: integration, security, adversarial, interoperability. | all | planned |

## Actors and trust boundaries

Actors: the user, the website (TrailGate server side), the agent (client side), the agent runtime (for example an LLM), and the user's browser used during consent.

Boundaries:

1. Agent to website: all protocol traffic crosses this boundary. Each side treats the other as untrusted; every message is validated.
2. Website to its user: the site's existing authentication and consent surface. TrailGate does not replace site authentication; the server SDK must preserve it.
3. Agent process to model runtime: private keys and unrestricted credentials never cross into model context. The model sees scoped grants and structured results, not signing material.
4. Discovery fetch path: the discovery document is untrusted input until validated against the schema and bound to the expected origin.
5. Persistence: grant store, wallet ledger, and audit log are authoritative server state, not agent-controllable data.

## Intended request flow (planned)

1. Discovery: the agent fetches the site's discovery document and validates it (schema, version, origin binding).
2. Consent: the agent initiates a consent flow; the user reviews and approves a narrowly scoped grant on the site.
3. Issuance: the site issues a grant bound to the site identifier, the agent's public key, permissions, resource restrictions, expiry, and structured constraints.
4. Requests: the agent sends signed requests proving possession of the authorized key. Signatures bind the method, target, body, audience, timestamp, and a nonce for replay resistance.
5. Enforcement: the site verifies the signature, checks the grant and its constraints against authoritative state, applies its own authorization and business rules, then executes or denies. It returns a verifiable receipt either way.
6. Inspection and revocation: the user and site can inspect activity; the site can revoke the grant.

## Design invariants

- Constraints are enforced authoritatively on the server. An agent cannot widen them by modifying a request.
- Every protected request re-checks the grant, resource ownership, and the site's own rules. A valid grant does not authorize every action.
- Money is integer minor units plus an explicit currency identifier. Floating-point values are never authoritative.
- Fail closed: when a required check cannot run, the request is denied.
- Keys rotate; grants expire; revocation is checked at enforcement time.
- Idempotency and atomic reservations protect against duplicate and concurrent spending.

## Error handling

Protocol and SDK failures surface as stable, machine-readable error codes from the spec error registry (draft convention in `spec/README.md`). SDKs map transport, validation, and verification failures to registry codes; unrecognized failures map to a generic internal code and never leak secrets, key material, or internal state.

## Dependency rules

- `packages/core/` has no dependency on any other TrailGate package.
- `packages/server/` and `packages/agent/` depend only on `core` and external libraries.
- `packages/agent-cli/`, `packages/mcp-adapter/` depend on `agent`.
- `apps/example-shop/` depends on `server` (and optionally `agent` for demo flows).
- The protocol must work without ExampleShop and without MCP.
