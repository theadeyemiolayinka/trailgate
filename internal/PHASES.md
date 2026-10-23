# Phases

Staged build plan. A phase is complete when its deliverables are merged and its quality gates pass. Every phase requires `pnpm verify` green, ADRs for contract changes, and documentation kept in sync with code. Workstream codes (D0 to D3) are defined in `TEAM.md`.

Cross-cutting rule: shared interfaces are agreed before independent implementations depend on them. If a needed contract is missing or ambiguous, the responsible owner raises it to D0 before inventing one.

## Phase 0: Foundation (current)

Owner: D0.

- Monorepo, workspace tooling, quality gates, governance documents, package scaffolds.
- Gate: `pnpm verify` passes; repository reviewed by all owners.

## Phase 1: Specification and core

Owner: D0. Depends on: Phase 0.

- `spec/`: protocol document, machine-readable schemas, wire formats, error code registry, conformance vector format, worked examples.
- `packages/core/`: shared types, validation, permission model, crypto verification abstractions, request binding, receipt verification interfaces.
- `packages/test-fixtures/`: shared vectors consumable by all packages.
- Gate: spec draft 0.1 reviewed and tagged; the core API surface is agreed in writing by D1 and D2; vectors validate.

This phase freezes the contracts that the Server and Agent SDKs implement. Phase 2 work does not begin against undefined interfaces.

## Phase 2: SDKs

Owners: D1 (server), D2 (agent). Depends on: Phase 1 contracts.

- `packages/server/`: discovery endpoint, consent and grant endpoints, grant lifecycle (issue, refresh, revoke, expire), policy integration, audit hooks, authoritative constraint enforcement with atomic spending reservations.
- `packages/agent/`: discovery client, key management, consent initiation, signed request sender, grant status, receipt verification. Private keys must never reach model context.
- `packages/agent-cli/`: developer CLI on the Agent SDK.
- Gate: core conformance checks pass against both SDKs in `tests/`; adversarial test skeletons exist.

## Phase 3: Reference application and demonstration

Owner: D3. Depends on: Phase 2.

- `apps/example-shop/`: ecommerce reference app on the Server SDK, consent UX, simulated wallet with real authorization and accounting semantics (integer minor units, reservations, refunds, reconciliation).
- Reproducible end-to-end demo in `scripts/`: discovery, consent, scoped grant issuance, signed requests, budget enforcement, receipts, revocation.
- Gate: `tests/integration/` passes against the demo; consent UX reviewed against the threat model's disclosure requirements.

## Phase 4: Hardening and interoperability

Owners: D0 (conformance, security), D2 (MCP), all (test coverage). Depends on: Phase 3.

- `packages/conformance/`: runnable conformance suite usable by third-party implementers.
- `tests/security/` and `tests/adversarial/`: coverage mapped to `docs/threat-model.md`.
- `tests/interoperability/`: evidence that the protocol works without ExampleShop, for example a second independently implemented server or documented equivalent.
- `packages/mcp-adapter/`: optional MCP adapter on the Agent SDK.
- Gate: conformance suite passes; adversarial suite runs in CI; interoperability evidence documented.

## Phase 5: Documentation and release readiness

Owner: D0, all contributing. Depends on: Phase 4.

- `docs/guides/`: website integration guide, agent integration guide, MCP adapter guide.
- License decision completed and applied; changelog established; spec versioning policy finalized.
- Gate: full `pnpm verify`; documentation review; security re-review against `docs/threat-model.md`.

## Non-negotiables

- The protocol and the ordinary SDKs must work without ExampleShop and without MCP. Both are consumers of the protocol, not parts of it.
- The server SDK must preserve the host site's existing authentication and business logic.
- Constraints are enforced authoritatively on the server. An agent cannot widen a constraint by modifying a request.
- Fail closed: when a required check cannot be performed, the request is denied.
