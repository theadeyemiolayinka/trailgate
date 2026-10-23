# Team

TrailGate is built by four owners, each responsible for a workstream. Owners control the interfaces in their area. Interfaces that cross ownership boundaries are agreed in writing before dependent code is written against them.

## Workstreams

| Owner | Scope |
| --- | --- |
| D0 (technical lead) | Protocol design, `spec/`, `packages/core/`, `packages/conformance/`, `packages/test-fixtures/`, security architecture, ADR arbitration. |
| D1 | `packages/server/`: website integration SDK, authorization endpoints, grant lifecycle, policy integration, audit hooks. |
| D2 | `packages/agent/`, `packages/agent-cli/`, `packages/mcp-adapter/`: discovery, key management, consent initiation, signed requests, receipt verification. |
| D3 | `apps/example-shop/`, consent UX, end-to-end demonstration, `tests/` suites. |

## Working rules

- Shared interfaces are agreed in `spec/` or an ADR before independent implementations depend on them.
- Contract ambiguity blocks the work. Raise it to D0; do not invent an interface.
- Significant decisions are recorded as ADRs in `docs/decisions/` (see ADR 0002 for the process).
- Do not overwrite or reset another owner's work. Coordinate through ADRs and explicit handoffs.
- Public interfaces must be typed and documented. Contract changes update the spec, schemas, vectors, and tests in the same change.
- Milestone reports follow the format in `CONTRIBUTING.md`.

## Open decisions

| Item | Owner | Target |
| --- | --- | --- |
| License selection | D0 | Phase 5 |
| Protocol draft version 0.1 | D0 | Phase 1 |
| ExampleShop framework choice | D3 | Phase 3 |
