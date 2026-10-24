# Team

Four workstreams. Each owner controls the interfaces in their area. Interfaces that cross ownership boundaries are agreed in writing before dependent code is written against them.

Workstream codes (D0 to D3) are used throughout the repository as shorthand. This file is the only place codes are mapped to people.

## Roster

| Workstream | Person | Scope |
| --- | --- | --- |
| D0 | Adeyemi Olayinka | Technical lead. Protocol design, `spec/`, `packages/core/`, `packages/conformance/`, `packages/test-fixtures/`, security architecture, ADR arbitration. |
| D1 | Adekola Oluwasegun | `packages/server/`: website integration SDK, authorization endpoints, grant lifecycle, policy integration, audit hooks. |
| D2 | Banjo Oluwatimilehin | `packages/agent/`, `packages/agent-cli/`, `packages/mcp-adapter/`: discovery, key management, consent initiation, signed requests, receipt verification. |
| D3 | Odunaro Oluwatimilehin | `apps/example-shop/`, consent UX, end-to-end demonstration, `tests/` suites. |

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
| ~~License selection~~ decided: MIT | D0 | done |
| Protocol draft version 0.1 | D0 | Phase 1 |
| ~~ExampleShop framework choice~~ | D3 | decided: node:http + node:sqlite, zero added deps |
