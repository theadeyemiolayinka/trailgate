# TrailGate

TrailGate is an experimental open protocol for secure, user-consented delegation from users to AI agents and automated clients.

A website that implements TrailGate exposes a standard way for an agent to discover supported capabilities, request user-approved access, prove possession of an authorized key, make permitted requests, and inspect resulting activity. A grant is scoped to a specific site, a specific agent key, explicit permissions, resource restrictions, an expiry, and structured constraints such as maximum transaction amount or cumulative budget. The website remains responsible for its own authentication, authorization, business rules, and authoritative constraint enforcement.

## Status

Experimental. TrailGate is not a proven security standard, the specification is not finalized, and nothing in this repository should be used in production or with real funds.

The repository contains the draft 0.1 protocol contract in `spec/` (normative document, JSON Schemas, error registry, examples, conformance vectors) plus working implementations: the core verification library, a framework-neutral server SDK, an agent SDK with CLI and MCP adapter, a port-contract conformance suite, and a SQLite-backed reference application. Security properties and their evidence are scoped in `docs/security-guarantees.md`; several surfaces remain deployment responsibilities (key custody, transport-level DoS controls, production stores).

## Repository layout

| Path | Purpose |
| --- | --- |
| `spec/` | Language-neutral protocol specification, schemas, wire formats, examples, conformance vectors. |
| `docs/` | Architecture, threat model, guides, and ADRs (`docs/decisions/`). |
| `packages/core/` | Shared types, validation, permission semantics, crypto verification abstractions, request binding, receipt verification. |
| `packages/server/` | Website integration SDK: authorization endpoints, grant lifecycle, policy integration, audit hooks. |
| `packages/agent/` | Client SDK: discovery, grant status, key management, consent initiation, signed requests, receipt verification. |
| `packages/agent-cli/` | Developer CLI built on the Agent SDK. |
| `packages/mcp-adapter/` | Optional MCP integration built on the Agent SDK. Not required to use TrailGate. |
| `packages/conformance/` | Reusable protocol conformance checks. |
| `packages/test-fixtures/` | Shared test vectors and fixtures. |
| `apps/example-shop/` | Ecommerce reference application with consent UX and simulated wallet. |
| `tests/` | Integration, security, adversarial, and interoperability suites. |
| `scripts/` | Development and reproducible demo scripts. |
| `internal/` | Team collaboration docs: roster, phases. Not protocol documentation. |

## Getting started

Prerequisites:

- Node.js 22.18 or later (unflagged TypeScript type stripping is required for tests)
- pnpm 11.3 or later (`corepack enable` is recommended)
- Git

```sh
pnpm install
pnpm verify
```

`pnpm verify` runs every quality gate in order:

| Command | What it does |
| --- | --- |
| `pnpm check` | Biome formatting and lint checks across the repo. |
| `pnpm build` | `tsc` emit to `dist/` in every package. Runs before typecheck and test because workspace packages resolve each other through `dist/`. |
| `pnpm typecheck` | `tsc --noEmit` in every package. |
| `pnpm test` | `node --test` in every package. |

`pnpm format` applies Biome formatting. `pnpm lint` runs lint checks only.

## Development

- `CONTRIBUTING.md`: workflow, commit style, code conventions, quality gates.
- `internal/TEAM.md`: workstream ownership and interface rules.
- `internal/PHASES.md`: staged build plan and integration milestones.
- `docs/architecture.md`: components and trust boundaries.
- `docs/threat-model.md`: assets, attackers, surfaces, mitigations, open risks.
- `docs/guides/quickstart.md`: verified external setup path.
- `docs/CONNECT_YOUR_AGENT.md`: connect an agent (Devin, Claude, Cursor, Windsurf, Codex) via MCP or the CLI.
- `docs/INSTALL_AND_DEPLOY.md`: bundle builds, MCP configs, two-laptop setup.
- `docs/RELEASING.md`: changesets versioning and the manual GitHub Release pipeline.
- `docs/limitations.md`: known limitations, honestly stated.
- `docs/security-review-0.1.md`: adversarial audit of draft 0.1 core.
- `docs/release-review-0.1.md`: requirement-to-test matrix, conformance findings, and the release decision.
- `docs/security-guarantees.md`: what this repository does and does not guarantee.
- `docs/decisions/`: architecture decision records.
- `docs/research/protocol-references.md`: standards research behind the contract.
- `docs/handoff.md`: which schema and interface each owner implements next.
- `spec/protocol.md`: the normative draft 0.1 contract.

## License

MIT. See `LICENSE`.
