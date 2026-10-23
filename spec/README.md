# TrailGate specification

This directory holds the language-neutral protocol specification. Current version: 0.1-draft, experimental. It is not a proven security standard and is not ready for production use.

## Contents

- `protocol.md`: the normative protocol document (actors, discovery, consent, grants, proofs, constraints, spending, revocation, receipts, audit, errors).
- `errors.md`: the error code registry (append-only).
- `schemas/`: JSON Schema draft 2020-12 documents, `$id`s `urn:trailgate:schemas:*`:
  `discovery`, `grant-request`, `grant`, `constraint`, `receipt`, `error`, `audit-event`.
- `examples/`: worked examples (documents and an annotated protected request).
- `vectors/`: conformance vectors (`vectors.json`): schema cases validate against the schemas; decision cases record expected enforcement outcomes for the conformance suite.

## Error code convention

Protocol and SDK errors carry a stable, machine-readable code plus a human-readable message. Codes use the form `tg.<domain>.<name>` (for example `tg.grant.expired`). The registry in `errors.md` is append-only: codes are added or deprecated, never reused or removed.

## Rules

- Spec changes follow the process in `docs/decisions/0002-protocol-decision-and-versioning-process.md`.
- The spec must not depend on this repository layout, ExampleShop, or MCP.
- Schema and vector changes are validated by `packages/test-fixtures` (`src/spec-vectors.test.ts`), which runs under `pnpm test`.
- Owner: D0 (see `internal/TEAM.md`). Implementer handoff: `docs/handoff.md`.
