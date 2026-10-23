# TrailGate specification

This directory holds the language-neutral protocol specification. Nothing here is normative yet; content lands in Phase 1 per `internal/PHASES.md`.

Planned contents:

- `protocol.md`: the protocol document: roles, flows, message formats, security requirements.
- `schemas/`: machine-readable schemas for discovery documents, grants, signed requests, and receipts.
- `examples/`: worked examples.
- `vectors/`: conformance test vectors, shared with `packages/test-fixtures/`.
- `errors.md`: the error code registry.

## Error code convention (draft)

Protocol and SDK errors carry a stable, machine-readable code plus a human-readable message. Codes use the form `tg.<domain>.<name>`, for example `tg.grant.expired` or `tg.request.replay_detected`. The registry is append-only: codes are added or deprecated, never reused or removed. This convention is a draft and is finalized with spec draft 0.1 in Phase 1.

## Rules

- Spec changes follow the process in `docs/decisions/0002-protocol-decision-and-versioning-process.md`.
- The spec must not depend on this repository layout, ExampleShop, or MCP.
- Owner: D0 (see `internal/TEAM.md`).
