# 0002. Protocol decision and versioning process

Status: accepted, 2026-10-23.

## Context

The spec will be consumed by independently implemented websites and agents. Uncontrolled contract changes would silently break interoperability and make security review meaningless. At the same time, the protocol is experimental and will need to break compatibility during drafts.

## Decision

- The normative contract lives in `spec/`. Code, docs, and examples are non-normative; where they disagree with the spec, the spec wins and they are fixed.
- Shared contracts are agreed before independent implementations depend on them. A contract change (wire format, schema, error code, crypto suite, endpoint semantics, public SDK API consumed by another owner) requires all of:
  1. An ADR in `docs/decisions/` with motivation and alternatives considered.
  2. Written signoff from each affected owner per `TEAM.md`. D0 arbitrates disputes.
  3. Spec, schemas, examples, conformance vectors, and tests updated in the same change.
- Versioning: pre-1.0 spec versions are drafts numbered `0.x`. Breaking changes between drafts are allowed but must bump the draft version and document migration. A semver commitment begins at 1.0, which is not declared before Phase 4 interoperability evidence exists.
- Error codes form an append-only registry in `spec/`. Codes are added or deprecated, never reused or removed.
- Discovery documents and grant formats carry explicit version fields from the start so implementations can detect incompatible peers.
- A contract ambiguity discovered during implementation blocks that work until resolved through this process; implementers do not invent interfaces.

## Consequences

- Contract changes are slower and heavier than ordinary changes, by design.
- Pre-1.0 breakage is permitted but always explicit and versioned; consumers can pin a draft.
- Silent contract drift is treated as a bug regardless of intent.
