# 0001. Monorepo layout and tooling

Status: accepted, 2026-10-23.

## Context

TrailGate needs a language-neutral spec, several TypeScript SDK packages, a reference application, and cross-component test suites, developed in parallel with shared contracts between them.

## Decision

- Single pnpm workspace containing `packages/*` and `apps/*`. This is a development convenience only; protocol implementers are not required to use a monorepo, and nothing in `spec/` may depend on this layout.
- TypeScript in strict mode with `module` and `moduleResolution` set to `NodeNext`. Packages emit with `tsc` to `dist/`.
- Biome (`@biomejs/biome`) for formatting and linting. One dependency replaces a formatter plus a linter stack.
- `node:test` for tests, run under Node 22.18+ native TypeScript type stripping. Test files are `*.test.ts` co-located in `src/`, excluded from package `tsconfig.json`.
- Shared dev dependency versions are pinned in the `catalog` section of `pnpm-workspace.yaml` so every package compiles with the same toolchain.
- No task orchestrator (Turbo, Nx). `pnpm -r` is sufficient at the current scale. Revisit when build graph depth or CI time justifies the extra dependency and config.
- Node.js 22.18 or later is required (unflagged type stripping for `node --test`); pnpm 11.3 or later is required.
- License is undecided. `LICENSE` documents the pending state; packages are marked `UNLICENSED` until an ADR decides otherwise.

## Consequences

- Minimal dependency surface: the full toolchain is `typescript`, `@biomejs/biome`, and `@types/node`.
- Relative imports in emitted package code must use `.js` extensions (NodeNext). Test files import `.ts` directly because they run under type stripping.
- Test files are not typechecked by `tsc`; Biome still lints them. Revisit if this gap causes real failures.
- `turbo.json` is intentionally absent. Adopting Turbo later is additive and does not change package layout.
- TypeScript 7 is pinned in the catalog. If toolchain incompatibilities appear, downgrade to the latest 5.x in one change.
