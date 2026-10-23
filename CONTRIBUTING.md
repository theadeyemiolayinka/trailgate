# Contributing

## Setup

```sh
corepack enable
pnpm install
```

Node.js 22.18 or later and pnpm 11.3 or later are required (see `engines` in `package.json`).

## Quality gates

Run `pnpm verify` before submitting work. It runs, in order:

1. `pnpm check`: Biome format and lint checks. Fix with `pnpm format` or `biome check --write .`.
2. `pnpm typecheck`: `tsc --noEmit` per package.
3. `pnpm test`: `node --test` per package.
4. `pnpm build`: `tsc` emit per package.

Do not mark work complete because it compiles. Report which gates you actually ran and their results.

## Commits

- Conventional commits: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `build`, `ci`, `perf`.
- Scope to the owning area when useful, for example `feat(server): ...`.
- Small, reviewable changes. Do not reset or overwrite unrelated work.
- No AI co-author or attribution trailers.
- Never commit secrets, private keys, production credentials, or real customer data.

## Code conventions

- Strict TypeScript per `tsconfig.base.json`. Keep public APIs typed and documented.
- Validate all untrusted input at system boundaries: network responses, discovery documents, request bodies, redirects, persisted records, user input.
- Money is integer minor units plus an explicit currency identifier. Floating-point values are never an authoritative accounting representation.
- Use established cryptographic libraries and standards. Do not invent cryptographic algorithms.
- Prefer no new dependency. If one is needed, pin it in the `catalog` in `pnpm-workspace.yaml` and justify it in the change description.
- Relative imports in published package code use `.js` extensions (NodeNext resolution). Test files import `.ts` directly.
- No em dashes, en dashes, emojis, or decorative ASCII in code, comments, docs, or commit messages.

## Tests

- `node:test` with `*.test.ts` files co-located in `src/`.
- Tests run under Node's native type stripping: erasable TypeScript syntax only, and relative imports in test files must end in `.ts`.
- Test files are excluded from package `tsconfig.json` and are not typechecked by `tsc`. Biome still lints them.
- Cross-package suites live in `tests/`, not inside packages.

## Adding a package

Copy the scaffold shape used by existing packages: `package.json` with `build`, `typecheck`, and `test` scripts, a `tsconfig.json` extending `tsconfig.base.json`, a `README.md` stating owner and scope, and `src/index.ts`. Packages under `packages/*` and `apps/*` are picked up by the workspace automatically.

## Shared contracts

Any change to a shared interface (wire format, schema, error code, endpoint semantics, public SDK API used by another owner) requires all of:

1. An ADR in `docs/decisions/` describing motivation and alternatives.
2. Signoff from each affected owner per `internal/TEAM.md`.
3. Spec, schemas, examples, conformance vectors, and tests updated in the same change.

If a contract you need is missing or ambiguous, raise it to D0 before inventing an interface.

## Milestone reports

At each milestone report: what changed, which files and public APIs changed, which checks actually ran and their results, known limitations and security risks, dependencies on other owners, and the next recommended step.
