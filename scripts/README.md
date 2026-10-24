# Scripts

Development, demo, and release scripts.

| Script | Purpose | Entry point |
| --- | --- | --- |
| `agent-demo.ts` | Reproducible agent-connection demo: the full client flow against the server SDK in-process. | `node --experimental-strip-types scripts/agent-demo.ts` after `pnpm build` |
| `bundle.mjs` | Builds self-contained single-file executables (`bundle/trailgate.mjs`, `bundle/trailgate-mcp.mjs`). | `pnpm bundle` |
| `embed-schemas.mjs` | Embeds the `spec/schemas/` documents into package sources for the single-file bundles. | `pnpm embed` |
| `pack.mjs` | Assembles release artifacts in `dist-release/`: bundles, package tarballs, `SHA256SUMS`. | `pnpm release` |

See `docs/RELEASING.md` for the release pipeline and `docs/INSTALL_AND_DEPLOY.md` for how the bundles are consumed.
