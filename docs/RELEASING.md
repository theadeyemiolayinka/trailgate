# Releasing

TrailGate ships GitHub Releases only; packages are not on any npm registry
yet. A release is always an explicit human action.

## Versioning

Each package keeps an independent version (changesets, independent mode).

When you make a user-facing change, record intent next to the code:

```sh
pnpm changeset
# pick the affected packages + bump type; a .changeset/*.md file is created
```

Commit the changeset file with your change. Nothing is bumped yet.

To materialize queued changesets into real versions + CHANGELOG.md files:

```sh
pnpm version          # changeset version + lockfile sync
```

## Cutting a release

**From CI (preferred):** Actions -> `release` -> Run workflow. Optionally
pass a tag; the default is `v<@trailgate/agent-cli version>`. The
workflow applies queued changesets, commits the bump, runs `pnpm verify`
+ `pnpm bundle` + pack, then creates a GitHub Release attaching:

- `trailgate.mjs`, `trailgate-mcp.mjs` - the installable single files
- `trailgate-<pkg>-<version>.tgz` - npm tarballs of `packages/*`
- `SHA256SUMS` - checksums for everything

**Locally:**

```sh
pnpm release          # verify + bundle + dist-release/ artifacts
git tag v0.2.0 && git push origin v0.2.0
gh release create v0.2.0 dist-release/* --generate-notes
```

## What consumers do

Download `trailgate-mcp.mjs` (or `trailgate.mjs`) from the release page -
no npm install, no auth, needs only Node >= 22.18. See
`docs/INSTALL_AND_DEPLOY.md` for MCP client configs.

The `.tgz` tarballs are source-of-truth artifacts: their workspace deps
resolve to real versions (`@trailgate/core@0.1.0`) which no registry
serves yet, so `npm i` on them fails until publishing to a registry is
decided. That is a deliberate gap, not a bug - the bundles are the
supported install path for now.
