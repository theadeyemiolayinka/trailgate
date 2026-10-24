# Blogarithm: getting started

## Prerequisites

- Node >= 22.18 (uses `node:sqlite` and native TS type-stripping)
- pnpm >= 11.3 (repo pins `pnpm@11.3.0`; `corepack pnpm` works everywhere)
- Repo deps installed once at the root: `corepack pnpm install`
- Workspace packages built once: `corepack pnpm -r --filter "@trailgate/*" build`

## Environment variables

| Var | Default | Meaning |
| --- | --- | --- |
| `BLOG_PORT` | `3401` | HTTP listener port |
| `BLOG_ISSUER` | `https://localhost:3444` | TrailGate issuer identity (bare https origin) |
| `BLOG_TLS_PORT` | `3444` | TLS listener port (requires dev certs) |
| `BLOG_HOST` | `127.0.0.1` | bind address |
| `BLOG_DB` | `data/blogarithm.db` | sqlite path, or `:memory:` |
| `BLOG_SEED` | `1` | seed demo data when the database is empty |

## Start

```bash
cd apps/blogarithm
corepack pnpm start          # serves http://127.0.0.1:3401
corepack pnpm dev            # same, with file watching
```

The database and seed data are created automatically on first run.

## TLS mode

```bash
corepack pnpm certs   # generates dev-certs/ca.crt + server cert (needs openssl)
corepack pnpm dev     # now also serves https://localhost:3444
```

Dev certs are generated locally and not committed. Trust them for Node
tools with `export NODE_EXTRA_CA_CERTS=$PWD/dev-certs/ca.crt`; import
`ca.crt` into the browser/OS trust store to remove the warning.

## Demo account

`demo@blogarithm.dev` / `demo-password-1`

## Agent demo

```bash
corepack pnpm demo           # full scripted scenario
corepack pnpm demo --manual  # pause so you can approve in the browser
```

`--manual` prints a consent URL; sign in, review the permission list, and
approve. Without `--manual` the demo approves through the real login and
consent form automatically (same HTTP path a human uses).

## Tests

```bash
corepack pnpm test           # 7 acceptance tests
corepack pnpm typecheck
```

## Troubleshooting

- `listen EACCES`: the port is in a Windows excluded range; set `BLOG_PORT`.
- `multiple stored grants match` from a custom agent: pass `grantId` to
  `fetchProtected` when more than one grant exists locally.
- Stale agent key/grant store: the agent SDK persists state in its file
  store; a fresh `SoftwareKeyProvider` per run is used by the shipped demo.
