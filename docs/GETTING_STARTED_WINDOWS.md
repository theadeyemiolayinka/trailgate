# Getting started on Windows

Verified equivalents of the Unix setup. Commands were verified on macOS;
PowerShell translations below are provided for Windows and marked where
they could not be exercised on a Windows machine.

## Prerequisites

- Node.js 22.18 or later (<https://nodejs.org>). Check with `node -v`.
- pnpm 11.3 or later. `corepack enable` then `corepack prepare pnpm@11.3.0 --activate`,
  or `npm i -g pnpm`.
- Git for Windows (includes Git Bash and `openssl`, both needed for the
  certificate step).
- The Anthropic steps additionally need `ANTHROPIC_API_KEY`; everything
  else runs fully offline.

## Install and build

```powershell
git clone <repo-url>
cd trailgate
pnpm install
pnpm build
pnpm verify    # check + typecheck + all tests
```

`pnpm verify` runs `pnpm check`, `pnpm build`, `pnpm typecheck`, and the
full workspace test suite. On a clean checkout this is the single gate.

## Dev certificates (HTTPS)

The shop needs a locally trusted certificate so the browser and the agent
can reach `https://localhost:3443` without warnings.

Run in **Git Bash** (installed with Git for Windows):

```sh
cd apps/example-shop
pnpm certs
```

This uses `openssl` from Git Bash and writes `dev-certs/ca.crt`,
`server.crt`, `server.key`. It was verified under Git Bash semantics; if
`openssl` is not on PATH inside Git Bash, install Git for Windows which
bundles it, or use `mkcert` (`mkcert -install` then generate
`localhost` certs into `dev-certs/` and adjust `SHOP_CERTS_DIR`).

Trust the CA once:

- **For Node-based tools** (CLI, MCP server, claude-host):
  `setx NODE_EXTRA_CA_CERTS "C:\path\to\trailgate\apps\example-shop\dev-certs\ca.crt"`
  (new shells pick it up), or per-session
  `$env:NODE_EXTRA_CA_CERTS = "C:\path\to\...\ca.crt"`.
- **For the browser**, double-click `dev-certs\ca.crt` and install it into
  "Trusted Root Certification Authorities" (Current User), or run
  `certutil -addstore -user Root dev-certs\ca.crt` from an elevated shell.

## Start ExampleShop

```powershell
cd apps\example-shop
pnpm dev
```

Expected output:

```text
ExampleShop storefront:  http://127.0.0.1:3300
TLS listener (issuer origin): https://localhost:3443
```

Open `https://localhost:3443` (or `http://127.0.0.1:3300` for a quick look;
the TrailGate identity is the TLS origin). Sign in as `ada@example.com` /
`demo-pass-1234`. The wallet starts with a simulated USD 250.00 balance;
"Add test credit" on the wallet page tops it up and is labelled simulated.

## Agent CLI

After `pnpm build`:

```powershell
$env:NODE_EXTRA_CA_CERTS = "$PWD\apps\example-shop\dev-certs\ca.crt"   # from repo root
node packages\agent-cli\dist\cli.js keygen
node packages\agent-cli\dist\cli.js discover https://localhost:3443
node packages\agent-cli\dist\cli.js actions https://localhost:3443
```

State lives in `.\.trailgate` (or pass `--state-dir <dir>`).

## MCP server for a compatible agent host

```powershell
node packages\mcp-adapter\dist\mcp.js
```

Point your MCP host at that command with `TRAILGATE_STATE_DIR` and
`NODE_EXTRA_CA_CERTS` set as above. See
`packages/mcp-adapter/README.md` for a config example and
`docs/AGENT_INTEGRATION_GUIDE.md` for the full path.

## Stop

- Shop/CLI/MCP server: Ctrl+C in each terminal.
- Database: `apps\example-shop\data\example-shop.db`; delete it to reset
  (it reseeds on next start).
- Agent state: delete `.trailgate` to wipe keys, grants, and pending
  consent sessions.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `TLS listener inactive` | run `pnpm certs` in `apps\example-shop` (Git Bash), restart `pnpm dev` |
| `certificate has expired` / self-signed errors from the CLI | set `NODE_EXTRA_CA_CERTS` to `dev-certs\ca.crt` in the same shell |
| Browser warns about the certificate | install `ca.crt` into the user trust store (above) |
| `ERR_PNPM_...` on install | `pnpm -v` must be >= 11.3; `corepack prepare pnpm@11.3.0 --activate` |
| `SHOP_ISSUER must be a bare https origin` | `SHOP_ISSUER` accepts only `https://host[:port]`, no path |
| Discovery fails with `tg.discovery.invalid` | the issuer is `https://localhost:3443`; `http://` targets are rejected by design |
| Port in use | `SHOP_PORT`/`SHOP_TLS_PORT` env vars change the listeners |
