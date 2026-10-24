# Installing TrailGate on an agent

TrailGate is an experimental protocol; it is not published to npm. The
supported distribution is a self-contained single-file bundle: one `.mjs`
file that runs anywhere Node >= 22.18 exists, with no `npm install`.

Two artifacts are produced:

| File | Role |
| --- | --- |
| `bundle/trailgate.mjs` | Agent CLI (keygen, discover, actions, request, fetch, ...) |
| `bundle/trailgate-mcp.mjs` | MCP stdio server exposing the nine `trailgate.*` tools |

## Build the bundle

```sh
pnpm install
pnpm bundle          # runs the package builds, then esbuild
ls bundle/
```

Copy the `.mjs` file(s) to the target machine (scp, AirDrop, USB, a
release artifact - anything). On the target you need only Node >= 22.18.

```sh
node trailgate.mjs keygen --state-dir ./tg-state
node trailgate.mjs discover https://your-shop.example --state-dir ./tg-state
```

`--state-dir` picks where keys, pending sessions, grants, and the
discovery cache live. For the MCP server set `TRAILGATE_STATE_DIR` in its
environment instead (MCP clients do not pass argv).

## Wire it into an MCP client

The MCP server speaks JSON-RPC 2.0 over stdio. Point your client at the
bundle (or at `node packages/mcp-adapter/dist/mcp.js` inside the repo).
`TRAILGATE_STATE_DIR` selects the state directory;
`NODE_EXTRA_CA_CERTS` makes it trust a dev CA like ExampleShop's.

### Windsurf (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "trailgate": {
      "command": "node",
      "args": ["/path/to/trailgate-mcp.mjs"],
      "env": {
        "TRAILGATE_STATE_DIR": "/path/to/tg-state",
        "NODE_EXTRA_CA_CERTS": "/path/to/ca.crt"
      }
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json`)

Same `mcpServers` shape as above.

### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)

Same `mcpServers` shape as above, then restart the app.

### Claude Code

```sh
claude mcp add trailgate -- node /path/to/trailgate-mcp.mjs
# per-server env via -e flags, e.g. -e TRAILGATE_STATE_DIR=/path/to/tg-state
```

### Codex CLI (`~/.codex/config.toml`)

```toml
[mcp_servers.trailgate]
command = "node"
args = ["/path/to/trailgate-mcp.mjs"]
env = { TRAILGATE_STATE_DIR = "/path/to/tg-state", NODE_EXTRA_CA_CERTS = "/path/to/ca.crt" }
```

### Verify the wiring without a model

```sh
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n' \
  | node trailgate-mcp.mjs
# -> {"protocolVersion":"2024-11-05",...,"serverInfo":{"name":"trailgate-mcp"}}
```

Then ask your agent: "use trailgate_discover on https://your-shop.example
and tell me what actions exist".

## Two-laptop setup (shop on machine A, agent on machine B)

The agent and the MCP server never need the repo; only the shop does.

**Machine A (the site):**

```sh
# cert must name the address the agent will dial
SHOP_CERT_SAN="DNS:shop-host.local,IP:192.168.1.20" pnpm certs

# listen on the LAN, and make the issuer origin match the cert SAN
SHOP_HOST=0.0.0.0 \
SHOP_ISSUER=https://shop-host.local:3443 \
SHOP_TLS=1 \
pnpm dev
```

`SHOP_ISSUER` is the protocol origin embedded in discovery, consent URLs,
grants, and receipts. It must be the same `https://host:port` the agent
dials, and that host must be covered by the certificate's SANs.

**Machine B (the agent):**

```sh
scp machine-a:apps/example-shop/dev-certs/ca.crt ./ca.crt
scp machine-a:bundle/trailgate.mjs machine-a:bundle/trailgate-mcp.mjs ./

export NODE_EXTRA_CA_CERTS=$PWD/ca.crt
node trailgate.mjs keygen --state-dir ./tg-state
node trailgate.mjs discover https://shop-host.local:3443 --state-dir ./tg-state
node trailgate.mjs request https://shop-host.local:3443 \
  --permission tg.cart.read --permission tg.order.create --state-dir ./tg-state
# consent URL points at machine A; open it in any browser, sign in, approve
node trailgate.mjs redeem https://shop-host.local:3443 --request-id <id> --state-dir ./tg-state
node trailgate.mjs fetch https://shop-host.local:3443 /api/cart --state-dir ./tg-state
```

Or register `trailgate-mcp.mjs` in your MCP client on machine B with
`NODE_EXTRA_CA_CERTS` pointing at the copied `ca.crt`, and drive it in
natural language.

## What is and is not distributed

- Bundled: the whole agent-side stack (core, agent SDK, CLI, MCP tools).
- Not bundled: the server SDK and ExampleShop. Sites integrate
  `@trailgate/server` from this repo; publishing to npm is a separate,
  later step.
- Node builtin `node:sqlite` is not used by the agent bundles; only the
  ExampleShop needs it.

## Caveats

- Bundles are dev artifacts, not signed releases. Verify checksums if you
  transfer them over untrusted channels.
- The dev CA is for development. For anything beyond a LAN demo, issue a
  real certificate and a public origin.
- `keys.json` in the state dir holds plaintext private JWKs (mode 0600).
  Protect it like a password.
