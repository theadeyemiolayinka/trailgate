# Connect your agent

The complete path from "nothing installed" to an AI agent acting on
ExampleShop under a grant you approved. Every install path ends at the
same place: the nine `trailgate.*` tools over a shared `.trailgate`
state directory.

## What the agent actually gets

A stdio MCP server (`trailgate-mcp.mjs`) that owns all the cryptography:
key generation, discovery + signature verification, consent initiation,
PKCE redemption, request signing, receipt verification. The model only
picks tools and reads results — it never touches key material.

| Tool | Does |
| --- | --- |
| `trailgate.discover` | Validate a site's TrailGate support, return capabilities + actions |
| `trailgate.actions` | List the action catalog with local grant coverage |
| `trailgate.request` | Start a grant request; returns a consent URL for you |
| `trailgate.status` | Check a pending request's consent state |
| `trailgate.redeem` | Exchange an approved request for a grant (PKCE) |
| `trailgate.access` | Local check: does a stored grant cover these permissions? |
| `trailgate.fetch` | Signed request to a protected endpoint, with receipt |
| `trailgate.grants` | List stored grant metadata (never the tokens) |
| `trailgate.revoke` | Revoke a grant |

## Step 0: build the bundle (once, or download from a release)

```sh
cd trailgate
pnpm install && pnpm bundle   # -> bundle/trailgate.mjs, bundle/trailgate-mcp.mjs
```

Or grab both files from the latest GitHub Release — no build needed.

## Step 1: Devin

Devin reads `~/.config/devin/mcp_config.json` (already written for this
machine — shown here for reference):

```json
{
  "mcpServers": {
    "trailgate": {
      "command": "node",
      "args": ["/path/to/trailgate-mcp.mjs"],
      "env": {
        "TRAILGATE_STATE_DIR": "/path/to/.trailgate",
        "NODE_EXTRA_CA_CERTS": "/path/to/ca.crt"
      }
    }
  }
}
```

`NODE_EXTRA_CA_CERTS` is only needed while ExampleShop uses its dev CA.
Restart Devin sessions after editing; then ask it to use the
`trailgate.*` tools.

## Step 2: any other MCP client

Same `mcpServers` shape everywhere:

- **Windsurf**: `~/.codeium/windsurf/mcp_config.json`
- **Cursor**: `~/.cursor/mcp.json`
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Claude Code**: `claude mcp add trailgate -- node /path/to/trailgate-mcp.mjs`
- **Codex**: `~/.codex/config.toml`, `[mcp_servers.trailgate]` table

## Step 3: start the shop

```sh
cd trailgate/apps/example-shop
pnpm certs                                   # first time only
export NODE_EXTRA_CA_CERTS=$PWD/dev-certs/ca.crt
SHOP_TLS=1 pnpm dev                          # https://localhost:3443
```

## Step 4: drive it with natural language

Tell your agent (Devin, Claude, whatever is connected):

> "Discover whether https://localhost:3443 supports TrailGate, list its
> actions, then request access to read my cart and create orders."

The agent will call `trailgate.discover` -> `trailgate.actions` ->
`trailgate.request`, which prints a `consentUrl`. **You** open that URL,
sign in (`ada@example.com` / `demo-pass-1234`), review the scope, approve.
Then tell it:

> "Redeem that request, then fetch my cart."

`trailgate.redeem` exchanges the approval for a grant;
`trailgate.fetch` signs the request and returns cart data plus a signed
receipt. Try the constraints too:

> "Checkout my cart" (order create + pay; an `approval_threshold` over
> USD 50 will produce a signed `tg.constraint.approval_required` denial
> with an approval URL you open and decide)

## Step 5: the no-MCP path (raw CLI)

Same state dir, same tools, human-driven:

```sh
node bundle/trailgate.mjs keygen   --state-dir ~/.trailgate
node bundle/trailgate.mjs discover https://localhost:3443 --state-dir ~/.trailgate
node bundle/trailgate.mjs actions  https://localhost:3443 --state-dir ~/.trailgate
node bundle/trailgate.mjs request  https://localhost:3443 \
    --permission tg.cart.read --permission tg.order.create --state-dir ~/.trailgate
# open consentUrl, approve, then:
node bundle/trailgate.mjs redeem   https://localhost:3443 --request-id <id> --state-dir ~/.trailgate
node bundle/trailgate.mjs fetch    https://localhost:3443 /api/cart --state-dir ~/.trailgate
```

## Step 6: a custom host (SDK path)

`apps/claude-host` is the reference: it loads the same tools, gates
mutating calls behind a terminal `y/N` prompt, and feeds the tool
surface to the Anthropic messages API. Copy it for any model — the only
model-specific code is the message loop; tools come from
`createTrailGateTools(client, { beforeAction })`.

## Two laptops

`docs/INSTALL_AND_DEPLOY.md` has the full recipe: `SHOP_HOST=0.0.0.0` +
`SHOP_CERT_SAN` on machine A, copy `ca.crt` + the `.mjs` file to machine
B, point the MCP config there at the bundle.

## Troubleshooting

- **`tg.discovery.signature_invalid` / key_changed**: the shop rotated
  its dev signing keys; delete `discovery.json` in the state dir and
  re-discover.
- **`tg.request.resource_denied`**: the grant lacks the resource; request
  again with the `cart:{user}`/`wallet:{user}` templates (the CLI adds
  them automatically from the action catalog).
- **consent URL `404`/login loop**: sign in on the shop first; consent
  requires an authenticated site session.
- **tools missing in your client**: restart the client after editing
  config; verify the server alone with
  `printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n' | node bundle/trailgate-mcp.mjs`.
