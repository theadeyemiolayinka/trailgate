# @trailgate/agent-cli

Developer CLI for exercising TrailGate flows: discovery, consent initiation, grant inspection, signed requests, and receipt verification against a compatible site.

Owner: D2 (see `internal/TEAM.md`).

Status: Phase 2 foundation on `@trailgate/agent`. Experimental; not production ready.

## Usage

```sh
trailgate keygen                              # new signing key in ./.trailgate/keys.json
trailgate discover https://shop.example.com   # validated capabilities + actions
trailgate actions https://shop.example.com    # action catalog with grant coverage
trailgate request https://shop.example.com \
    --permission tg.order.create --wait       # consent flow, poll + redeem
trailgate fetch https://shop.example.com /api/orders --method POST
trailgate grants                              # stored grant metadata
trailgate status https://shop.example.com --grant-id <jti>
trailgate revoke https://shop.example.com --grant-id <jti>
```

`request` prints a `consent_url`; the user approves on the site's own surface. `--wait` polls `grant_status` and redeems automatically. Without `--wait`, approve then run `redeem <url> --request-id <id>`.

`--state-dir <dir>` (default `./.trailgate`) selects where `keys.json`, `pending.json`, `grants.json`, and `discovery.json` (the action-catalog cache, refreshed when stale) live.

## State files

- `keys.json` holds private JWKs in plaintext, mode 0600. A development convenience, not a keychain: it offers no protection against a process that can read the file.
- `pending.json` holds `code_verifier` values between `request` and `redeem`, mode 0600 for the same reason.
- `grants.json` holds grant metadata via `FileGrantStore`; records are re-validated on load.

Commands print JSON. Grant views never include the grant token; `keygen` prints only the public JWK.

## Layout

| File | Contents |
| --- | --- |
| `src/commands.ts` | `runCli(argv, deps)`: command dispatch with injectable client factory, stdout/stderr. |
| `src/state.ts` | Key file and pending-session persistence (0600). |
| `src/cli.ts` | Executable entry (`trailgate` bin). |
