# @trailgate/server

Reusable SDK for websites implementing TrailGate: discovery endpoint, consent and grant endpoints, grant lifecycle (issue, revoke, expire), policy integration, audit hooks, and authoritative constraint enforcement.

Owner: D1 (see `internal/TEAM.md`).

Status: Phase 2 foundation against draft 0.1 (`spec/protocol.md`). Experimental; not production ready.

## What it does

The SDK composes the verification pipeline in `@trailgate/core` with the server-side flows the spec assigns to the website:

- `GET /.well-known/trailgate` discovery document, self-validated against the schema and same-origin rules.
- `POST grant_request`, consent decision support, `POST grant_redemption`, `GET grant_status`, `POST grant_revocation` (provisional).
- `protect(route, handler)`: the spec section 11 enforcement pipeline around a host handler, including signed receipts for allowed and denied requests, audit events, spending reservations, and idempotent replays.

## What it does not do

- It never replaces or inspects the host's authentication. Consent and revocation happen on the site's own surfaces; the host passes its authenticated user identifier in.
- It never bypasses the site's authorization or business rules. A configured `policy` callback runs after every protocol check, and host handlers keep their own logic.
- It is not a web framework. Handlers consume and produce framework-neutral `HostRequest`/`HostResponse` values; the host adapts Express, Fastify, Hono, or anything else.

## Layout

| File | Contents |
| --- | --- |
| `src/server.ts` | `createTrailGateServer` factory and the `TrailGateServer` surface. |
| `src/config.ts` | `TrailGateServerOptions`, defaults, and config validation. |
| `src/types.ts` | `HostRequest`/`HostResponse`, consent view, route protection, handler types. |
| `src/ports.ts` | Storage, ledger, idempotency, audit, and authorization port interfaces. |
| `src/memory.ts` | In-memory reference implementations of every port (not for production). |
| `src/lifecycle.ts` | Grant request intake, consent decisions, redemption, status, revocation. |
| `src/discovery.ts` | Discovery document builder. |
| `src/enforcement.ts` | `protect` pipeline: verification, reservations, idempotency, receipts, audit. |
| `src/signing.ts` | Site signing keys, grant JWT signing, receipt issuance. |
| `src/ids.ts` | Opaque identifier generation (128-bit). |

See `INTEGRATION.md` for the setup guide and the list of provisional surfaces.
