# Blogarithm

A second TrailGate demonstration application: a blogging and publishing
platform where an AI agent can draft, publish, and manage content, but only
inside the permissions the user explicitly grants.

Where ExampleShop exercises delegated commerce, Blogarithm exercises
delegated content: drafting is not publishing, comment settings are not
deletion, and revocation cuts access off.

## Run

```bash
corepack pnpm install
corepack pnpm start      # http://127.0.0.1:3401
```

Demo account: `demo@blogarithm.dev` / `demo-password-1` (seeded on first run).

## Agent demo

With the app running:

```bash
corepack pnpm demo           # scripted end-to-end scenario
corepack pnpm demo --manual  # pause for browser consent at each grant
```

## Test

```bash
corepack pnpm test
```

## Layout

| Path | Role |
| --- | --- |
| `src/app.ts` | Route wiring: public blog, auth, workspace, consent, protocol endpoints |
| `src/api/routes.ts` | Agent JSON API; every route runs `tg.protect` |
| `src/tg/` | TrailGate vocabulary, Server SDK wiring, SQLite port stores |
| `src/domain/` | posts, comments, notifications, users (auth, sessions) |
| `src/db/` | `node:sqlite` schema, migrations, seed data |
| `src/ui/` | Server-rendered pages, layout, markdown renderer |
| `src/dev/` | `demo-agent.ts` (scripted demo), `loopback.ts` (dev transport) |
| `public/` | stylesheet served at `/static/` |

Docs: `docs/BLOGARITHM_*.md` in this directory.
