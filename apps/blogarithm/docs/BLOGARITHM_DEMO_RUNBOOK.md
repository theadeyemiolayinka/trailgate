# Blogarithm demo runbook

Target length: about 5 minutes. The scripted agent does the protocol work;
the browser shows the product. Nothing is simulated.

## Setup (once)

```bash
corepack pnpm install
corepack pnpm -r --filter "@trailgate/*" build
cd apps/blogarithm && corepack pnpm start
```

Open `http://127.0.0.1:3401`. Sign in as `demo@blogarithm.dev` /
`demo-password-1` in the browser tab you will show.

## Script

1. Public blog (`/`): featured article, cards, tags, search. This is a real
   publishing product, not a protocol dashboard.
2. Article page (`/post/why-delegated-authority-beats-shared-credentials`):
   reading layout plus a live comment section. Optionally post a comment.
3. Workspace (`/workspace`): stats, recent posts, notifications. Open
   `Agent access`: currently no grants.
4. Terminal: `corepack pnpm demo`. Steps narrate themselves:
   - Step 1-2: discovery + an unsigned request denied
     (`tg.request.malformed`).
   - Step 3: the agent requests draft-only permissions. In `--manual`
     mode, show the consent page in the browser: specific permission list,
     "not requested" list, duration.
   - Step 4: agent creates a draft (201 + verified receipt). Show it in
     Posts.
   - Step 5: agent tries to publish. Denied:
     `tg.request.permission_denied` with a verified denial receipt. This
     is the key beat.
   - Step 6: second consent adds `tg.posts.publish` + `tg.posts.settings`
     scoped to `post:{user}`.
   - Step 7: publish succeeds; open the printed live URL.
   - Step 8-9: agent disables comments; the public comment form now
     rejects submissions (422).
   - Step 10: delete attempt denied - settings permission is not delete.
   - Step 11: user revokes the grant (real access-page revoke); the next
     call returns `tg.grant.revoked`.
5. Back in the browser, `Agent access` shows both grants, their
   permissions verbatim, expiry, and revoke state. `Notifications` shows
   the audit trail of what the agent did.

## Fallback

If the agent SDK or network fails mid-demo, fall back to
`corepack pnpm test`: the same sequence runs in-process in under 2 seconds
(`trailgate: draft permission cannot publish; second grant can;
revocation denies`) and exercises identical code paths. Show the test
file `src/app.test.ts` while it runs.

## What to say

Drafting is not publishing. Comment settings are not deletion. Revocation
is not a UI toggle. Every one of those denials came back as a signed
receipt from the same protocol pipeline that governs ExampleShop.
