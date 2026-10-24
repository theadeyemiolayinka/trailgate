# Blogarithm implementation

Second TrailGate demo app: a blogging platform demonstrating delegated
authority over content creation, publication, and moderation.

## Integration model

Blogarithm uses the real protocol packages, same as ExampleShop:

- `@trailgate/server` (`createTrailGateServer`) owns discovery, grant
  intake, consent state, redemption, status, revocation, request
  verification, idempotency, replay, receipts, and audit.
- `@trailgate/core` owns signature and grant verification internals.
- `@trailgate/agent` powers the demo client.
- The app supplies: the permission vocabulary, resource selector types,
  durable SQLite port stores (`src/tg/stores.ts`), subject mapping,
  resource ownership (`post:`/`comment:` -> `author_id`), and a site
  policy that denies grants whose subject no longer resolves to a user.

Nothing in the app reimplements verification, grant formats, or crypto.

## Permissions vocabulary (`src/tg/vocabulary.ts`)

| Permission | Meaning | Risk class |
| --- | --- | --- |
| `tg.posts.read` | read own posts incl. drafts | read |
| `tg.posts.create` | create drafts | write |
| `tg.posts.update` | edit own posts | write |
| `tg.posts.publish` | publish/unpublish own posts | publish |
| `tg.posts.delete` | delete/restore own posts | delete |
| `tg.posts.settings` | change post settings (comments on/off) | write |
| `tg.comments.read` | read comments on own posts | read |
| `tg.comments.delete` | delete comments on own posts | delete |
| `tg.notifications.read` | read own notifications | read |
| `tg.notifications.write` | mark notifications read | write |
| `tg.profile.read` | read own author profile | read |

Resource selectors: `post:<id>`, `comment:<id>`, plus the `post:{user}`
consent-time template which binds to the subject's existing posts.

## Agent API (`src/api/routes.ts`)

Every route runs `tg.protect`; the spec-11 pipeline executes before any
handler. Routes operate on `ctx.subject`'s own rows only.

`GET /api/profile`, `GET /api/posts` (filters `status`, `q`),
`GET /api/posts/:id`, `POST /api/posts` (create draft),
`PATCH /api/posts/:id`, `POST /api/posts/:id/publish`,
`POST /api/posts/:id/unpublish`, `DELETE /api/posts/:id`,
`POST /api/posts/:id/restore`, `POST /api/posts/:id/settings`,
`GET /api/comments`, `GET /api/posts/:id/comments`,
`DELETE /api/comments/:id`, `GET /api/notifications`,
`POST /api/notifications/:id/read` (`all` for bulk).

## Enforcement boundaries demonstrated

- Draft vs publish: `tg.posts.create` does not imply `tg.posts.publish`.
- Settings vs delete: `tg.posts.settings` does not imply `tg.posts.delete`.
- Ownership: selectors resolve through `resourceOwners` to `author_id`;
  a grant for user A's posts returns `tg.request.resource_denied` for
  user B's post even when the selector matches the grant scope.
- Revocation: checked per request; denied calls return `tg.grant.revoked`
  plus a signed denial receipt.
- Comments closed: `comments_enabled` is enforced server-side; the public
  form rejects with 422.

## Storage

`node:sqlite` (WAL) at `data/blogarithm.db`. Migrations in
`src/db/database.ts`: domain tables (users, sessions, posts, comments,
notifications) plus the shared `tg_*` protocol tables used by
`src/tg/stores.ts`. All port stores honor the SDK atomicity contracts
(CAS transitions, atomic nonce/idempotency claims).

## Known gaps

- Editor is markdown + preview, not a rich-text component.
- `post:{user}` binds at consent time; posts created later are not in
  scope (re-consent needed — matches spec semantics).
- `approval_threshold` constraint type is wired (approvals store) but no
  route currently requires it.
- TLS listener needs dev certs (`dev-certs/`); the demo uses the loopback
  transport which exercises the identical signed-URI path over HTTP.
