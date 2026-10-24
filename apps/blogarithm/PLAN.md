# Blogarithm implementation plan

Second TrailGate demo application: a blogging and publishing platform.

- Location: `apps/blogarithm/`. Node + TypeScript, `node:sqlite` (no external deps), `node:http`, server-rendered HTML + shared stylesheet. Same shape as `apps/example-shop`.
- Reuse: `db/database.ts`, `db/ids.ts`, `http/{router,forms,responses}.ts`, `tg/stores.ts` pattern adapted from example-shop; `@trailgate/server` + `@trailgate/core` for all protocol enforcement.
- Domain: users, posts (draft/published/deleted lifecycle), comments (+ per-post comments_enabled), notifications, sessions, seed data.
- Permissions vocabulary: `tg.posts.read`, `tg.posts.create`, `tg.posts.update`, `tg.posts.publish`, `tg.posts.delete`, `tg.posts.settings`, `tg.comments.read`, `tg.comments.delete`, `tg.notifications.read`, `tg.notifications.write`, `tg.activity.read`.
- Protected actions under `POST /tg/action/<name>` via `tg.protect`: posts.list/get/create_draft/update/publish/unpublish/delete, posts.comments.enable/disable, comments.list/delete, notifications.list/mark_read, activity.recent.
- Consent page at `paths.consent` rendered in product design; grant management at `/workspace/access` (listBySubject, revoke).
- Demo agent: `src/dev/demo-agent.ts` doing real discovery -> grant request -> signed calls.
- Docs: `docs/` per assignment renamed to BLOGARITHM_*.md.

Progress notes for continuation: ports.ts gained `listBySubject` on GrantRegistry (added to interface + memory impl). Server SDK API now includes maxGrantSeconds, defaultGrantSeconds, approvals store, bindSubjectResources, resourcePolicy, refineScope, capabilities, policy.authorize. Constraint types in core: cumulative_budget, rate_limit, valid_window, spend_window, approval_threshold.
