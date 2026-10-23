# @trailgate/server

Reusable SDK for websites implementing TrailGate: discovery endpoint, consent and grant endpoints, grant lifecycle (issue, refresh, revoke, expire), policy integration, audit hooks, and authoritative constraint enforcement.

Owner: D1.

Status: scaffolded. Implementation begins in Phase 2 against the contracts frozen in Phase 1.

Rules: the SDK must preserve the host site's existing authentication and business logic, and must enforce constraints from authoritative server state, never from agent-supplied claims.
