# Release review: draft 0.1 conformance and adversarial gate

Milestone C review of the actual repository: the normative specification
(`spec/protocol.md`, `spec/errors.md`, `spec/schemas/`, `spec/vectors/`), the threat model,
every package's implementation, and every test that claims to prove a security property.

Reviewer stance: a normative requirement counts as satisfied only where code implements it
and tests demonstrate it. A passing happy-path demo is not evidence. Tests that assert a
denial without checking the intended security condition caused it do not count.

This is not a certification, formal verification, or a claim of production readiness.

## Verification results at this commit

| Command | Result |
| --- | --- |
| `pnpm typecheck` | Clean, all 8 packages. |
| `pnpm build` | Clean, all packages. |
| `pnpm test` | 446 tests, 0 failures (core 137, server 76, agent 102, conformance 11, mcp-adapter 10, agent-cli 11, test-fixtures 45, example-shop 54). |
| `pnpm check` | 0 errors. 1 warning and 150 info diagnostics, all pre-existing style rules. |

The example-shop count includes the live Milestone A test (spawned HTTP server, real
SQLite file, real SDKs), the Milestone B suite (13 integration tests), the port-contract
conformance suite on the SQLite stores, and the cross-process ledger race test.

## Requirement-to-test matrix

Spec sections refer to `spec/protocol.md`. "Vectors" means the shared fixtures in
`spec/vectors/vectors.json` executed by `packages/test-fixtures` and the conformance
runner.

| Requirement (spec) | Evidence | Status |
| --- | --- | --- |
| Discovery document shape, same-origin endpoints, version list (5) | `packages/agent/src/discovery.test.ts` (malformed docs, cross-origin endpoint rejection, cache staleness), vectors | Covered |
| Discovery signature verification and key-continuity pinning (5.5) | `packages/agent/src/discovery.test.ts` signature/rotation cases, `packages/server/src/discovery.test.ts` emission cases | Covered |
| Unsupported protocol version fails closed, no guessing (5, errors) | `packages/agent/src/flow.test.ts`, vectors | Covered |
| Action catalog optional, generated from enforcement declarations (5.2) | `packages/server` action tests, `milestone-a.test.ts` catalog assertions | Covered |
| Grant request schema, unknown permission, unknown constraint type at intake (7, 9.2) | `milestone-b.test.ts` intake test, `enforcement.test.ts`, vectors | Covered |
| Human consent required; unauthenticated approval impossible (10.3) | `milestone-b.test.ts` consent test, `lifecycle.test.ts` | Covered |
| PKCE binding at redemption; single-use redemption CAS (10.4) | `lifecycle.test.ts`, port-contract suite (in-memory + SQLite) | Covered |
| Key binding: cnf.jkt, wrong-key denial (8, 11) | `milestone-a.test.ts` wrong-key case, `enforcement.test.ts` | Covered |
| Request proof: method, target, Content-Digest, exp, nonce bound by signature (11.2) | `enforcement.test.ts` tampered-body digest mismatch, missing-header denial, `signature.test.ts`, vectors | Covered |
| Replay: nonce single-use per grant (11.4) | `enforcement.test.ts` replay case, port-contract nonce case | Covered |
| Idempotency: replay returns stored outcome, conflict on different op, in-flight on pending (11.4) | `enforcement.test.ts` three cases, `milestone-b.test.ts`, port-contract idempotency cases | Covered |
| Permission semantics: unadvertised permission denied, escalation impossible (8) | `enforcement.test.ts`, `milestone-b.test.ts` | Covered |
| Cross-user resource isolation via ownership resolver (8, 11 stage 11) | `enforcement.test.ts`, `milestone-b.test.ts` cross-user order | Covered |
| Constraints conjunctive; unknown type denies with `tg.constraint.unknown_type` (9.2) | `constraints.test.ts`, `enforcement.test.ts` | Covered |
| `max_amount` (9.2) | `constraints.test.ts`, `enforcement.test.ts`, `milestone-b.test.ts` currency case | Covered |
| `cumulative_budget` via atomic reserve/consume/release (9.2, 12) | `enforcement.test.ts`, `milestone-b.test.ts` exhaustion + concurrent cases, port-contract ledger cases | Covered |
| `spend_window` windowed sums; refunds offset in-window (9.2, 12) | `enforcement.test.ts`, `milestone-b.test.ts` refund-in-window case, port-contract | Covered |
| `rate_limit` rolling window (9.2) | `milestone-b.test.ts` rate-limit + audit test, `constraints.test.ts`, port-contract | Covered |
| `valid_window` (9.2) | `constraints.test.ts` | Covered |
| `approval_threshold` lifecycle: deny with surface, subject-only decide, single-use consume, restore on failure, expiry (9.2, 12.4) | `enforcement.test.ts` four lifecycle tests, `milestone-b.test.ts` two end-to-end tests through the real web surface, port-contract approval cases | Covered |
| Expiry and revocation take effect at the next request (13) | `enforcement.test.ts` expired grant, `milestone-b.test.ts` revocation mid-grant and revocation-over-approval | Covered |
| Signed receipts reflect the actual decision; verifiable against site keys (14) | `enforcement.test.ts` receipt verify, `receipts.test.ts` (agent), `milestone-a.test.ts` persisted receipt | Covered |
| Audit events for the full lifecycle (15) | `milestone-a.test.ts` and `milestone-b.test.ts` read `tg_audit` rows directly; audit event union in core types | Covered |
| Store failure fails closed (11.3, 15) | `enforcement.test.ts` dead-audit-sink denial; `constraints.test.ts` missing-ledger and missing-approvals fail closed | Covered |
| Agent cannot leave the discovered origin or widen server-side limits | `request.test.ts` cross-origin target rejection; `milestone-b` constraints are server-side only | Covered |
| Consent callback: exact registered `redirect_uri`, `request_id`, `state` (10.3) | `packages/agent/src/consent.ts` validator + `consent.test.ts`; `redirect_uri` intake is schema-bound to `https://` | Covered |
| Receipt tampering detection | `verifyReceipt` cases in `packages/core` receipt tests and vectors | Covered |
| Unsupported policy types documented, never silently ignored (9.2) | Normative paragraph in 9.2; intake rejects unregistered types (`milestone-b.test.ts`) | Covered |

## Adversarial findings this milestone

Severity scale: Critical (credential/fund theft or trust-model bypass), High
(authorization bypass or exploitable fail-closed violation), Medium (security-relevant
correctness), Low (conformance defect, limited impact).

### Fixed

- **Open redirect via `next` query parameter (Medium, app-level).** `POST /login` honored
  an unvalidated `?next=` from the URL when the form field was absent, allowing a crafted
  login link to redirect to an external origin after authentication. `nextPath` now
  validates both sources to local paths only. Application surface, not protocol code.
- **Concurrent process open could fail with `database is locked` (Medium, availability).**
  `PRAGMA busy_timeout` ran after `PRAGMA journal_mode = WAL`; the WAL switch needs a lock
  that could not wait on the default zero timeout. Reordered. Surfaced by the new
  cross-process race test flaking once in five runs.
- **`approval_threshold` was specified as unsupported (spec gap, now closed).** It is now
  a registered 0.1 constraint with the full lifecycle in section 12.4: typed denial with
  `tg.constraint.approval_required` plus `approval_url`, subject-bound decide, atomic
  single-use consume (`approved -> used`), restore-on-failure, TTL expiry, and audit
  events. Implemented across core, server SDK, both store families, ExampleShop web
  surface, spec, errors registry, and port-contract conformance.

### Verified non-findings

- Two concurrent requests carrying the same operation cannot both spend one approval:
  `consumeApproved` flips state atomically inside `BEGIN IMMEDIATE`; tested.
- An approval cannot be swapped to a different operation: the record binds to the
  operation digest (method, target, content digest, grant jti); tested.
- Cross-process overspend: four OS processes racing `reserve` over one SQLite file
  produced exactly one winner and three `tg.constraint.violated`; tested repeatedly.
- A dead audit sink denies the request rather than executing unrecorded; tested.
- A failed or denied handler restores a consumed approval to `approved`; tested.

### Known limits carried into release (documented, not hidden)

- `node:sqlite` is the reference store. Production stores must run
  `runPortContractSuite` against their own implementation before deployment; atomicity
  guarantees depend on the store honoring transaction semantics.
- Approval TTL is a site-configured value (`requestApprovalTtlSeconds`, default 600s);
  expiry is enforced at decide and consume time. Expired `approved` records cannot be
  consumed.
- Receipt `amounts` and `grant_status` remain informational; the ledger is authoritative.
- Discovery documents are not yet signed (open spec issue); a hostile network could swap
  a document off-path. Same-origin pinning limits, not eliminates, this risk.
- Edge defenses (WAF, connection limits) and production key custody remain
  operator-supplied, per `docs/security-guarantees.md`.

## Release decision

**Ship draft 0.1 as an experimental reference implementation.** All normative requirements
in the matrix are covered by tests that demonstrate the intended security condition, the
port-contract suite passes on both store families, the cross-process overspend proof
holds, and no confirmed critical or high-severity defect remains open. The known limits
above are documented at the points of use rather than implied away.
