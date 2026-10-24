# Tests

Cross-component test suites. Unit tests live inside packages (`src/*.test.ts`); this tree holds tests that span components.

| Directory | Suite |
| --- | --- |
| `integration/` | End-to-end flows across SDKs and the reference app. |
| `security/` | Security property tests mapped to `docs/threat-model.md`. |
| `adversarial/` | Hostile-client and hostile-environment cases. |
| `interoperability/` | Conformance checks against independent implementations. |

These directories are reserved for standalone runners. The cross-component coverage that already exists lives with the components it exercises:

- `apps/example-shop/src/live-e2e.test.ts`: live subprocess server, real SQLite file, real SDKs.
- `apps/example-shop/src/policy-lifecycle.test.ts`: policy lifecycle integration suite.
- `apps/example-shop/src/tg/concurrency.test.ts`: cross-process ledger atomicity proof.
- `packages/conformance/src/port-contracts.ts`: reusable port-contract suite, run in `packages/conformance/src/port-contracts.test.ts` (in-memory stores) and `apps/example-shop/src/tg/conformance.test.ts` (SQLite stores).
- `spec/vectors/vectors.json`: shared conformance vectors executed by `packages/test-fixtures`.

When a suite gains a runner it lands here per the tooling ADR (`docs/decisions/0001`).
