# Tests

Cross-component test suites. Unit tests live inside packages (`src/*.test.ts`); this tree holds tests that span components.

| Directory | Suite |
| --- | --- |
| `integration/` | End-to-end flows across SDKs and the reference app. Phase 3. |
| `security/` | Security property tests mapped to `docs/threat-model.md`. Phase 4. |
| `adversarial/` | Hostile-client and hostile-environment cases. Phase 4. |
| `interoperability/` | Conformance checks against independent implementations. Phase 4. |

These directories are intentionally empty until their phase. The cross-component coverage that already exists lives with the components it exercises:

- `apps/example-shop/src/milestone-a.test.ts`: live subprocess server, real SQLite file, real SDKs.
- `apps/example-shop/src/milestone-b.test.ts`: policy lifecycle integration suite.
- `apps/example-shop/src/tg/concurrency.test.ts`: cross-process ledger atomicity proof.
- `packages/conformance/src/port-contracts.ts`: reusable port-contract suite, run in `packages/conformance/src/port-contracts.test.ts` (in-memory stores) and `apps/example-shop/src/tg/conformance.test.ts` (SQLite stores).
- `spec/vectors/vectors.json`: shared conformance vectors executed by `packages/test-fixtures`.

When a suite gains a runner it lands here per the tooling ADR (`docs/decisions/0001`).
