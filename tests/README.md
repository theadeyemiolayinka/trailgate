# Tests

Cross-component test suites. Unit tests live inside packages (`src/*.test.ts`); this tree holds tests that span components.

| Directory | Suite |
| --- | --- |
| `integration/` | End-to-end flows across SDKs and the reference app. Phase 3. |
| `security/` | Security property tests mapped to `docs/threat-model.md`. Phase 4. |
| `adversarial/` | Hostile-client and hostile-environment cases. Phase 4. |
| `interoperability/` | Conformance checks against independent implementations. Phase 4. |

These directories are intentionally empty until their phase. Each suite gains a runner configuration when its first real test lands, per the tooling ADR (`docs/decisions/0001`).
