# @trailgate/core

Shared protocol foundations for TrailGate draft 0.1: typed errors, types, dependency ports, schema validation, discovery validation, grant parsing and verification, permission and constraint evaluation, RFC 9421 request-signature verification, request binding, and receipt verification.

Owner: D0 (see `internal/TEAM.md`).

Rules: `core` must not depend on any other TrailGate package, must not perform network access, and must not contain application-specific storage or ExampleShop logic.

## Status

Implemented against `spec/protocol.md` draft 0.1. Experimental. Not production-ready, not certified, not formally verified.

## Public API surface

Everything is exported from `src/index.ts`. The main entry points:

- `verifyProtectedRequest(req, deps)` — the full section 11.3 verification pipeline. `req` is `{ method, url, headers, body? }`; `deps` injects all external state (see ports below). Returns `{ grant, requestDigest, signatureBase, idempotentReplay, context }` or throws a `TrailGateError` with a stable `tg.*` code.
- `verifyGrant(token, deps)` / `parseGrant(token)` — grant JWS parsing and verification (JOSE `alg` allowlist `EdDSA`/`ES256`, `typ` check, `cnf.jkt`, issuer/audience/expiry claims, unknown `critical` members fail closed).
- `validateDiscoveryDocument(doc, options)` / `parseDiscoveryDocument(text, options)` — schema, same-origin endpoint rules, `critical` handling, protocol-version negotiation.
- `evaluateConstraints(constraints, ctx)` — conjunctive evaluation of the four registered constraint types; unknown types yield `tg.constraint.unknown_type`, unavailable evaluators yield `tg.internal.unavailable`.
- `assertPermissionGranted` / `assertRequestedPermissionsKnown` — exact-match permission checks.
- `buildReceiptPayload` / `signReceipt` / `verifyReceipt` — receipt construction, signing, and verification including optional `expectedRequestDigest` binding.
- `signRequest(req, options)` — signs a request under the section 11.2 profile (fixed covered components, `tag: "trailgate"`). Provided for agents, fixtures, and conformance use.
- `schemaRegistry()` — the JSON Schema 2020-12 validators loaded from `spec/schemas/` (`SCHEMA_IDS`).
- `Codes` and `TrailGateError` — the stable error-code registry; `toErrorResponse(err)` produces the `{ "error": { code, message, detail? } }` envelope.

### Ports (injected dependencies)

External state is always injected; core never does I/O:

| Interface | Purpose |
| --- | --- |
| `Clock` | Current time (`systemClock`, `fixedClock(at)` provided) |
| `KeyResolver` | `jkt`/`kid` to public JWK, for site keys and agent keys |
| `NonceStore` | Atomic `claim(grantId, nonce, ttl)`; `false` means replay |
| `RevocationChecker` | `isRevoked(grantId)`; failures must deny |
| `Ledger` | Consumed/reserved minor units for `cumulative_budget` |
| `RateLimiter` | Windowed counts for `rate_limit` |
| `ResourceOwnerResolver` | Selector to owning subject |
| `IdempotencyStore` | Stored operation digests for `Idempotency-Key` dedupe |
| `SitePolicy` | Final site-side authorization hook (stage 13) |

`verifyProtectedRequest` requires `resolveSiteKey`, `resolveAgentKey`, `revocation`, and `nonceStore` unconditionally; the rest are optional and only consulted when the corresponding check is configured (`requiredPermission`, `touchedResource`, `requestAmount`, `idempotency`, `policy`, `permissionVocabulary`, `knownCriticalFields`).

## Conventions

- All relative imports use `.ts` specifiers; `tsconfig` rewrites them to `.js` on emit (`rewriteRelativeImportExtensions`). Tests run directly on sources via `node --test` type stripping.
- Errors: throw `TrailGateError` with a `Codes.*` value, never a bare `Error`, for any protocol decision. Do not put private keys, secrets, or internal paths in `message`/`detail`.
- Anything security-critical that cannot be verified must throw; never silently skip a check.

## Compatibility policy

- The package tracks `spec/protocol.md`. Its version and `PROTOCOL_VERSION` move together; `SUPPORTED_PROTOCOL_VERSIONS` lists every accepted `tg.version`/`protocol_versions` value.
- Within a protocol version, additive changes only: new exports, new optional dependency hooks, new error codes (append-only per `spec/errors.md`).
- Breaking changes (renamed exports, changed verification semantics, removed codes) require a spec version bump through the ADR 0002 contract process.
- The error `code` strings are the stable contract; `message` text is not.

## Known limitations

- `schemaRegistry()` loads `spec/schemas/*.schema.json` from the repository layout at import time (`../../../spec/schemas/` relative to the module). It works from `src/` and `dist/` because both sit one level under `packages/core/`; embedding core outside this layout requires `createSchemaRegistry(customSchemas)`.
- Structured-fields parsing covers the subset needed by the section 11.2 profile (strings, integers, booleans, byte sequences, inner lists, parameters). It is not a general RFC 8941 implementation; unsupported shapes fail as `tg.request.malformed` or `tg.request.signature_invalid`.
- `verifyProtectedRequest` verifies the request; reservation/consume/refund ledger operations are the server's job (section 12) and live in the server SDK.
- The `IdempotencyStore` comparison digest is an operation digest (method, target URI, `Content-Digest`, grant `jti`), per the clarified section 11.4 wording.
- Only `ed25519` is exercised end-to-end by vectors; `ecdsa-p256-sha256` is implemented and unit-tested but has no external interoperability vectors yet.
