# Agent SDK design (draft 0.1 foundation)

Owner: D2. Status: Phase 2 foundation against `spec/protocol.md` draft 0.1. Experimental; not production ready.

This document records the API outline, the provisional surfaces, and the contract questions that need D0.

## Model boundary

The SDK separates what a model runtime may see from what the protocol needs:

- Runtime-visible: `SiteContext`, `ConsentSession`, `StoredGrantRecord`, `GrantStatusResponse`, `ProtectedResponse`, `ReceiptOutcome`.
- Never surfaced: private key material (`AgentSigner` has no export method), `code_verifier` values (held inside the client between `requestGrant` and `redeemGrant`).

`AgentError` (kind `no_grant | no_key | unknown_request | ambiguous`) covers local failures before any protocol exchange. Wire failures are `TrailGateError` with a `tg.*` code from `spec/errors.md`. Callers branch on `code`, never `message`.

## API outline

`createAgentClient(options?) -> AgentClient` composes everything below. The lower-level functions are also exported for adapters that need finer control.

| Surface | Entry point | Spec |
| --- | --- | --- |
| Discovery | `discoverSite(target, opts)`, `client.discover` | Section 5: HTTPS origin normalization, no redirects (transport contract + 3xx rejection), schema + same-origin validation via core, version negotiation, `critical` handling, `Cache-Control`-aware caching capped at 24 h |
| Capability inspection | `siteCapabilities(ctx)`, `ctx.document` | Sections 5.2, 4 |
| Grant request | `client.requestGrant(site, scope)`, `buildGrantRequestBody`, `submitGrantRequest` | Section 10.2; S256 verifier generated per request, challenge in body, verifier retained internally |
| Consent session | `ConsentSession` (`request_id`, `consent_url`, `expires_at`) | Sections 10.2-10.3; `consent_url` origin is validated against the site origin |
| Callback validation | `validateConsentCallback(url, expected)`, `client.handleConsentCallback` | Section 10.3: exact `redirect_uri` match after removing the two appended params, `request_id` and `state` equality |
| Status lookup | `fetchGrantStatus`, `client.grantStatus` | Section 10.5; treated as informational/untrusted |
| Polling | `awaitConsentDecision`, `client.awaitApproval` | Sections 10.5, 10.1 terminal states |
| Redemption | `redeemGrantRequest`, `client.redeemGrant` | Section 10.4; grant signature verified via `verifyGrant`, `cnf.jkt` must equal the requesting key, then stored |
| Key operations | `AgentSigner` port, `SoftwareKeyProvider` | Sections 6.2, 11.2; `jkt` via RFC 7638 thumbprint; no export method on the interface |
| Grant metadata storage | `GrantStore` port, `InMemoryGrantStore`, `selectGrant` | Local concern; records re-validated through `parseGrant` on ingest |
| Signed requests | `buildProtectedRequestHeaders`, `executeProtectedRequest`, `client.fetchProtected` | Section 11: fixed covered components, `tag: "trailgate"`, `Content-Digest`, `Idempotency-Key`, window <= 300 s |
| Origin pinning | `resolveSiteUrl` | Protected traffic cannot leave the discovered origin; the SDK is not an arbitrary fetch tool |
| Receipt verification | `verifyReceiptHeader`, `ProtectedResponse.receipt` | Section 14.3; bound to the exact sent signature base via `tg.request_digest`; failures reported, not thrown |
| Revocation | `client.revokeGrant` | Provisional; see below |
| Availability | `client.checkAccess`, `client.ensureGrant`, `checkAccessAsync` | Distinguishable verdicts: `ready`, `no_grant`, `insufficient_permission`, `expired`, `wrong_key`, `revoked` (with `confirmFresh`), `unsupported_version`. A stored token is never proof of access. |
| Key custody | `AgentKeyProvider`, `ProcessKeyProvider`, `FileKeyProvider` | See `KEYS.md`; no silent downgrade to weaker storage |
| Retry classification | `isRetryableCode` | `tg.internal.unavailable`/`tg.internal.error` only (spec/errors.md) |
| Error reporting | `parseErrorEnvelope`, `errorFromResponse`, `ProtectedResponse.error` | Section 16 + `spec/errors.md` |

## Provisional surfaces

Marked `@provisional` in code. Depend on contract questions below or on decisions outside the spec text.

1. `RECEIPT_HEADER = 'trailgate-receipt'` (receipts.ts). Draft 0.1 requires a receipt per protected request but does not name the delivery channel. Mirrors `RECEIPT_HEADER` in `@trailgate/server`. A D0 ruling changes both together.
2. `client.revokeGrant` sends `{grant_id, reason?}` to `endpoints.grant_revocation`. Draft 0.1 names the endpoint but defines no agent-initiated body or caller model; the server SDK's provisional handler expects this shape behind a `revocationAuthorizer`.
3. Status responses are treated as unsigned informational documents (spec section 10.5 lets sites choose; the server SDK sends them plainly). If the spec later profiles signed status, `fetchGrantStatus` gains a verification path.
4. `AgentSigner.sign(signatureBase)` duplicates the last step of core `signRequest` so non-exportable key providers work. Header bytes are tested identical to core's output for Ed25519.

## Questions for D0

- Q1. Receipt transport: confirm `trailgate-receipt` header (or spec a channel) in a spec errata; affects this package and `@trailgate/server` equally.
- Q2. Agent-initiated revocation: request schema and caller model for `grant_revocation`. The SDK currently mirrors D1's provisional `{grant_id, reason?}`.
- Q3. Signed `grant_status`: is a signed status profile wanted, or is plainly informational the 0.1 answer? Agents currently treat status as untrusted.
- Q4. `signRequest` signer indirection: should core grow a `signRequestWithSigner(req, {signer, ...})` so both SDKs share the profile assembly? Not blocking; the duplication is small and pinned by an equivalence test.
- Q5. Local development without TLS: spec requires HTTPS everywhere; a local dev mode (`http://localhost`) would need an explicit spec decision, not an SDK-side carve-out. Flagging early because D3's demo work will hit it.

## Security notes

- Private keys: `AgentSigner` exposes `jkt`, `publicJwk`, `algorithm`, `sign`. `SoftwareKeyProvider` holds the JWK in process memory and imports it via `fromPrivateJwk` for key-file flows; it documents that a keychain protects at rest, not against a compromised invoking process.
- Redirects: `fetchTransport` sets `redirect: 'manual'` globally; discovery additionally rejects 3xx. A signed request is never re-targeted silently.
- Error handling: `ProtectedResponse.error` is data (parsed envelope); only local failures and pre-request validation throw.
- Grants: stored grants are selected by issuer + expiry + permission; `tg.grant.expired`/`tg.grant.revoked` responses evict the record. Enforcement remains server-authoritative.
