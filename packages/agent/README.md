# @trailgate/agent

Client SDK for agents using TrailGate: site discovery, grant status, key management, consent initiation, signed requests, and receipt verification.

Status: implemented against draft 0.1 (`spec/protocol.md`). Experimental; not production ready.

## Quick start

```ts
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';

const client = createAgentClient();
client.useKey(SoftwareKeyProvider.generate());

const site = await client.discover('https://shop.example.com');
const session = await client.requestGrant(site, {
  permissions: ['tg.order.create'],
  constraints: [{ type: 'max_amount', params: { amount: 5000, currency: 'USD' } }],
});

// Direct the user to session.consentUrl on the site's own surface.
// Polling mode (no redirect_uri registered):
const grant = await client.awaitApproval(session.requestId);

const res = await client.fetchProtected(site, {
  method: 'POST',
  target: '/api/orders',
  body: JSON.stringify({ item: 'book' }),
});
res.error?.code; // tg.* wire code when the site denied
res.receipt;     // verified receipt bound to the exact signed request
```

Redirect mode: pass `redirectUri` and `state` to `requestGrant`, hand the callback URL to `client.handleConsentCallback(requestId, url)`, then `client.redeemGrant(requestId)`.

## Capability discovery and intent mapping

`client.listActions(site)` returns the site's advertised action catalog (spec section 5.2): each entry carries `id`, `method`, `path`, `permission`, `description`, `mutates`, and `spend`, annotated with whether a stored grant covers it. An agent runtime maps user intent ("check my cart") to an action by its `description`, then requests the listed permission when coverage is missing. Discovery results cache per origin for the document's `max-age` (capped at 24 h); `client.discover(url, { refresh: true })` forces a refetch, and `FileDiscoveryCache` persists the cache across processes.

## Per-request approvals

A grant carrying `approval_threshold` can deny a high-value request with `tg.constraint.approval_required`. The denial's `error.detail` then carries `approval_url`, the site's human decision surface: hand it to the user, and after they approve on the site, retry the identical request. An approval executes exactly once, binds to the exact operation, and is subject-only (spec section 12.4).

## Key custody

`AgentSigner` is the custody boundary; it never exports private key material. `SoftwareKeyProvider` (process memory) and `FileKeyProvider` (0600 file) are development-grade. Production agents should inject an OS- or hardware-backed implementation of the same interface. See `KEYS.md`.

## What it does

- Discovery per spec section 5: HTTPS only, no redirects, schema and same-origin validation, `critical` handling, version negotiation, `Cache-Control`-aware caching capped at 24 h.
- Consent and lifecycle per section 10: S256 grant requests, redirect or polling completion, single-use redemption with client-side grant signature verification.
- Protected requests per section 11: RFC 9421 profile headers, `Content-Digest`, `Idempotency-Key`, origin pinning (requests cannot leave the discovered site origin).
- Receipts per section 14: verified against discovery keys and bound to the exact sent signature base; failures are reported, not thrown.
- Discovery per section 5.5: `trailgate-discovery-signature` headers are verified when present, and the client pins `signing_keys` across fetches via the discovery cache. An unendorsed key change fails with `tg.discovery.key_changed`; legitimate rotation is endorsed by a signature under the outgoing key. `allowKeyRotation` on the client opts out.
- Error envelopes per section 16: surfaced as typed data (`ProtectedResponse.error`, `TrailGateError.code`); branch on `code`, never `message`.

## What it does not do

- It never exposes private keys or `code_verifier` values to callers. `AgentSigner` has no export method; see `src/keys.ts` for the boundary.
- It does not fetch arbitrary URLs. Every protected request is pinned to the discovered origin.
- It does not decide authorization. Local expiry and permission checks inform grant selection; the site's enforcement is authoritative.

## Layout

| File | Contents |
| --- | --- |
| `src/client.ts` | `createAgentClient` facade: pending consent sessions, discovery cache, grant selection, `AgentError`. |
| `src/discovery.ts` | `discoverSite`, `SiteContext`, `resolveSiteUrl`, `siteKeyResolver`, cache rules. |
| `src/grants.ts` | Grant request body, submission, redemption, status lookup, consent polling. |
| `src/consent.ts` | Redirect callback validation (`request_id`, `state`, exact `redirect_uri`). |
| `src/keys.ts` | `AgentSigner` port and `SoftwareKeyProvider` reference implementation. |
| `src/store.ts` | `StoredGrantRecord`, `GrantStore` port, `InMemoryGrantStore`, `selectGrant`. |
| `src/request.ts` | Signature-profile header construction and protected request execution. |
| `src/receipts.ts` | Receipt header extraction and verification (provisional transport). |
| `src/transport.ts` | `HttpTransport` port and `fetch`-based default (never follows redirects). |
| `src/errors.ts` | Error envelope parsing and typed error mapping. |

See `DESIGN.md` for the API outline, provisional surfaces, and open contract questions. `src/host.test.ts` exercises the full lifecycle end to end against `@trailgate/server` without ExampleShop.
