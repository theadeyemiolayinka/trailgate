# @trailgate/agent

Client SDK for agents using TrailGate: site discovery, grant status, key management, consent initiation, signed requests, and receipt verification.

Owner: D2 (see `internal/TEAM.md`).

Status: Phase 2 foundation against draft 0.1 (`spec/protocol.md`). Experimental; not production ready.

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

## What it does

- Discovery per spec section 5: HTTPS only, no redirects, schema and same-origin validation, `critical` handling, version negotiation, `Cache-Control`-aware caching capped at 24 h.
- Consent and lifecycle per section 10: S256 grant requests, redirect or polling completion, single-use redemption with client-side grant signature verification.
- Protected requests per section 11: RFC 9421 profile headers, `Content-Digest`, `Idempotency-Key`, origin pinning (requests cannot leave the discovered site origin).
- Receipts per section 14: verified against discovery keys and bound to the exact sent signature base; failures are reported, not thrown.
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
