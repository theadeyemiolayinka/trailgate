import type { Clock } from '@trailgate/core';
import {
  Codes,
  SUPPORTED_PROTOCOL_VERSIONS,
  systemClock,
  TrailGateError,
  verifyGrant,
} from '@trailgate/core';
import type { AccessCheck, AccessCriteria } from './access.ts';
import { checkAccessAsync } from './access.ts';
import type { ConsentCallbackExpectation } from './consent.ts';
import { validateConsentCallback } from './consent.ts';
import type { SiteContext } from './discovery.ts';
import { discoverSite, originOf, siteKeyResolver } from './discovery.ts';
import { errorFromResponse } from './errors.ts';
import type {
  ConsentSession,
  GrantRequestOptions,
  GrantStatusResponse,
  PendingGrantRequest,
  PollApprovalOptions,
} from './grants.ts';
import {
  awaitConsentDecision,
  buildGrantRequestBody,
  fetchGrantStatus,
  generateCodeVerifier,
  redeemGrantRequest,
  submitGrantRequest,
} from './grants.ts';
import type { AgentSigner } from './keys.ts';
import type { ProtectedRequestOptions, ProtectedResponse } from './request.ts';
import { executeProtectedRequest } from './request.ts';
import type { GrantStore, StoredGrantRecord } from './store.ts';
import { InMemoryGrantStore, recordFromGrantToken, selectGrant } from './store.ts';
import type { HttpTransport } from './transport.ts';
import { fetchTransport } from './transport.ts';

export interface AgentClientOptions {
  transport?: HttpTransport;
  clock?: Clock;
  grantStore?: GrantStore;
  /** Protocol versions this agent speaks. Defaults to `SUPPORTED_PROTOCOL_VERSIONS`. */
  protocolVersions?: readonly string[];
}

/**
 * Local failure raised before any protocol exchange: no usable grant, no
 * matching key, ambiguous selection, or a pending-request id the client
 * does not hold. These are SDK usage errors, not `tg.*` wire codes.
 */
export class AgentError extends Error {
  readonly kind: 'no_grant' | 'no_key' | 'unknown_request' | 'ambiguous';
  constructor(kind: AgentError['kind'], message: string) {
    super(message);
    this.name = 'AgentError';
    this.kind = kind;
  }
}

interface DiscoveryCacheEntry {
  context: SiteContext;
  /** Unix seconds after which the cached document is stale. */
  staleAt: number;
}

export interface FetchProtectedInput extends Omit<ProtectedRequestOptions, 'target'> {
  /** Path (recommended) or same-origin absolute URL. */
  target: string;
  /** Selects a stored grant by `jti`; otherwise one is selected by `permission`. */
  grantId?: string;
  /** Narrows grant selection to records carrying this permission. */
  permission?: string;
}

/**
 * The agent-facing surface. One client serves any number of sites;
 * discovery results are cached per origin (spec section 5.4). Keys are
 * registered with `useKey` and resolved by thumbprint at signing time.
 *
 * Security boundary: nothing returned by this client carries private key
 * material or `code_verifier` values. Model runtimes should receive
 * `ConsentSession`, `StoredGrantRecord`, and `ProtectedResponse` shapes.
 */
export interface AgentClient {
  /** Registers a signer for later use. Called once per key per session. */
  useKey(signer: AgentSigner): void;
  keyFor(jkt: string): AgentSigner | undefined;
  /**
   * Discovers and validates a site's TrailGate support (spec section 5).
   * Results are cached per origin; `refresh` bypasses the cache.
   */
  discover(target: string, options?: { refresh?: boolean }): Promise<SiteContext>;
  /**
   * `POST grant_request` and returns the consent session (spec section
   * 10.2). `options.key` selects the signer; required when more than one is
   * registered. The consent URL is for the user's browser, on the site origin.
   */
  requestGrant(
    target: string | SiteContext,
    scope: GrantRequestOptions,
    options?: { key?: AgentSigner },
  ): Promise<ConsentSession>;
  /**
   * Redirect mode (spec section 10.3): validates the callback the site
   * redirected to after consent. Throws `tg.request.malformed` on any
   * mismatch; call `redeemGrant` afterwards to collect the grant.
   */
  handleConsentCallback(requestId: string, callbackUrl: string): Promise<void>;
  /** `GET grant_status` (spec section 10.5). Informational, unsigned. */
  grantStatus(
    target: string | SiteContext,
    query: { requestId?: string; grantId?: string },
  ): Promise<GrantStatusResponse>;
  /**
   * Polling mode: waits for consent on `grant_status`, then redeems and
   * stores the verified grant. Throws on denial, expiry, or timeout.
   */
  awaitApproval(requestId: string, options?: PollApprovalOptions): Promise<StoredGrantRecord>;
  /**
   * `POST grant_redemption` for an approved request (spec section 10.4),
   * then verifies the grant signature, checks the `cnf.jkt` binding
   * matches the requesting key, and stores it.
   */
  redeemGrant(requestId: string): Promise<StoredGrantRecord>;
  /**
   * Returns the internal pending record for `requestId`, including the
   * `code_verifier`. Exists for trusted local tooling that persists sessions
   * between processes; never surface it to a model runtime or log.
   */
  exportPending(requestId: string): PendingGrantRequest | undefined;
  /**
   * Re-registers a pending consent session created by this SDK, for example
   * after a CLI persisted it between `request` and `redeem` invocations.
   * The record carries the `code_verifier`; treat it as secret material.
   */
  restorePending(record: PendingGrantRequest): void;
  listGrants(filter?: { issuer?: string }): Promise<StoredGrantRecord[]>;
  getGrant(jti: string): Promise<StoredGrantRecord | undefined>;
  /**
   * Checks local grant availability for the site without implying access:
   * returns a distinguishable `AccessCheck` (missing grant, insufficient
   * permission, expired, wrong key, revoked, unsupported version, or
   * `ready`). With `criteria.confirmFresh` a live `grant_status` lookup
   * also catches server-side revocation.
   */
  checkAccess(target: string | SiteContext, criteria?: AccessCriteria): Promise<AccessCheck>;
  /**
   * The product flow in one call: discover, check local access, and either
   * return the ready grant or start the consent flow and return the
   * session. Callers then await `awaitApproval` or complete the redirect.
   */
  ensureGrant(
    target: string | SiteContext,
    scope: GrantRequestOptions,
    options?: { key?: AgentSigner },
  ): Promise<
    | { status: 'ready'; grant: StoredGrantRecord }
    | { status: 'consent_required'; session: ConsentSession; reason: AccessCheck }
  >;
  /** Signs and sends a protected request (spec section 11). See `ProtectedResponse`. */
  fetchProtected(
    target: string | SiteContext,
    input: FetchProtectedInput,
  ): Promise<ProtectedResponse>;
  /**
   * `POST grant_revocation` with `{grant_id, reason?}` sent as a section 11
   * signed request carrying the grant being revoked (spec section 13 agent
   * self-revocation). The stored grant and its signing key are required;
   * the record is removed locally on success.
   */
  revokeGrant(
    target: string | SiteContext,
    grantId: string,
    options?: { reason?: string },
  ): Promise<void>;
}

export function createAgentClient(options: AgentClientOptions = {}): AgentClient {
  const transport = options.transport ?? fetchTransport();
  const clock = options.clock ?? systemClock;
  const store = options.grantStore ?? new InMemoryGrantStore();
  const versions = options.protocolVersions ?? SUPPORTED_PROTOCOL_VERSIONS;
  const signers = new Map<string, AgentSigner>();
  const pending = new Map<string, PendingGrantRequest>();
  const discoveryCache = new Map<string, DiscoveryCacheEntry>();

  async function discover(target: string, opts?: { refresh?: boolean }): Promise<SiteContext> {
    const origin = originOf(target);
    const cached = discoveryCache.get(origin);
    if (cached !== undefined && opts?.refresh !== true && cached.staleAt > clock.now()) {
      return cached.context;
    }
    const context = await discoverSite(target, {
      transport,
      clock,
      supportedProtocolVersions: versions,
    });
    discoveryCache.set(context.origin, {
      context,
      staleAt: context.fetchedAt + context.cacheMaxAgeSeconds,
    });
    return context;
  }

  async function site(target: string | SiteContext): Promise<SiteContext> {
    return typeof target === 'string' ? discover(target) : target;
  }

  function pickSigner(explicit?: AgentSigner): AgentSigner {
    if (explicit !== undefined) {
      return explicit;
    }
    if (signers.size === 1) {
      const only = [...signers.values()][0];
      if (only !== undefined) {
        return only;
      }
    }
    if (signers.size === 0) {
      throw new AgentError('no_key', 'no signing key is registered; call useKey first');
    }
    throw new AgentError('ambiguous', 'multiple keys are registered; pass options.key');
  }

  async function redeem(requestId: string): Promise<StoredGrantRecord> {
    const record = pending.get(requestId);
    if (record === undefined) {
      throw new AgentError('unknown_request', `no pending grant request ${requestId}`);
    }
    const context = await discover(record.siteOrigin);
    const { grant } = await redeemGrantRequest(context, requestId, record.codeVerifier, transport);
    const payload = await verifyGrant(grant, {
      resolveSiteKey: siteKeyResolver(context.document),
      issuer: context.issuer,
      audience: context.origin,
      now: clock.now(),
    });
    if (payload.cnf.jkt !== record.keyId) {
      throw new TrailGateError(
        Codes.GRANT_MALFORMED,
        'issued grant is bound to a different key than requested',
      );
    }
    const stored = recordFromGrantToken(grant);
    await store.put(stored);
    pending.delete(requestId);
    return stored;
  }

  return {
    useKey(signer: AgentSigner): void {
      signers.set(signer.jkt, signer);
    },

    keyFor(jkt: string): AgentSigner | undefined {
      return signers.get(jkt);
    },

    discover,

    async requestGrant(target, scope, opts): Promise<ConsentSession> {
      const context = await site(target);
      const signer = pickSigner(opts?.key);
      signers.set(signer.jkt, signer);
      const codeVerifier = generateCodeVerifier();
      const body = buildGrantRequestBody(context.protocolVersion, scope, signer, codeVerifier);
      const session = await submitGrantRequest(context, body, transport);
      const record: PendingGrantRequest = {
        ...session,
        siteOrigin: context.origin,
        keyId: signer.jkt,
        codeVerifier,
      };
      pending.set(record.requestId, record);
      return session;
    },

    async handleConsentCallback(requestId: string, callbackUrl: string): Promise<void> {
      const record = pending.get(requestId);
      if (record === undefined) {
        throw new AgentError('unknown_request', `no pending grant request ${requestId}`);
      }
      if (record.redirectUri === undefined) {
        throw new AgentError(
          'unknown_request',
          'this request did not register a redirect_uri; poll grant status instead',
        );
      }
      const expectation: ConsentCallbackExpectation = {
        requestId,
        redirectUri: record.redirectUri,
        ...(record.state !== undefined ? { state: record.state } : {}),
      };
      validateConsentCallback(callbackUrl, expectation);
    },

    grantStatus(target, query): Promise<GrantStatusResponse> {
      return site(target).then((context) => fetchGrantStatus(context, query, transport));
    },

    async awaitApproval(requestId: string, opts): Promise<StoredGrantRecord> {
      const record = pending.get(requestId);
      if (record === undefined) {
        throw new AgentError('unknown_request', `no pending grant request ${requestId}`);
      }
      const context = await discover(record.siteOrigin);
      await awaitConsentDecision(context, requestId, transport, opts);
      return redeem(requestId);
    },

    redeemGrant: redeem,

    exportPending(requestId: string): PendingGrantRequest | undefined {
      return pending.get(requestId);
    },

    restorePending(record: PendingGrantRequest): void {
      pending.set(record.requestId, record);
    },

    listGrants(filter) {
      return store.list(filter);
    },

    getGrant(jti: string) {
      return store.get(jti);
    },

    async checkAccess(target, criteria = {}): Promise<AccessCheck> {
      const context = await site(target);
      return checkAccessAsync(context, await store.list(), criteria, {
        clock,
        signers,
        clientVersions: versions,
        ...(criteria.confirmFresh === true
          ? {
              statusOf: async (grantId: string) =>
                fetchGrantStatus(context, { grantId }, transport),
            }
          : {}),
      });
    },

    async ensureGrant(target, scope, options) {
      const context = await site(target);
      const check = await this.checkAccess(context, {
        permissions: scope.permissions,
        ...(options?.key !== undefined ? { keyId: options.key.jkt } : {}),
      });
      if (check.status === 'ready') {
        return { status: 'ready', grant: check.grant };
      }
      const session = await this.requestGrant(context, scope, {
        ...(options?.key !== undefined ? { key: options.key } : {}),
      });
      return { status: 'consent_required', session, reason: check };
    },

    async fetchProtected(target, input): Promise<ProtectedResponse> {
      const context = await site(target);
      let grant: StoredGrantRecord | undefined;
      if (input.grantId !== undefined) {
        grant = await store.get(input.grantId);
        if (grant === undefined) {
          throw new AgentError('no_grant', `no stored grant ${input.grantId}`);
        }
      } else {
        grant = selectGrant(await store.list({ issuer: context.origin }), {
          issuer: context.origin,
          ...(input.permission !== undefined ? { permission: input.permission } : {}),
          clock,
        });
        if (grant === undefined) {
          throw new AgentError(
            'no_grant',
            'no usable stored grant for this site; run requestGrant first',
          );
        }
      }
      const signer = signers.get(grant.keyId);
      if (signer === undefined) {
        throw new AgentError(
          'no_key',
          `grant is bound to key ${grant.keyId}, which is not registered`,
        );
      }
      const res = await executeProtectedRequest(context, grant, signer, input, {
        transport,
        clock,
      });
      if (res.error?.code === Codes.GRANT_EXPIRED || res.error?.code === Codes.GRANT_REVOKED) {
        // spec/errors.md: the agent should discard an expired or revoked grant.
        await store.remove(grant.jti);
      }
      return res;
    },

    async revokeGrant(target, grantId, opts): Promise<void> {
      const context = await site(target);
      // Spec section 13: agent self-revocation presents the revocation call
      // as a section 11 signed request carrying the grant being revoked.
      const grant = await store.get(grantId);
      if (grant === undefined) {
        throw new AgentError('no_grant', `no stored grant ${grantId}`);
      }
      const signer = signers.get(grant.keyId);
      if (signer === undefined) {
        throw new AgentError(
          'no_key',
          `grant is bound to key ${grant.keyId}, which is not registered`,
        );
      }
      const res = await executeProtectedRequest(
        context,
        grant,
        signer,
        {
          method: 'POST',
          target: context.document.endpoints.grant_revocation,
          body: JSON.stringify({
            grant_id: grantId,
            ...(opts?.reason !== undefined ? { reason: opts.reason } : {}),
          }),
        },
        { transport, clock },
      );
      if (res.status !== 200) {
        throw errorFromResponse(res.status, res.body);
      }
      await store.remove(grantId);
    },
  };
}
