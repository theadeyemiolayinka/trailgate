import { createHash } from 'node:crypto';
import type {
  GrantPayload,
  Jwk,
  KeyResolver,
  Money,
  RequestVerificationResult,
} from '@trailgate/core';
import {
  buildSignatureBase,
  Codes,
  decodeCompactJws,
  getHeader,
  isTrailGateError,
  parseTgSignatureInput,
  TrailGateError,
  toErrorResponse,
  verifyProtectedRequest,
} from '@trailgate/core';
import type { ResolvedServerConfig } from './config.ts';
import { randomId } from './ids.ts';
import type { Reservation } from './ports.ts';
import { issueReceipt } from './signing.ts';
import type {
  EnforcementContext,
  HostRequest,
  HostResponse,
  ProtectedHandler,
  RouteProtection,
} from './types.ts';

/**
 * Response header carrying the receipt JWS.
 * @provisional The receipt delivery channel is not named in draft 0.1
 * (spec section 14 requires a receipt but does not specify how it is
 * returned). Raise changes through D0 before depending on this name.
 */
export const RECEIPT_HEADER = 'trailgate-receipt';

/** Maps verification failure codes to the spec section 11.3 stage for audit. */
const CODE_TO_STAGE: Record<string, number> = {
  [Codes.REQUEST_MALFORMED]: 1,
  [Codes.REQUEST_BODY_DIGEST_MISMATCH]: 2,
  [Codes.REQUEST_SIGNATURE_INVALID]: 3,
  [Codes.REQUEST_EXPIRED]: 4,
  [Codes.GRANT_MALFORMED]: 5,
  [Codes.REQUEST_AUDIENCE_MISMATCH]: 5,
  [Codes.GRANT_EXPIRED]: 5,
  [Codes.GRANT_REVOKED]: 6,
  [Codes.REQUEST_KEY_MISMATCH]: 7,
  [Codes.REQUEST_REPLAY_DETECTED]: 8,
  [Codes.REQUEST_IDEMPOTENCY_CONFLICT]: 9,
  [Codes.REQUEST_PERMISSION_DENIED]: 10,
  [Codes.REQUEST_RESOURCE_DENIED]: 11,
  [Codes.CONSTRAINT_VIOLATED]: 12,
  [Codes.CONSTRAINT_UNKNOWN_TYPE]: 12,
  [Codes.AUTHORIZATION_DENIED]: 13,
};

/**
 * Operation digest per spec section 11.4 / ADR 0008: method, target URI,
 * Content-Digest, and grant jti. Must produce the same value core computes
 * inside `verifyProtectedRequest`; promoting this helper into core is a
 * pending question for D0.
 */
function operationDigestOf(req: HostRequest, grantId: string): string {
  return createHash('sha256')
    .update(
      `${req.method.toUpperCase()} ${req.url} ${getHeader(req, 'content-digest')} ${grantId}`,
      'utf8',
    )
    .digest('base64url');
}

/** Best-effort recovery of the receipt binding inputs from a failed request. */
function receiptBasis(req: HostRequest): { grantId?: string; signatureBase?: string } {
  const basis: { grantId?: string; signatureBase?: string } = {};
  try {
    const grantHeader = getHeader(req, 'trailgate-grant');
    if (grantHeader !== undefined) {
      const decoded = decodeCompactJws(grantHeader);
      const jti = (decoded.payload as Partial<GrantPayload>).jti;
      if (typeof jti === 'string') {
        basis.grantId = jti;
      }
    }
  } catch {
    // Grant was malformed or unsigned; no reliable jti for the receipt.
  }
  try {
    const inputHeader = getHeader(req, 'signature-input');
    if (inputHeader !== undefined) {
      const parsed = parseTgSignatureInput(inputHeader);
      basis.signatureBase = buildSignatureBase(req, parsed.components, parsed.entry);
    }
  } catch {
    // Signature-Input was unparseable; no signature base to bind a receipt to.
  }
  return basis;
}

/**
 * Renders a denial: error envelope, `request.denied` audit event, and a
 * signed receipt when the request was parseable enough to bind one
 * (spec section 14.4). Failures while denying never mask the denial itself.
 */
async function denialResponse(
  err: unknown,
  req: HostRequest,
  config: ResolvedServerConfig,
  extra?: { grantId?: string; signatureBase?: string; released?: Money },
): Promise<HostResponse> {
  const error = isTrailGateError(err)
    ? err
    : new TrailGateError(Codes.INTERNAL_ERROR, 'internal error');
  const basis = { ...receiptBasis(req), ...extra };
  let auditId: string | undefined;
  try {
    auditId = await config.stores.audit.record({
      event: 'request.denied',
      at: config.clock.now(),
      code: error.code,
      stage: String(CODE_TO_STAGE[error.code] ?? 0),
      ...(basis.grantId !== undefined ? { grant_id: basis.grantId } : {}),
    });
  } catch {
    // Audit failure on an already-denied path must not mask the denial.
  }
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (basis.grantId !== undefined && basis.signatureBase !== undefined && auditId !== undefined) {
    try {
      const { token } = await issueReceipt(
        {
          issuer: config.issuer,
          audience: config.audience,
          grantId: basis.grantId,
          signatureBase: basis.signatureBase,
          decision: 'denied',
          code: error.code,
          auditId,
          now: config.clock.now(),
          ...(extra?.released !== undefined ? { amounts: { released: extra.released } } : {}),
        },
        config.signingKey,
      );
      headers[RECEIPT_HEADER] = token;
    } catch {
      // A receipt that cannot be signed is omitted; the error body still stands.
    }
  }
  return { status: error.httpStatus, headers, body: toErrorResponse(error) };
}

function resolveAmount(route: RouteProtection, req: HostRequest): Money | undefined {
  return typeof route.amount === 'function' ? route.amount(req) : route.amount;
}

function resolveResource(route: RouteProtection, req: HostRequest): string | undefined {
  return typeof route.resource === 'function' ? route.resource(req) : route.resource;
}

function requestNonce(req: HostRequest): string | undefined {
  try {
    const header = getHeader(req, 'signature-input');
    if (header === undefined) {
      return undefined;
    }
    return parseTgSignatureInput(header).params.nonce;
  } catch {
    return undefined;
  }
}

function siteKeyResolver(config: ResolvedServerConfig): KeyResolver {
  const keys = new Map<string, Jwk>(config.signingKeys.map((key) => [key.kid, key.publicJwk]));
  return { resolve: async (kid) => keys.get(kid) };
}

/**
 * Wraps a host handler with the spec section 11 enforcement pipeline:
 * protocol verification via `verifyProtectedRequest`, then reservation,
 * execution, settlement, idempotency recording, audit, and a signed receipt.
 *
 * The returned handler produces complete `HostResponse`s including denials;
 * it never throws for protocol-level failures. Reservations are consumed when
 * the host handler answers with status < 400 and released on throws or
 * higher statuses (spec section 12).
 */
export function createProtectedHandler(
  route: RouteProtection,
  handler: ProtectedHandler,
  config: ResolvedServerConfig,
): (req: HostRequest) => Promise<HostResponse> {
  return async (req) => {
    const amount = resolveAmount(route, req);
    const resource = resolveResource(route, req);
    let result: RequestVerificationResult;
    try {
      result = await verifyProtectedRequest(req, {
        issuer: config.issuer,
        audience: config.audience,
        resolveSiteKey: siteKeyResolver(config),
        resolveAgentKey: config.stores.agentKeys,
        revocation: config.stores.grants,
        nonceStore: config.stores.nonces,
        idempotency: config.stores.idempotency,
        ledger: config.stores.ledger,
        rateLimiter: config.stores.rateLimiter,
        clock: config.clock,
        toleranceSeconds: config.toleranceSeconds,
        supportedProtocolVersions: config.supportedProtocolVersions,
        permissionVocabulary: config.permissions,
        ...(config.resourceOwners !== undefined ? { resourceOwners: config.resourceOwners } : {}),
        ...(config.policy !== undefined ? { policy: config.policy } : {}),
        requiredPermission: route.permission,
        ...(amount !== undefined ? { requestAmount: amount } : {}),
        ...(resource !== undefined ? { touchedResource: resource } : {}),
      });
    } catch (err) {
      return denialResponse(err, req, config);
    }

    const { grant, requestDigest } = result;
    const now = config.clock.now();
    const idempotencyKey = getHeader(req, 'idempotency-key');

    let auditId: string;
    try {
      const nonce = requestNonce(req);
      auditId = await config.stores.audit.record({
        event: 'request.authenticated',
        at: now,
        grant_id: grant.jti,
        request_digest: requestDigest,
        ...(nonce !== undefined ? { nonce } : {}),
      });
    } catch {
      return denialResponse(
        new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'audit sink is unavailable'),
        req,
        config,
        { grantId: grant.jti, signatureBase: result.signatureBase },
      );
    }

    await config.stores.rateLimiter.record(grant.jti, now);

    if (result.idempotentReplay && idempotencyKey !== undefined) {
      const stored = await config.stores.idempotency.lookup(grant.jti, idempotencyKey);
      if (stored?.outcome === undefined) {
        return denialResponse(
          new TrailGateError(
            Codes.INTERNAL_UNAVAILABLE,
            'idempotent replay has no recorded outcome',
          ),
          req,
          config,
          { grantId: grant.jti, signatureBase: result.signatureBase },
        );
      }
      const outcome = stored.outcome;
      const replayed: HostResponse = { status: outcome.status };
      if (outcome.headers !== undefined) {
        replayed.headers = outcome.headers;
      }
      if (outcome.body !== undefined) {
        replayed.body = outcome.body;
      }
      return replayed;
    }

    let reservation: Reservation | undefined;
    if (amount !== undefined) {
      const budgets = grant.tg.constraints
        .filter((c) => c.type === 'cumulative_budget')
        .map((c) => c.params as Money | undefined)
        .filter((p): p is Money => p !== undefined && p.currency === amount.currency);
      try {
        reservation = await config.stores.ledger.reserve({
          reservationId: randomId('rsv'),
          grantId: grant.jti,
          amount,
          budgets,
          now,
          ttlSeconds: config.reservationTtlSeconds,
        });
        await config.stores.audit.record({
          event: 'reservation.created',
          at: now,
          grant_id: grant.jti,
          reservation_id: reservation.reservationId,
          amount: amount.amount,
          currency: amount.currency,
        });
      } catch (err) {
        if (reservation !== undefined) {
          try {
            await releaseReservation(config, reservation, grant.jti, now);
          } catch {
            // Releasing also failed; the reservation TTL will reclaim it.
          }
        }
        return denialResponse(err, req, config, {
          grantId: grant.jti,
          signatureBase: result.signatureBase,
        });
      }
    }

    const context: EnforcementContext = { ...result.context, grant };
    let response: HostResponse;
    try {
      response = await handler(req, context);
    } catch (err) {
      if (reservation !== undefined) {
        try {
          await releaseReservation(config, reservation, grant.jti, now);
        } catch {
          // The handler's error takes precedence; the reservation TTL reclaims it.
        }
      }
      return denialResponse(err, req, config, {
        grantId: grant.jti,
        signatureBase: result.signatureBase,
        ...(reservation !== undefined ? { released: reservation.amount } : {}),
      });
    }

    const amounts: { consumed?: Money; released?: Money } = {};
    if (reservation !== undefined) {
      if (response.status < 400) {
        await config.stores.ledger.consume(reservation.reservationId, now);
        await config.stores.audit.record({
          event: 'reservation.consumed',
          at: now,
          grant_id: grant.jti,
          reservation_id: reservation.reservationId,
          amount: reservation.amount.amount,
          currency: reservation.amount.currency,
        });
        amounts.consumed = reservation.amount;
      } else {
        await releaseReservation(config, reservation, grant.jti, now);
        amounts.released = reservation.amount;
      }
    }

    const { token } = await issueReceipt(
      {
        issuer: config.issuer,
        audience: config.audience,
        grantId: grant.jti,
        signatureBase: result.signatureBase,
        decision: 'allowed',
        auditId,
        now,
        ...(Object.keys(amounts).length > 0 ? { amounts } : {}),
      },
      config.signingKey,
    );
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      ...(response.headers ?? {}),
      [RECEIPT_HEADER]: token,
    };
    const finalResponse: HostResponse = { ...response, headers };

    if (route.mutating !== false && idempotencyKey !== undefined) {
      try {
        await config.stores.idempotency.record(grant.jti, idempotencyKey, {
          requestDigest: operationDigestOf(req, grant.jti),
          outcome: { status: finalResponse.status, headers, body: finalResponse.body },
        });
      } catch {
        // A record that cannot be stored weakens dedupe, not this response;
        // production stores should surface this operationally.
      }
    }
    return finalResponse;
  };
}

async function releaseReservation(
  config: ResolvedServerConfig,
  reservation: Reservation,
  grantId: string,
  now: number,
): Promise<void> {
  await config.stores.ledger.release(reservation.reservationId, now);
  await config.stores.audit.record({
    event: 'reservation.released',
    at: now,
    grant_id: grantId,
    reservation_id: reservation.reservationId,
    amount: reservation.amount.amount,
    currency: reservation.amount.currency,
  });
}
