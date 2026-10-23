import { createHash } from 'node:crypto';
import { evaluateConstraints } from './constraints.ts';
import { requestDigestOf, verifyContentDigest } from './digest.ts';
import { Codes, TrailGateError } from './errors.ts';
import { verifyGrant } from './grant.ts';
import { signatureAlgorithmFor } from './jwk.ts';
import { assertPermissionGranted } from './permissions.ts';
import type {
  Clock,
  IdempotencyStore,
  KeyResolver,
  Ledger,
  NonceStore,
  RateLimiter,
  ResourceOwnerResolver,
  RevocationChecker,
  SitePolicy,
  VerifiedRequestContext,
} from './ports.ts';
import { systemClock } from './ports.ts';
import { assertResourceAllowed } from './resources.ts';
import {
  buildSignatureBase,
  checkNonceShape,
  checkSignatureWindow,
  getHeader,
  getSignatureBytes,
  MAX_CLOCK_TOLERANCE_SECONDS,
  MAX_SIGNATURE_WINDOW_SECONDS,
  parseTgSignatureInput,
  publicKeyFromJwk,
  verifySignatureBytes,
} from './signature.ts';
import type { GrantPayload, Money } from './types.ts';

export interface ProtectedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array | string;
}

export interface RequestVerificationDeps {
  issuer: string;
  audience: string;
  resolveSiteKey: KeyResolver;
  resolveAgentKey: KeyResolver;
  revocation: RevocationChecker;
  nonceStore: NonceStore;
  clock?: Clock;
  idempotency?: IdempotencyStore;
  ledger?: Ledger;
  rateLimiter?: RateLimiter;
  resourceOwners?: ResourceOwnerResolver;
  policy?: SitePolicy;
  toleranceSeconds?: number;
  supportedProtocolVersions?: readonly string[];
  permissionVocabulary?: readonly string[];
  knownCriticalFields?: readonly string[];
  requiredPermission?: string;
  requestAmount?: Money;
  touchedResource?: string;
}

export interface RequestVerificationResult {
  grant: GrantPayload;
  requestDigest: string;
  signatureBase: string;
  idempotentReplay: boolean;
  context: VerifiedRequestContext;
}

const REQUIRED_HEADERS = [
  'trailgate-grant',
  'signature-input',
  'signature',
  'content-digest',
  'idempotency-key',
];

function bodyBytes(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) {
    return new Uint8Array();
  }
  if (typeof body === 'string') {
    return new TextEncoder().encode(body);
  }
  return body;
}

export async function verifyProtectedRequest(
  req: ProtectedRequest,
  deps: RequestVerificationDeps,
): Promise<RequestVerificationResult> {
  const clock = deps.clock ?? systemClock;
  const tolerance = deps.toleranceSeconds ?? 60;
  if (tolerance > MAX_CLOCK_TOLERANCE_SECONDS) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'clock tolerance exceeds the allowed maximum');
  }

  for (const name of REQUIRED_HEADERS) {
    if (getHeader(req, name) === undefined) {
      throw new TrailGateError(Codes.REQUEST_MALFORMED, `missing required header: ${name}`);
    }
  }

  const body = bodyBytes(req.body);
  verifyContentDigest(getHeader(req, 'content-digest'), body);

  const signatureInput = parseTgSignatureInput(getHeader(req, 'signature-input') as string);
  checkNonceShape(signatureInput.params.nonce);
  checkSignatureWindow(
    signatureInput.params.created,
    signatureInput.params.expires,
    clock.now(),
    tolerance,
  );

  const grantToken = getHeader(req, 'trailgate-grant') as string;
  const grant = await verifyGrant(grantToken, {
    resolveSiteKey: deps.resolveSiteKey,
    issuer: deps.issuer,
    audience: deps.audience,
    now: clock.now(),
    ...(deps.knownCriticalFields !== undefined
      ? { knownCriticalFields: deps.knownCriticalFields }
      : {}),
  });

  const supported = deps.supportedProtocolVersions ?? ['0.1'];
  if (!supported.includes(grant.tg.version)) {
    throw new TrailGateError(Codes.GRANT_MALFORMED, 'unsupported grant protocol version');
  }

  if (deps.permissionVocabulary !== undefined) {
    const vocabulary = new Set(deps.permissionVocabulary);
    const unknown = grant.tg.permissions.filter((permission) => !vocabulary.has(permission));
    if (unknown.length > 0) {
      throw new TrailGateError(
        Codes.GRANT_MALFORMED,
        'grant carries permissions outside the site vocabulary',
        { unknown },
      );
    }
  }

  if (await deps.revocation.isRevoked(grant.jti)) {
    throw new TrailGateError(Codes.GRANT_REVOKED, 'grant is revoked');
  }

  if (signatureInput.params.keyid !== grant.cnf.jkt) {
    throw new TrailGateError(
      Codes.REQUEST_KEY_MISMATCH,
      'signature keyid does not match grant key binding',
    );
  }
  const agentJwk = await deps.resolveAgentKey.resolve(grant.cnf.jkt);
  if (agentJwk === undefined) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, 'agent key is unresolvable');
  }
  const agentAlg = signatureAlgorithmFor(agentJwk);
  if (agentAlg === undefined || agentAlg !== signatureInput.params.alg) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      'signature algorithm does not match the agent key',
    );
  }
  const signatureBase = buildSignatureBase(req, signatureInput.components, signatureInput.entry);
  const signatureBytes = getSignatureBytes(getHeader(req, 'signature') as string);
  const signatureOk = verifySignatureBytes(
    signatureInput.params.alg,
    publicKeyFromJwk(agentJwk),
    signatureBytes,
    signatureBase,
  );
  if (!signatureOk) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, 'signature verification failed');
  }

  const signatureWindowTtl = MAX_SIGNATURE_WINDOW_SECONDS + tolerance;
  const nonceIsFresh = await deps.nonceStore.claim(
    grant.jti,
    signatureInput.params.nonce,
    signatureWindowTtl,
  );
  if (!nonceIsFresh) {
    throw new TrailGateError(Codes.REQUEST_REPLAY_DETECTED, 'nonce already seen for this grant');
  }

  const requestDigest = requestDigestOf(signatureBase);
  const operationDigest = createHash('sha256')
    .update(
      `${req.method.toUpperCase()} ${req.url} ${getHeader(req, 'content-digest')} ${grant.jti}`,
      'utf8',
    )
    .digest('base64url');
  let idempotentReplay = false;
  const idempotencyKey = getHeader(req, 'idempotency-key');
  if (deps.idempotency !== undefined && idempotencyKey !== undefined) {
    const record = await deps.idempotency.lookup(grant.jti, idempotencyKey);
    if (record !== undefined) {
      if (record.requestDigest !== operationDigest) {
        throw new TrailGateError(
          Codes.REQUEST_IDEMPOTENCY_CONFLICT,
          'idempotency-key reused with a different request',
        );
      }
      idempotentReplay = true;
    }
  }

  if (deps.requiredPermission !== undefined) {
    assertPermissionGranted(grant.tg.permissions, deps.requiredPermission);
  }

  if (deps.touchedResource !== undefined) {
    if (deps.resourceOwners === undefined) {
      throw new TrailGateError(Codes.INTERNAL_UNAVAILABLE, 'resource ownership cannot be checked');
    }
    await assertResourceAllowed(
      grant.tg.resources,
      deps.touchedResource,
      deps.resourceOwners,
      grant.sub,
    );
  }

  await evaluateConstraints(grant.tg.constraints, {
    grantId: grant.jti,
    now: clock.now(),
    ...(deps.ledger !== undefined ? { ledger: deps.ledger } : {}),
    ...(deps.rateLimiter !== undefined ? { rateLimiter: deps.rateLimiter } : {}),
    ...(deps.requestAmount !== undefined ? { requestAmount: deps.requestAmount } : {}),
  });

  const context: VerifiedRequestContext = {
    grantId: grant.jti,
    permissions: grant.tg.permissions,
    resources: grant.tg.resources,
    method: req.method,
    url: req.url,
    requestDigest,
    ...(grant.sub !== undefined ? { subject: grant.sub } : {}),
  };
  if (deps.policy !== undefined) {
    await deps.policy.authorize(context);
  }

  return { grant, requestDigest, signatureBase, idempotentReplay, context };
}
