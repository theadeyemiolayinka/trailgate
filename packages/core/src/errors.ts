export type ErrorCode = `tg.${string}.${string}`;

export const Codes = {
  DISCOVERY_INVALID: 'tg.discovery.invalid',
  DISCOVERY_UNSUPPORTED_VERSION: 'tg.discovery.unsupported_version',
  GRANT_MALFORMED: 'tg.grant.malformed',
  GRANT_EXPIRED: 'tg.grant.expired',
  GRANT_REVOKED: 'tg.grant.revoked',
  GRANT_REDEEMED: 'tg.grant.redeemed',
  GRANT_UNKNOWN: 'tg.grant.unknown',
  GRANT_UNKNOWN_PERMISSION: 'tg.grant.unknown_permission',
  GRANT_SCOPE_REJECTED: 'tg.grant.scope_rejected',
  GRANT_CONSENT_DENIED: 'tg.grant.consent_denied',
  REQUEST_MALFORMED: 'tg.request.malformed',
  REQUEST_BODY_DIGEST_MISMATCH: 'tg.request.body_digest_mismatch',
  REQUEST_SIGNATURE_INVALID: 'tg.request.signature_invalid',
  REQUEST_KEY_MISMATCH: 'tg.request.key_mismatch',
  REQUEST_EXPIRED: 'tg.request.expired',
  REQUEST_REPLAY_DETECTED: 'tg.request.replay_detected',
  REQUEST_IDEMPOTENCY_CONFLICT: 'tg.request.idempotency_conflict',
  REQUEST_IDEMPOTENCY_IN_FLIGHT: 'tg.request.idempotency_in_flight',
  REQUEST_TOO_LARGE: 'tg.request.too_large',
  REQUEST_AUDIENCE_MISMATCH: 'tg.request.audience_mismatch',
  REQUEST_PERMISSION_DENIED: 'tg.request.permission_denied',
  REQUEST_RESOURCE_DENIED: 'tg.request.resource_denied',
  CONSTRAINT_VIOLATED: 'tg.constraint.violated',
  CONSTRAINT_UNKNOWN_TYPE: 'tg.constraint.unknown_type',
  CONSTRAINT_APPROVAL_REQUIRED: 'tg.constraint.approval_required',
  AUTHORIZATION_DENIED: 'tg.authorization.denied',
  INTERNAL_UNAVAILABLE: 'tg.internal.unavailable',
  INTERNAL_ERROR: 'tg.internal.error',
} as const;

export type RegisteredCode = (typeof Codes)[keyof typeof Codes];

const HTTP_STATUS: Record<RegisteredCode, number> = {
  'tg.discovery.invalid': 400,
  'tg.discovery.unsupported_version': 400,
  'tg.grant.malformed': 400,
  'tg.grant.expired': 403,
  'tg.grant.revoked': 403,
  'tg.grant.redeemed': 409,
  'tg.grant.unknown': 404,
  'tg.grant.unknown_permission': 400,
  'tg.grant.scope_rejected': 403,
  'tg.grant.consent_denied': 403,
  'tg.request.malformed': 400,
  'tg.request.body_digest_mismatch': 400,
  'tg.request.signature_invalid': 403,
  'tg.request.key_mismatch': 403,
  'tg.request.expired': 403,
  'tg.request.replay_detected': 403,
  'tg.request.idempotency_conflict': 409,
  'tg.request.idempotency_in_flight': 409,
  'tg.request.too_large': 413,
  'tg.request.audience_mismatch': 403,
  'tg.request.permission_denied': 403,
  'tg.request.resource_denied': 403,
  'tg.constraint.violated': 403,
  'tg.constraint.unknown_type': 403,
  'tg.constraint.approval_required': 403,
  'tg.authorization.denied': 403,
  'tg.internal.unavailable': 503,
  'tg.internal.error': 500,
};

export interface ErrorResponse {
  error: {
    code: ErrorCode;
    message: string;
    detail?: Record<string, unknown>;
  };
}

export class TrailGateError extends Error {
  readonly code: ErrorCode;
  readonly detail?: Record<string, unknown>;
  readonly httpStatus: number;

  constructor(code: ErrorCode, message: string, detail?: Record<string, unknown>) {
    super(message);
    this.name = 'TrailGateError';
    this.code = code;
    this.httpStatus = HTTP_STATUS[code as RegisteredCode] ?? 400;
    if (detail !== undefined) {
      this.detail = detail;
    }
  }
}

export function isTrailGateError(value: unknown): value is TrailGateError {
  return value instanceof TrailGateError;
}

export function toErrorResponse(err: unknown): ErrorResponse {
  if (isTrailGateError(err)) {
    const error: ErrorResponse['error'] = { code: err.code, message: err.message };
    if (err.detail !== undefined) {
      error.detail = err.detail;
    }
    return { error };
  }
  return {
    error: {
      code: Codes.INTERNAL_ERROR,
      message: 'internal error',
    },
  };
}
