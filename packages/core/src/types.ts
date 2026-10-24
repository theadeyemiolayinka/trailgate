export type ProtocolVersion = '0.1';

export type Permission = `tg.${string}.${string}`;

export interface Money {
  amount: number;
  currency: string;
}

export interface Jwk {
  kty: string;
  use?: string;
  key_ops?: string[];
  alg?: string;
  kid?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  [member: string]: unknown;
}

export interface Jwks {
  keys: Jwk[];
  [member: string]: unknown;
}

export interface DiscoveryEndpoints {
  grant_request: string;
  grant_redemption: string;
  grant_status: string;
  grant_revocation: string;
}

export interface DiscoveryCapabilities {
  supports_redirect?: boolean;
  supports_receipts_unsigned?: boolean;
  max_grant_seconds?: number;
  rate_limits?: Record<string, unknown>;
  [member: string]: unknown;
}

/**
 * Advisory descriptor of one protected route (spec section 5.2). It maps
 * intent to a concrete request target; it authorizes nothing by itself and
 * is untrusted site input until the discovery document validates.
 */
export interface DiscoveryAction {
  /** Stable action identifier, unique within the document. */
  id: string;
  /** Uppercase HTTP method of the protected route. */
  method: string;
  /** Absolute path template; `{name}` marks a substituted path parameter. */
  path: string;
  /** The `tg.*` permission the request must hold. */
  permission: string;
  /**
   * Short statement of what the action does. Required: it is the primary
   * signal an agent uses to match intent to endpoint.
   */
  description: string;
  /** Whether the action changes state; absent means "treat as mutating". */
  mutates?: boolean;
  /** Resource selector template, e.g. `cart:{user}`. */
  resource?: string;
  /** When true, the action may charge money and spend constraints apply. */
  spend?: boolean;
}

export interface DiscoveryDocument {
  version: string;
  protocol_versions: string[];
  issuer: string;
  endpoints: DiscoveryEndpoints;
  signing_keys: Jwks;
  permissions: string[];
  constraint_types: string[];
  capabilities?: DiscoveryCapabilities;
  actions?: DiscoveryAction[];
  critical?: string[];
  [member: string]: unknown;
}

export interface Constraint {
  type: string;
  params?: Record<string, unknown>;
}

export interface GrantTgClaims {
  version: string;
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  request_id: string;
}

export interface GrantPayload {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  sub?: string;
  cnf: { jkt: string };
  tg: GrantTgClaims;
  critical?: string[];
}

export interface GrantRequestBody {
  version: string;
  permissions: string[];
  resources: string[];
  constraints: Constraint[];
  agent_key: Jwk;
  code_challenge: string;
  code_challenge_method: 'S256';
  redirect_uri?: string;
  state?: string;
  requested_seconds?: number;
}

export interface ReceiptAmounts {
  reserved?: Money;
  consumed?: Money;
  released?: Money;
}

export interface ReceiptTgClaims {
  grant_id: string;
  request_digest: string;
  decision: 'allowed' | 'denied';
  code?: string;
  amounts?: ReceiptAmounts;
  audit_id: string;
}

export interface ReceiptPayload {
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  tg: ReceiptTgClaims;
  critical?: string[];
}

export type AuditEventType =
  | 'grant.requested'
  | 'grant.consent_decided'
  | 'grant.issued'
  | 'grant.revoked'
  | 'request.authenticated'
  | 'request.denied'
  | 'reservation.created'
  | 'reservation.consumed'
  | 'reservation.released'
  | 'idempotency.record_failed'
  | 'request_approval.requested'
  | 'request_approval.decided'
  | 'key.rotated';

export interface AuditEvent {
  event: AuditEventType;
  at: number;
  actor?: string;
  request_id?: string;
  grant_id?: string;
  jkt?: string;
  sub?: string;
  decision?: string;
  code?: string;
  stage?: string;
  reason?: string;
  nonce?: string;
  request_digest?: string;
  reservation_id?: string;
  amount?: number;
  currency?: string;
  permissions?: string[];
  constraints?: Constraint[];
  old_jkt?: string;
  new_jkt?: string;
  exp?: number;
  detail?: Record<string, unknown>;
}
