import { randomBytes } from 'node:crypto';
import type { Jwk } from './keys.ts';

export const FIXTURE_ORIGIN = 'https://shop.example.com';

export function randomId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('base64url')}`;
}

export function makeDiscovery(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = {
    version: '0.1',
    protocol_versions: ['0.1'],
    issuer: FIXTURE_ORIGIN,
    endpoints: {
      grant_request: `${FIXTURE_ORIGIN}/tg/grant-request`,
      grant_redemption: `${FIXTURE_ORIGIN}/tg/redeem`,
      grant_status: `${FIXTURE_ORIGIN}/tg/status`,
      grant_revocation: `${FIXTURE_ORIGIN}/tg/revoke`,
    },
    signing_keys: {
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
    },
    permissions: ['tg.cart.read', 'tg.order.create', 'tg.wallet.charge'],
    constraint_types: ['max_amount', 'cumulative_budget', 'rate_limit', 'valid_window'],
  };
  return { ...base, ...overrides };
}

export function makeMoney(amount = 5000, currency = 'USD'): { amount: number; currency: string } {
  return { amount, currency };
}

export function makeConstraint(
  type: string,
  params: Record<string, unknown> = {},
): Record<string, unknown> {
  const defaults: Record<string, Record<string, unknown>> = {
    max_amount: { amount: 5000, currency: 'USD' },
    cumulative_budget: { amount: 20000, currency: 'USD' },
    rate_limit: { max_requests: 60, window_seconds: 3600 },
    valid_window: { not_before: 0, not_after: 4102444800 },
  };
  return { type, params: { ...(defaults[type] ?? {}), ...params } };
}

export interface GrantPayloadInput {
  issuer?: string;
  audience?: string;
  iat?: number;
  exp?: number;
  jti?: string;
  sub?: string;
  jkt: string;
  permissions?: string[];
  resources?: string[];
  constraints?: Record<string, unknown>[];
  requestId?: string;
  version?: string;
}

export function makeGrantPayload(input: GrantPayloadInput): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: input.issuer ?? FIXTURE_ORIGIN,
    aud: input.audience ?? FIXTURE_ORIGIN,
    iat: input.iat ?? now - 60,
    exp: input.exp ?? now + 3600,
    jti: input.jti ?? randomId('grt'),
    cnf: { jkt: input.jkt },
    tg: {
      version: input.version ?? '0.1',
      permissions: input.permissions ?? ['tg.order.create'],
      resources: input.resources ?? [],
      constraints: input.constraints ?? [],
      request_id: input.requestId ?? randomId('req'),
    },
  };
  if (input.sub !== undefined) {
    payload['sub'] = input.sub;
  }
  return payload;
}

export function makeGrantRequest(input: {
  agentKey: Jwk;
  permissions?: string[];
  resources?: string[];
  constraints?: Record<string, unknown>[];
  codeChallenge?: string;
  redirectUri?: string;
}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    version: '0.1',
    permissions: input.permissions ?? ['tg.order.create'],
    resources: input.resources ?? [],
    constraints: input.constraints ?? [],
    agent_key: input.agentKey,
    code_challenge: input.codeChallenge ?? randomBytes(32).toString('base64url'),
    code_challenge_method: 'S256',
  };
  if (input.redirectUri !== undefined) {
    body['redirect_uri'] = input.redirectUri;
  }
  return body;
}
