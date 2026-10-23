import { Codes, TrailGateError } from './errors.ts';
import { callPort, type Ledger, type RateLimiter } from './ports.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { Constraint, Money } from './types.ts';

export const REGISTERED_CONSTRAINT_TYPES = [
  'max_amount',
  'cumulative_budget',
  'rate_limit',
  'valid_window',
] as const;

export interface ConstraintContext {
  grantId: string;
  now: number;
  requestAmount?: Money;
  ledger?: Ledger;
  rateLimiter?: RateLimiter;
}

function asInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new TrailGateError(
      Codes.CONSTRAINT_VIOLATED,
      `constraint param ${name} is not an integer`,
    );
  }
  return value;
}

function checkMoneyShape(params: Record<string, unknown>): { amount: number; currency: string } {
  const amount = asInteger(params['amount'], 'amount');
  const currency = params['currency'];
  if (typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency)) {
    throw new TrailGateError(
      Codes.CONSTRAINT_VIOLATED,
      'constraint param currency is not iso 4217',
    );
  }
  return { amount, currency };
}

async function evaluateMaxAmount(
  params: Record<string, unknown>,
  ctx: ConstraintContext,
): Promise<void> {
  const limit = checkMoneyShape(params);
  if (ctx.requestAmount === undefined) {
    return;
  }
  if (ctx.requestAmount.currency !== limit.currency || ctx.requestAmount.amount > limit.amount) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'request amount exceeds max_amount', {
      type: 'max_amount',
      limit,
    });
  }
}

async function evaluateCumulativeBudget(
  params: Record<string, unknown>,
  ctx: ConstraintContext,
): Promise<void> {
  const budget = checkMoneyShape(params);
  if (ctx.ledger === undefined) {
    throw new TrailGateError(
      Codes.INTERNAL_UNAVAILABLE,
      'cumulative_budget cannot be evaluated without a ledger',
    );
  }
  const ledger = ctx.ledger;
  const [consumed, reserved] = await Promise.all([
    callPort(
      () => ledger.consumedMinorUnits(ctx.grantId, budget.currency),
      'ledger is unavailable',
    ),
    callPort(
      () => ledger.reservedMinorUnits(ctx.grantId, budget.currency),
      'ledger is unavailable',
    ),
  ]);
  const requested =
    ctx.requestAmount !== undefined && ctx.requestAmount.currency === budget.currency
      ? ctx.requestAmount.amount
      : 0;
  if (consumed + reserved + requested > budget.amount) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'cumulative_budget would be exceeded', {
      type: 'cumulative_budget',
      limit: budget,
      consumed,
      reserved,
    });
  }
}

async function evaluateRateLimit(
  params: Record<string, unknown>,
  ctx: ConstraintContext,
): Promise<void> {
  const maxRequests = asInteger(params['max_requests'], 'max_requests');
  const windowSeconds = asInteger(params['window_seconds'], 'window_seconds');
  if (ctx.rateLimiter === undefined) {
    throw new TrailGateError(
      Codes.INTERNAL_UNAVAILABLE,
      'rate_limit cannot be evaluated without a counter',
    );
  }
  const rateLimiter = ctx.rateLimiter;
  const count = await callPort(
    () => rateLimiter.countInWindow(ctx.grantId, windowSeconds, ctx.now),
    'rate limiter is unavailable',
  );
  if (count >= maxRequests) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'rate_limit exceeded', {
      type: 'rate_limit',
      max_requests: maxRequests,
      window_seconds: windowSeconds,
    });
  }
}

function evaluateValidWindow(params: Record<string, unknown>, ctx: ConstraintContext): void {
  const notBefore = asInteger(params['not_before'], 'not_before');
  const notAfter = asInteger(params['not_after'], 'not_after');
  if (ctx.now < notBefore || ctx.now > notAfter) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'outside valid_window', {
      type: 'valid_window',
      not_before: notBefore,
      not_after: notAfter,
    });
  }
}

export async function evaluateConstraints(
  constraints: readonly Constraint[],
  ctx: ConstraintContext,
): Promise<void> {
  for (const constraint of constraints) {
    if (!schemaRegistry().validate(SCHEMA_IDS.constraint, constraint)) {
      throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'constraint is malformed', {
        type: constraint.type,
      });
    }
    const params = constraint.params ?? {};
    switch (constraint.type) {
      case 'max_amount':
        await evaluateMaxAmount(params, ctx);
        break;
      case 'cumulative_budget':
        await evaluateCumulativeBudget(params, ctx);
        break;
      case 'rate_limit':
        await evaluateRateLimit(params, ctx);
        break;
      case 'valid_window':
        evaluateValidWindow(params, ctx);
        break;
      default:
        throw new TrailGateError(Codes.CONSTRAINT_UNKNOWN_TYPE, 'unknown constraint type', {
          type: constraint.type,
        });
    }
  }
}
