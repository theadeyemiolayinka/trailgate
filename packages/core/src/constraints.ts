import { Codes, TrailGateError } from './errors.ts';
import { callPort, type Ledger, type RateLimiter, type RequestApprovalChecker } from './ports.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { Constraint, Money } from './types.ts';

export const REGISTERED_CONSTRAINT_TYPES = [
  'max_amount',
  'cumulative_budget',
  'rate_limit',
  'valid_window',
  'spend_window',
  'approval_threshold',
] as const;

export interface ConstraintContext {
  grantId: string;
  now: number;
  requestAmount?: Money;
  /** Operation binding (method, target, body, grant) for approval lookups. */
  operationDigest?: string;
  /**
   * True when this request replays a stored idempotency outcome. Replays
   * return the recorded decision rather than executing again, so
   * `approval_threshold` does not demand a fresh approval for them.
   */
  idempotentReplay?: boolean;
  ledger?: Ledger;
  rateLimiter?: RateLimiter;
  approvals?: RequestApprovalChecker;
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
      'constraint param currency is not a valid unit code',
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

async function evaluateSpendWindow(
  params: Record<string, unknown>,
  ctx: ConstraintContext,
): Promise<void> {
  const budget = checkMoneyShape(params);
  const windowSeconds = asInteger(params['window_seconds'], 'window_seconds');
  if (windowSeconds < 1) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'spend_window window must be positive', {
      type: 'spend_window',
    });
  }
  if (ctx.ledger?.consumedInWindow === undefined) {
    throw new TrailGateError(
      Codes.INTERNAL_UNAVAILABLE,
      'spend_window cannot be evaluated without a windowed ledger',
    );
  }
  const ledger = ctx.ledger;
  const consumedInWindow = ledger.consumedInWindow;
  const [consumed, reserved] = await Promise.all([
    callPort(
      () =>
        (consumedInWindow as NonNullable<Ledger['consumedInWindow']>)(
          ctx.grantId,
          budget.currency,
          windowSeconds,
          ctx.now,
        ),
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
  if ((consumed ?? 0) + reserved + requested > budget.amount) {
    throw new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'spend_window would be exceeded', {
      type: 'spend_window',
      limit: budget,
      window_seconds: windowSeconds,
      consumed,
      reserved,
    });
  }
}

/**
 * `approval_threshold` (spec section 9.2): amounts above `limit` must carry
 * a live human approval recorded for this exact operation digest. The
 * evaluator only peeks; enforcement performs the consuming transition
 * before the handler runs so a failed execution can release the approval
 * for retry instead of burning it.
 */
async function evaluateApprovalThreshold(
  params: Record<string, unknown>,
  ctx: ConstraintContext,
): Promise<void> {
  const limit = checkMoneyShape(params);
  if (ctx.requestAmount === undefined || ctx.idempotentReplay === true) {
    return;
  }
  if (ctx.requestAmount.currency !== limit.currency) {
    throw new TrailGateError(
      Codes.CONSTRAINT_VIOLATED,
      'request amount currency does not match approval_threshold',
      { type: 'approval_threshold', limit },
    );
  }
  if (ctx.requestAmount.amount <= limit.amount) {
    return;
  }
  if (ctx.approvals === undefined || ctx.operationDigest === undefined) {
    throw new TrailGateError(
      Codes.INTERNAL_UNAVAILABLE,
      'approval_threshold cannot be evaluated without an approval store',
    );
  }
  const approvals = ctx.approvals;
  const operationDigest = ctx.operationDigest;
  const approved = await callPort(
    () =>
      (approvals as RequestApprovalChecker).peekApproved(
        ctx.grantId,
        operationDigest as string,
        ctx.now,
      ),
    'approval store is unavailable',
  );
  if (approved === undefined) {
    throw new TrailGateError(
      Codes.CONSTRAINT_APPROVAL_REQUIRED,
      'request amount exceeds approval_threshold and requires human approval',
      {
        type: 'approval_threshold',
        limit,
        amount: ctx.requestAmount,
        grant_id: ctx.grantId,
      },
    );
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
      case 'spend_window':
        await evaluateSpendWindow(params, ctx);
        break;
      case 'valid_window':
        evaluateValidWindow(params, ctx);
        break;
      case 'approval_threshold':
        await evaluateApprovalThreshold(params, ctx);
        break;
      default:
        throw new TrailGateError(Codes.CONSTRAINT_UNKNOWN_TYPE, 'unknown constraint type', {
          type: constraint.type,
        });
    }
  }
}
