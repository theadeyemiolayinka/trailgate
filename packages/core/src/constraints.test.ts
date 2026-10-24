import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { type ConstraintContext, evaluateConstraints } from './constraints.ts';
import { Codes, TrailGateError } from './errors.ts';
import type { Ledger, RateLimiter } from './ports.ts';
import type { Constraint } from './types.ts';

const NOW = 1700000000;
const BASE: ConstraintContext = { grantId: 'grt_1', now: NOW };

async function expectCode(code: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

const ledger = (consumed: number, reserved: number): Ledger => ({
  consumedMinorUnits: async () => consumed,
  reservedMinorUnits: async () => reserved,
});

const limiter = (count: number): RateLimiter => ({
  countInWindow: async () => count,
});

describe('evaluateConstraints', () => {
  it('accepts an empty constraint list', async () => {
    await evaluateConstraints([], BASE);
  });

  it('enforces max_amount', async () => {
    const c: Constraint = { type: 'max_amount', params: { amount: 5000, currency: 'USD' } };
    await evaluateConstraints([c], { ...BASE, requestAmount: { amount: 5000, currency: 'USD' } });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], { ...BASE, requestAmount: { amount: 5001, currency: 'USD' } }),
    );
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], { ...BASE, requestAmount: { amount: 100, currency: 'EUR' } }),
    );
    await evaluateConstraints([c], BASE);
  });

  it('enforces cumulative_budget against ledger totals', async () => {
    const c: Constraint = { type: 'cumulative_budget', params: { amount: 20000, currency: 'USD' } };
    await evaluateConstraints([c], {
      ...BASE,
      ledger: ledger(15000, 4000),
      requestAmount: { amount: 1000, currency: 'USD' },
    });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], {
        ...BASE,
        ledger: ledger(15000, 4000),
        requestAmount: { amount: 1001, currency: 'USD' },
      }),
    );
  });

  it('fails closed when a ledger is unavailable', async () => {
    const c: Constraint = { type: 'cumulative_budget', params: { amount: 20000, currency: 'USD' } };
    await expectCode(Codes.INTERNAL_UNAVAILABLE, () => evaluateConstraints([c], BASE));
  });

  it('enforces spend_window against windowed ledger totals', async () => {
    const c: Constraint = {
      type: 'spend_window',
      params: { amount: 10000, currency: 'USD', window_seconds: 86_400 },
    };
    const windowedLedger: Ledger = {
      ...ledger(0, 500),
      consumedInWindow: async () => 9000,
    };
    await evaluateConstraints([c], {
      ...BASE,
      ledger: windowedLedger,
      requestAmount: { amount: 500, currency: 'USD' },
    });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], {
        ...BASE,
        ledger: windowedLedger,
        requestAmount: { amount: 501, currency: 'USD' },
      }),
    );
  });

  it('fails closed for spend_window without a windowed ledger', async () => {
    const c: Constraint = {
      type: 'spend_window',
      params: { amount: 10000, currency: 'USD', window_seconds: 86_400 },
    };
    await expectCode(Codes.INTERNAL_UNAVAILABLE, () => evaluateConstraints([c], BASE));
    await expectCode(Codes.INTERNAL_UNAVAILABLE, () =>
      evaluateConstraints([c], { ...BASE, ledger: ledger(0, 0) }),
    );
  });

  it('enforces rate_limit', async () => {
    const c: Constraint = {
      type: 'rate_limit',
      params: { max_requests: 60, window_seconds: 3600 },
    };
    await evaluateConstraints([c], { ...BASE, rateLimiter: limiter(59) });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], { ...BASE, rateLimiter: limiter(60) }),
    );
    await expectCode(Codes.INTERNAL_UNAVAILABLE, () => evaluateConstraints([c], BASE));
  });

  it('enforces valid_window', async () => {
    const c: Constraint = {
      type: 'valid_window',
      params: { not_before: NOW - 10, not_after: NOW + 10 },
    };
    await evaluateConstraints([c], BASE);
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], { ...BASE, now: NOW + 11 }),
    );
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints([c], { ...BASE, now: NOW - 11 }),
    );
  });

  it('denies unknown constraint types', async () => {
    const c = { type: 'merchant_only', params: {} } as unknown as Constraint;
    await expectCode(Codes.CONSTRAINT_UNKNOWN_TYPE, () => evaluateConstraints([c], BASE));
  });

  it('denies malformed constraint params', async () => {
    const c = { type: 'max_amount', params: { amount: 12.5, currency: 'usd' } } as Constraint;
    await expectCode(Codes.CONSTRAINT_VIOLATED, () => evaluateConstraints([c], BASE));
  });

  it('combines conjunctively', async () => {
    const constraints: Constraint[] = [
      { type: 'max_amount', params: { amount: 5000, currency: 'USD' } },
      { type: 'rate_limit', params: { max_requests: 10, window_seconds: 60 } },
    ];
    await evaluateConstraints(constraints, {
      ...BASE,
      requestAmount: { amount: 100, currency: 'USD' },
      rateLimiter: limiter(2),
    });
    await expectCode(Codes.CONSTRAINT_VIOLATED, () =>
      evaluateConstraints(constraints, {
        ...BASE,
        requestAmount: { amount: 6000, currency: 'USD' },
        rateLimiter: limiter(2),
      }),
    );
  });
});
