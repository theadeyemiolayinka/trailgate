import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, isTrailGateError, TrailGateError, toErrorResponse } from './errors.ts';

describe('TrailGateError', () => {
  it('carries a stable protocol code and optional detail', () => {
    const err = new TrailGateError(Codes.REQUEST_REPLAY_DETECTED, 'nonce already seen', {
      grant: 'grt_1',
    });
    assert.equal(err.code, 'tg.request.replay_detected');
    assert.deepEqual(err.detail, { grant: 'grt_1' });
    assert.equal(err.httpStatus, 403);
    assert.ok(err instanceof Error);
  });

  it('is detectable via isTrailGateError', () => {
    assert.equal(isTrailGateError(new TrailGateError(Codes.GRANT_EXPIRED, 'x')), true);
    assert.equal(isTrailGateError(new Error('x')), false);
  });
});

describe('toErrorResponse', () => {
  it('serializes to the registry envelope', () => {
    const body = toErrorResponse(new TrailGateError(Codes.GRANT_EXPIRED, 'grant has expired'));
    assert.deepEqual(body, {
      error: { code: 'tg.grant.expired', message: 'grant has expired' },
    });
  });

  it('includes detail when present', () => {
    const body = toErrorResponse(
      new TrailGateError(Codes.CONSTRAINT_VIOLATED, 'budget exceeded', {
        type: 'cumulative_budget',
      }),
    );
    assert.equal(body.error.detail?.['type'], 'cumulative_budget');
  });

  it('maps unknown errors to a generic internal error without leaking internals', () => {
    const body = toErrorResponse(new TypeError('secret internals'));
    assert.equal(body.error.code, Codes.INTERNAL_ERROR);
    assert.equal(body.error.message, 'internal error');
    assert.equal(body.error.detail, undefined);
  });
});
