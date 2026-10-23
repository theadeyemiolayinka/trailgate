import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from '@trailgate/core';
import { validateConsentCallback } from './consent.ts';

const EXPECTED = {
  requestId: 'req_abc',
  redirectUri: 'https://agent.example.com/callback',
  state: 'opaque-state-1',
};

function expectMalformed(err: unknown): boolean {
  return err instanceof TrailGateError && err.code === Codes.REQUEST_MALFORMED;
}

describe('validateConsentCallback', () => {
  it('accepts a well-formed callback', () => {
    validateConsentCallback(
      'https://agent.example.com/callback?request_id=req_abc&state=opaque-state-1',
      EXPECTED,
    );
  });

  it('accepts a redirect_uri that already had query params', () => {
    validateConsentCallback(
      'https://agent.example.com/callback?keep=1&request_id=req_abc&state=opaque-state-1',
      { ...EXPECTED, redirectUri: 'https://agent.example.com/callback?keep=1' },
    );
  });

  it('rejects a state mismatch', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://agent.example.com/callback?request_id=req_abc&state=wrong',
          EXPECTED,
        ),
      expectMalformed,
    );
  });

  it('rejects a missing request_id', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://agent.example.com/callback?state=opaque-state-1',
          EXPECTED,
        ),
      expectMalformed,
    );
  });

  it('rejects a mismatched request_id', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://agent.example.com/callback?request_id=req_other&state=opaque-state-1',
          EXPECTED,
        ),
      expectMalformed,
    );
  });

  it('rejects a different callback path (tampered redirect)', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://agent.example.com/other?request_id=req_abc&state=opaque-state-1',
          EXPECTED,
        ),
      expectMalformed,
    );
  });

  it('rejects a different callback host', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://evil.example.com/callback?request_id=req_abc&state=opaque-state-1',
          EXPECTED,
        ),
      expectMalformed,
    );
  });

  it('rejects unexpected state when none was registered', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'https://agent.example.com/callback?request_id=req_abc&state=unexpected',
          { requestId: 'req_abc', redirectUri: 'https://agent.example.com/callback' },
        ),
      expectMalformed,
    );
  });

  it('rejects a missing state when one was registered', () => {
    assert.throws(
      () =>
        validateConsentCallback('https://agent.example.com/callback?request_id=req_abc', EXPECTED),
      expectMalformed,
    );
  });

  it('rejects non-https callbacks', () => {
    assert.throws(
      () =>
        validateConsentCallback(
          'http://agent.example.com/callback?request_id=req_abc&state=opaque-state-1',
          { ...EXPECTED, redirectUri: 'http://agent.example.com/callback' },
        ),
      expectMalformed,
    );
  });
});
