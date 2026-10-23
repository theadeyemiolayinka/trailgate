import { Codes, TrailGateError } from '@trailgate/core';

export interface ConsentCallbackExpectation {
  /** The `request_id` the callback must carry. */
  requestId: string;
  /** The exact `redirect_uri` registered in the grant request. */
  redirectUri: string;
  /** The `state` value registered in the grant request, if any. */
  state?: string;
}

function fail(message: string): never {
  throw new TrailGateError(Codes.REQUEST_MALFORMED, message);
}

/**
 * Validates the post-consent redirect (spec section 10.3). The site is
 * required to redirect to exactly the registered `redirect_uri` with
 * `request_id` and `state` as added query parameters; this check enforces
 * all three constraints and treats everything else as a protocol violation.
 *
 * The `state` equality check is the CSRF binding for the redirect path.
 */
export function validateConsentCallback(
  callbackUrl: string,
  expected: ConsentCallbackExpectation,
): void {
  let url: URL;
  try {
    url = new URL(callbackUrl);
  } catch {
    fail('consent callback is not a valid url');
  }
  if (url.protocol !== 'https:') {
    fail('consent callback is not an https url');
  }

  const params = url.searchParams;
  const requestId = params.get('request_id');
  if (requestId === null || requestId !== expected.requestId) {
    fail('consent callback carries a mismatched request_id');
  }
  const state = params.get('state');
  if (expected.state !== undefined) {
    if (state !== expected.state) {
      fail('consent callback state does not match the registered value');
    }
  } else if (state !== null) {
    fail('consent callback carries unexpected state');
  }

  // Compare the callback target to the registered redirect URI after
  // removing the two parameters the site is allowed to append (section
  // 10.3). Any other difference is a tampered or open redirect.
  params.delete('request_id');
  params.delete('state');
  const callbackBase = url.toString();
  let registeredBase: string;
  try {
    registeredBase = new URL(expected.redirectUri).toString();
  } catch {
    fail('registered redirect_uri is not a valid url');
  }
  if (callbackBase !== registeredBase) {
    fail('consent callback target differs from the registered redirect_uri');
  }
}
