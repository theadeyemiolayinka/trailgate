import type { ErrorCode, ErrorResponse } from '@trailgate/core';
import { Codes, SCHEMA_IDS, schemaRegistry, TrailGateError } from '@trailgate/core';

/**
 * Parses a response body as the spec section 16 error envelope
 * (`spec/schemas/error.schema.json`). Returns the parsed `error` member or
 * undefined when the body is not a well-formed envelope. Callers branch on
 * `code`, never on `message` (spec/errors.md).
 */
export function parseErrorEnvelope(body: unknown): ErrorResponse['error'] | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return undefined;
  }
  if (!schemaRegistry().validate(SCHEMA_IDS.error, body)) {
    return undefined;
  }
  return (body as ErrorResponse).error;
}

export function parseJsonBytes(body: Uint8Array): unknown {
  if (body.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    return undefined;
  }
}

/**
 * Maps a non-success protocol response to a `TrailGateError`. A well-formed
 * envelope keeps its registered code; anything else is `tg.internal.error`
 * because the response cannot be trusted to a finer meaning. HTTP status is
 * advisory (spec section 16); the code is authoritative.
 */
export function errorFromResponse(status: number, body: Uint8Array): TrailGateError {
  const envelope = parseErrorEnvelope(parseJsonBytes(body));
  if (envelope !== undefined) {
    return new TrailGateError(envelope.code as ErrorCode, envelope.message, envelope.detail);
  }
  return new TrailGateError(Codes.INTERNAL_ERROR, `unexpected response status ${status}`);
}
