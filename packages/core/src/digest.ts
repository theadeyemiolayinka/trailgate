import { createHash } from 'node:crypto';
import { Codes, TrailGateError } from './errors.ts';
import { base64urlEncode } from './jwk.ts';

export const CONTENT_DIGEST_ALGORITHM = 'sha-256';

export function computeContentDigest(body: Uint8Array): string {
  const digest = createHash('sha256').update(body).digest();
  return `sha-256=:${digest.toString('base64')}:`;
}

export function parseContentDigest(headerValue: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const part of headerValue.split(',')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    entries.set(key, value);
  }
  return entries;
}

export function verifyContentDigest(headerValue: string | undefined, body: Uint8Array): void {
  if (headerValue === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'missing content-digest header');
  }
  const digests = parseContentDigest(headerValue);
  const expected = digests.get(CONTENT_DIGEST_ALGORITHM);
  if (expected === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'content-digest must include sha-256');
  }
  const actual = computeContentDigest(body).slice('sha-256='.length);
  if (actual !== expected) {
    throw new TrailGateError(Codes.REQUEST_BODY_DIGEST_MISMATCH, 'content-digest mismatch');
  }
}

export function requestDigestOf(signatureBase: string): string {
  const digest = createHash('sha256').update(signatureBase, 'utf8').digest();
  return base64urlEncode(digest);
}
