import { randomBytes } from 'node:crypto';

/** Opaque identifier: prefix + 128 bits of base64url randomness (spec section 3). */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString('base64url')}`;
}
