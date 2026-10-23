import { randomBytes } from 'node:crypto';

/** Opaque identifier with 128 bits of entropy, per spec section 3. */
export function randomId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString('base64url')}`;
}
