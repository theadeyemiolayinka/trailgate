import { createPrivateKey, type JsonWebKey, type KeyObject, sign, verify } from 'node:crypto';
import { Codes, TrailGateError } from './errors.ts';
import { jwkToPublicKey, signatureAlgorithmFor } from './jwk.ts';
import {
  parseSignatureField,
  parseSignatureInput,
  type SfItem,
  type SfSignatureEntry,
  type SfValue,
  serializeSignatureParams,
} from './structured-fields.ts';
import type { Jwk } from './types.ts';

export const SIGNATURE_LABEL = 'tg';
export const SIGNATURE_TAG = 'trailgate';
export const MAX_SIGNATURE_WINDOW_SECONDS = 300;
export const MAX_CLOCK_TOLERANCE_SECONDS = 120;
export const MIN_NONCE_LENGTH = 22;

export const REQUIRED_COVERED_COMPONENTS = [
  '@method',
  '@authority',
  '@path',
  '@query',
  'content-digest',
  'trailgate-grant',
  'idempotency-key',
] as const;

export const SUPPORTED_SIGNATURE_ALGORITHMS = ['ed25519', 'ecdsa-p256-sha256'] as const;
export type SignatureAlgorithm = (typeof SUPPORTED_SIGNATURE_ALGORITHMS)[number];

export interface RequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[]>;
}

export interface ParsedSignatureInput {
  components: string[];
  params: {
    created: number;
    expires: number;
    nonce: string;
    keyid: string;
    alg: SignatureAlgorithm;
    tag: string;
  };
  entry: SfSignatureEntry;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (value === undefined) {
    return undefined;
  }
  return Array.isArray(value) ? value.join(', ') : value;
}

export function getHeader(req: RequestLike, name: string): string | undefined {
  return headerValue(req.headers, name);
}

function derivedComponentValue(req: RequestLike, url: URL, name: string): string {
  switch (name) {
    case '@method':
      return req.method.toUpperCase();
    case '@authority':
      return url.host.toLowerCase();
    case '@path':
      return url.pathname === '' ? '/' : url.pathname;
    case '@query':
      return url.search === '' ? '?' : url.search;
    case '@target-uri':
      return req.url;
    case '@scheme':
      return url.protocol.replace(':', '');
    default:
      throw new TrailGateError(Codes.REQUEST_MALFORMED, `unsupported derived component: ${name}`);
  }
}

export function componentIdentifier(item: SfItem): string {
  if (typeof item.value !== 'string') {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'covered component must be a string');
  }
  if (Object.keys(item.params).length > 0) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      'component parameters are not supported in this profile',
    );
  }
  return item.value;
}

function componentValue(req: RequestLike, url: URL, identifier: string): string {
  if (identifier.startsWith('@')) {
    return derivedComponentValue(req, url, identifier);
  }
  const value = headerValue(req.headers, identifier);
  if (value === undefined) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      `covered header field missing: ${identifier}`,
    );
  }
  return value.trim();
}

export function buildSignatureBase(
  req: RequestLike,
  components: string[],
  signatureParams: SfSignatureEntry,
): string {
  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request url is not a valid absolute url');
  }
  const lines = components.map(
    (identifier) => `"${identifier}": ${componentValue(req, url, identifier)}`,
  );
  lines.push(`"@signature-params": ${serializeSignatureParams(signatureParams)}`);
  return lines.join('\n');
}

function requireProfileParam(
  params: Record<string, SfValue>,
  name: string,
  kind: 'string' | 'integer',
): SfValue {
  const value = params[name];
  const ok =
    value !== undefined &&
    (kind === 'string'
      ? typeof value === 'string'
      : typeof value === 'number' && Number.isInteger(value));
  if (!ok) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      `signature parameter ${name} is missing or has the wrong type`,
    );
  }
  return value;
}

export function parseTgSignatureInput(headerValue: string): ParsedSignatureInput {
  const entries = parseSignatureInput(headerValue);
  const entry = entries.get(SIGNATURE_LABEL);
  if (entry === undefined) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      `missing signature entry: ${SIGNATURE_LABEL}`,
    );
  }
  const components = entry.components.map(componentIdentifier);
  if (
    components.length !== REQUIRED_COVERED_COMPONENTS.length ||
    !REQUIRED_COVERED_COMPONENTS.every((name, index) => components[index] === name)
  ) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      'covered components do not match the required profile',
    );
  }
  const created = requireProfileParam(entry.params, 'created', 'integer') as number;
  const expires = requireProfileParam(entry.params, 'expires', 'integer') as number;
  const nonce = requireProfileParam(entry.params, 'nonce', 'string') as string;
  const keyid = requireProfileParam(entry.params, 'keyid', 'string') as string;
  const algRaw = requireProfileParam(entry.params, 'alg', 'string') as string;
  const tag = requireProfileParam(entry.params, 'tag', 'string') as string;
  if (!SUPPORTED_SIGNATURE_ALGORITHMS.includes(algRaw as SignatureAlgorithm)) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      `unsupported signature alg: ${algRaw}`,
    );
  }
  if (tag !== SIGNATURE_TAG) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, `unexpected signature tag: ${tag}`);
  }
  return {
    components,
    params: {
      created,
      expires,
      nonce,
      keyid,
      alg: algRaw as SignatureAlgorithm,
      tag,
    },
    entry,
  };
}

export function checkSignatureWindow(
  created: number,
  expires: number,
  now: number,
  toleranceSeconds: number,
): void {
  if (toleranceSeconds > MAX_CLOCK_TOLERANCE_SECONDS) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'clock tolerance exceeds the allowed maximum');
  }
  const window = expires - created;
  if (window <= 0 || window > MAX_SIGNATURE_WINDOW_SECONDS) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      'signature window outside the allowed range',
    );
  }
  if (created - toleranceSeconds > now) {
    throw new TrailGateError(Codes.REQUEST_EXPIRED, 'signature created in the future');
  }
  if (expires + toleranceSeconds < now) {
    throw new TrailGateError(Codes.REQUEST_EXPIRED, 'signature expired');
  }
}

export function checkNonceShape(nonce: string): void {
  if (nonce.length < MIN_NONCE_LENGTH) {
    throw new TrailGateError(Codes.REQUEST_SIGNATURE_INVALID, 'nonce below minimum entropy');
  }
}

export function verifySignatureBytes(
  alg: SignatureAlgorithm,
  publicKey: KeyObject,
  signature: Uint8Array,
  signatureBase: string,
): boolean {
  if (alg === 'ed25519') {
    return verify(null, Buffer.from(signatureBase, 'utf8'), publicKey, Buffer.from(signature));
  }
  return verify(
    'sha256',
    Buffer.from(signatureBase, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature),
  );
}

export function getSignatureBytes(headerValue: string, label = SIGNATURE_LABEL): Uint8Array {
  const entries = parseSignatureField(headerValue);
  const bytes = entries.get(label);
  if (bytes === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `missing signature for label: ${label}`);
  }
  return bytes;
}

export interface SignRequestOptions {
  privateJwk: Jwk;
  keyid: string;
  nonce: string;
  created?: number;
  expires?: number;
  grant: string;
  idempotencyKey: string;
  body?: Uint8Array;
}

export async function signRequest(
  req: { method: string; url: string; body?: Uint8Array },
  options: SignRequestOptions,
): Promise<Record<string, string>> {
  const { computeContentDigest } = await import('./digest.ts');
  const alg = signatureAlgorithmFor(options.privateJwk);
  if (alg === undefined) {
    throw new TrailGateError(Codes.INTERNAL_ERROR, 'unsupported key type for signing');
  }
  const now = Math.floor(Date.now() / 1000);
  const created = options.created ?? now;
  const expires = options.expires ?? created + 60;
  const body = options.body ?? req.body ?? new Uint8Array();
  const headers: Record<string, string> = {
    'content-digest': computeContentDigest(body),
    'trailgate-grant': options.grant,
    'idempotency-key': options.idempotencyKey,
  };
  const entry: SfSignatureEntry = {
    components: REQUIRED_COVERED_COMPONENTS.map((name) => ({ value: name, params: {} })),
    params: {
      created,
      expires,
      nonce: options.nonce,
      keyid: options.keyid,
      alg,
      tag: SIGNATURE_TAG,
    },
  };
  const base = buildSignatureBase(
    { method: req.method, url: req.url, headers },
    entry.components.map(componentIdentifier),
    entry,
  );
  const key = createPrivateKey({ key: options.privateJwk as JsonWebKey, format: 'jwk' });
  let signature: Buffer;
  if (alg === 'ed25519') {
    signature = sign(null, Buffer.from(base, 'utf8'), key);
  } else {
    signature = sign('sha256', Buffer.from(base, 'utf8'), {
      key,
      dsaEncoding: 'ieee-p1363',
    });
  }
  headers['signature-input'] = `tg=${serializeSignatureParams(entry)}`;
  headers['signature'] = `tg=:${signature.toString('base64')}:`;
  return headers;
}

export function publicKeyFromJwk(jwk: Jwk): KeyObject {
  return jwkToPublicKey(jwk);
}
