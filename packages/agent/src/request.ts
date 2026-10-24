import { randomBytes } from 'node:crypto';
import type { Clock, ReceiptPayload } from '@trailgate/core';
import {
  buildSignatureBase,
  Codes,
  computeContentDigest,
  MAX_SIGNATURE_WINDOW_SECONDS,
  REQUIRED_COVERED_COMPONENTS,
  requestDigestOf,
  type SfSignatureEntry,
  SIGNATURE_TAG,
  serializeSignatureParams,
  systemClock,
  TrailGateError,
} from '@trailgate/core';
import type { SiteContext } from './discovery.ts';
import { resolveSiteUrl, siteKeyResolver } from './discovery.ts';
import { parseErrorEnvelope, parseJsonBytes } from './errors.ts';
import type { AgentSigner } from './keys.ts';
import type { ReceiptOutcome } from './receipts.ts';
import { verifyReceiptHeader } from './receipts.ts';
import type { StoredGrantRecord } from './store.ts';
import type { AgentHttpResponse, HttpTransport } from './transport.ts';
import { fetchTransport } from './transport.ts';

export interface SignRequestInput {
  method: string;
  /** Path on the site origin or a same-origin absolute URL. */
  url: string;
  body?: Uint8Array;
}

export interface SignOptions {
  created?: number;
  expires?: number;
  nonce?: string;
  idempotencyKey?: string;
}

export interface SignedHeaders {
  headers: Record<string, string>;
  /** The exact RFC 9421 signature base that was signed (receipt binding). */
  signatureBase: string;
}

function bodyBytes(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) {
    return new Uint8Array();
  }
  if (typeof body === 'string') {
    return new TextEncoder().encode(body);
  }
  return body;
}

/**
 * Builds the spec section 11.2 signature profile headers for a protected
 * request. The signature base is assembled with the same primitives as
 * `signRequest` in `@trailgate/core`, but the cryptographic step goes
 * through the `AgentSigner` port so non-exportable key providers work.
 */
export async function buildProtectedRequestHeaders(
  req: SignRequestInput,
  grantToken: string,
  signer: AgentSigner,
  options: SignOptions = {},
  clock: Clock = systemClock,
): Promise<SignedHeaders> {
  const now = clock.now();
  const created = options.created ?? now;
  const expires = options.expires ?? created + 60;
  if (expires - created <= 0 || expires - created > MAX_SIGNATURE_WINDOW_SECONDS) {
    throw new TrailGateError(
      Codes.REQUEST_SIGNATURE_INVALID,
      'signature window outside the allowed range',
    );
  }
  const body = bodyBytes(req.body);
  const nonce = options.nonce ?? randomBytes(32).toString('base64url');
  const idempotencyKey = options.idempotencyKey ?? `idem_${randomBytes(16).toString('base64url')}`;
  const headers: Record<string, string> = {
    'content-digest': computeContentDigest(body),
    'trailgate-grant': grantToken,
    'idempotency-key': idempotencyKey,
  };
  const entry: SfSignatureEntry = {
    components: REQUIRED_COVERED_COMPONENTS.map((name) => ({ value: name, params: {} })),
    params: {
      created,
      expires,
      nonce,
      keyid: signer.jkt,
      alg: signer.algorithm,
      tag: SIGNATURE_TAG,
    },
  };
  const signatureBase = buildSignatureBase(
    { method: req.method, url: req.url, headers },
    entry.components.map((item) => item.value as string),
    entry,
  );
  const signature = await signer.sign(signatureBase);
  headers['signature-input'] = `tg=${serializeSignatureParams(entry)}`;
  headers['signature'] = `tg=:${Buffer.from(signature).toString('base64')}:`;
  return { headers, signatureBase };
}

export interface ProtectedRequestOptions {
  method: string;
  /** Path (recommended) or absolute URL. Must resolve inside the site origin. */
  target: string;
  body?: Uint8Array | string;
  /** Supply to dedupe a logical operation across retries (spec section 11.4). */
  idempotencyKey?: string;
  /** Test hook for deterministic nonces. */
  nonce?: string;
  /** Signature window in seconds; default 60, maximum 300 (spec section 11.2). */
  signatureTtlSeconds?: number;
}

/**
 * The structured result of a protected request. `error` carries the parsed
 * error envelope when the site answered a TrailGate error (branch on
 * `code`, never `message`). `receipt` reports verification of the
 * `trailgate-receipt` header when present (spec section 14.1; see
 * `receipts.ts`). HTTP-level denials are data, not exceptions.
 */
export interface ProtectedResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  error?: { code: string; message: string; detail?: Record<string, unknown> };
  receipt?: ReceiptOutcome;
}

/** Parses the JSON body, or undefined when absent or invalid. */
export function responseJson(res: ProtectedResponse): unknown {
  return parseJsonBytes(res.body);
}

export interface ExecuteProtectedDeps {
  transport?: HttpTransport;
  clock?: Clock;
}

/**
 * Signs and sends a protected request (spec section 11), then parses the
 * response: error envelope into `error`, `trailgate-receipt` header into a
 * verification outcome bound to the exact signature base sent.
 *
 * `target` is pinned to `site.origin` by `resolveSiteUrl`; there is no
 * code path that signs or sends a request to another origin.
 */
export async function executeProtectedRequest(
  site: SiteContext,
  grant: StoredGrantRecord,
  signer: AgentSigner,
  input: ProtectedRequestOptions,
  deps: ExecuteProtectedDeps = {},
): Promise<ProtectedResponse> {
  if (signer.jkt !== grant.keyId) {
    throw new TrailGateError(
      Codes.REQUEST_KEY_MISMATCH,
      'signer is not the key the grant is bound to',
    );
  }
  const transport = deps.transport ?? fetchTransport();
  const clock = deps.clock ?? systemClock;
  const url = resolveSiteUrl(site, input.target);
  const body = bodyBytes(input.body);
  const signOptions: SignOptions = {};
  if (input.nonce !== undefined) {
    signOptions.nonce = input.nonce;
  }
  if (input.idempotencyKey !== undefined) {
    signOptions.idempotencyKey = input.idempotencyKey;
  }
  if (input.signatureTtlSeconds !== undefined) {
    signOptions.expires = clock.now() + input.signatureTtlSeconds;
  }
  const signed = await buildProtectedRequestHeaders(
    { method: input.method, url, body },
    grant.token,
    signer,
    signOptions,
    clock,
  );
  const res: AgentHttpResponse = await transport.send({
    method: input.method,
    url,
    headers: signed.headers,
    body,
  });
  const out: ProtectedResponse = { status: res.status, headers: res.headers, body: res.body };
  const parsed = parseJsonBytes(res.body);
  const envelope = parseErrorEnvelope(parsed);
  if (envelope !== undefined) {
    out.error = envelope;
  }
  const receipt = await verifyReceiptHeader(res.headers, {
    resolveSiteKey: siteKeyResolver(site.document),
    issuer: site.issuer,
    audience: site.origin,
    expectedGrantId: grant.jti,
    expectedRequestDigest: requestDigestOf(signed.signatureBase),
  });
  if (receipt !== undefined) {
    out.receipt = receipt;
  }
  return out;
}

export type { ReceiptOutcome, ReceiptPayload };
