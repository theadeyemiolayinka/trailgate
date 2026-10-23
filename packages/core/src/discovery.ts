import { Codes, TrailGateError } from './errors.ts';
import { SCHEMA_IDS, schemaRegistry } from './schemas.ts';
import type { DiscoveryDocument } from './types.ts';

export const DISCOVERY_PATH = '/.well-known/trailgate';
export const KNOWN_CRITICAL_FIELDS = ['critical', 'version', 'protocol_versions'] as const;

export interface DiscoveryValidationOptions {
  expectedOrigin: string;
  supportedProtocolVersions: string[];
  knownCriticalFields?: readonly string[];
}

export function validateDiscoveryDocument(
  doc: unknown,
  options: DiscoveryValidationOptions,
): DiscoveryDocument {
  if (!schemaRegistry().validate(SCHEMA_IDS.discovery, doc)) {
    throw new TrailGateError(
      Codes.DISCOVERY_INVALID,
      'discovery document failed schema validation',
      {
        schema: schemaRegistry().errors(SCHEMA_IDS.discovery),
      },
    );
  }
  const typed = doc as DiscoveryDocument;
  let expected: URL;
  try {
    expected = new URL(options.expectedOrigin);
  } catch {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'expected origin is not a valid url');
  }
  if (expected.protocol !== 'https:') {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'expected origin must use https');
  }
  let issuer: URL;
  try {
    issuer = new URL(typed.issuer);
  } catch {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'issuer is not a valid url');
  }
  if (issuer.origin !== expected.origin) {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'issuer does not match document origin');
  }
  for (const [name, url] of Object.entries(typed.endpoints)) {
    let endpoint: URL;
    try {
      endpoint = new URL(url);
    } catch {
      throw new TrailGateError(Codes.DISCOVERY_INVALID, `endpoint ${name} is not a valid url`);
    }
    if (endpoint.origin !== expected.origin) {
      throw new TrailGateError(
        Codes.DISCOVERY_INVALID,
        `endpoint ${name} crosses the document origin`,
      );
    }
  }
  const known = new Set(options.knownCriticalFields ?? KNOWN_CRITICAL_FIELDS);
  for (const field of typed.critical ?? []) {
    if (!known.has(field)) {
      throw new TrailGateError(Codes.DISCOVERY_INVALID, `unrecognized critical field: ${field}`);
    }
  }
  if (!typed.protocol_versions.some((v) => options.supportedProtocolVersions.includes(v))) {
    throw new TrailGateError(Codes.DISCOVERY_UNSUPPORTED_VERSION, 'no common protocol version', {
      site: typed.protocol_versions,
      client: options.supportedProtocolVersions,
    });
  }
  return typed;
}

export function parseDiscoveryDocument(
  text: string,
  options: DiscoveryValidationOptions,
): DiscoveryDocument {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new TrailGateError(Codes.DISCOVERY_INVALID, 'discovery document is not valid json');
  }
  return validateDiscoveryDocument(doc, options);
}
