import { Codes, TrailGateError } from './errors.ts';

export const PROTOCOL_VERSION = '0.1';
export const SUPPORTED_PROTOCOL_VERSIONS = [PROTOCOL_VERSION] as const;

export function negotiateProtocolVersion(siteVersions: readonly string[]): string {
  const common = siteVersions.find((version) =>
    (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version),
  );
  if (common === undefined) {
    throw new TrailGateError(Codes.DISCOVERY_UNSUPPORTED_VERSION, 'no common protocol version', {
      site: [...siteVersions],
      client: [...SUPPORTED_PROTOCOL_VERSIONS],
    });
  }
  return common;
}
