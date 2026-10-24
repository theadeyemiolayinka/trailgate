import type { DiscoveryDocument } from '@trailgate/core';
import {
  DISCOVERY_SIGNATURE_HEADER,
  signDiscoveryBody,
  validateDiscoveryDocument,
} from '@trailgate/core';
import type { ResolvedServerConfig } from './config.ts';
import type { HostResponse } from './types.ts';

/**
 * Builds the discovery document served at `GET /.well-known/trailgate`
 * (spec section 5). The result is re-validated against the schema and the
 * same-origin rules before it is returned, so a misconfigured server fails
 * at startup or first read rather than publishing an invalid document.
 */
export function buildDiscoveryDocument(config: ResolvedServerConfig): DiscoveryDocument {
  const endpoint = (path: string): string => new URL(path, config.issuer).toString();
  const doc: DiscoveryDocument = {
    version: '0.1',
    protocol_versions: [...config.supportedProtocolVersions],
    issuer: config.issuer,
    endpoints: {
      grant_request: endpoint(config.paths.grantRequest),
      grant_redemption: endpoint(config.paths.grantRedemption),
      grant_status: endpoint(config.paths.grantStatus),
      grant_revocation: endpoint(config.paths.grantRevocation),
      action_status: endpoint(config.paths.actionStatus),
    },
    signing_keys: { keys: config.signingKeys.map((key) => key.publicJwk) },
    permissions: [...config.permissions],
    constraint_types: [...config.constraintTypes],
    ...(Object.keys(config.capabilities).length > 0
      ? { capabilities: { ...config.capabilities } }
      : {}),
    ...(config.actions.size > 0
      ? { actions: [...config.actions.values()].sort((a, b) => a.id.localeCompare(b.id)) }
      : {}),
    ...config.discoveryExtensions,
  };
  return validateDiscoveryDocument(doc, {
    expectedOrigin: config.issuer,
    supportedProtocolVersions: [...config.supportedProtocolVersions],
  });
}

/**
 * `GET /.well-known/trailgate` response (spec sections 5 and 5.5). The body
 * is pre-serialized so `trailgate-discovery-signature` covers the exact
 * bytes on the wire; hosts MUST send `body` verbatim. One detached JWS per
 * configured signing key, comma-joined: while an outgoing key remains
 * configured during rotation it still endorses the document for agents
 * that pinned it.
 */
export async function buildDiscoveryResponse(config: ResolvedServerConfig): Promise<HostResponse> {
  const body = JSON.stringify(buildDiscoveryDocument(config));
  const signatures = await Promise.all(
    config.signingKeys.map((key) => signDiscoveryBody(body, key)),
  );
  return {
    status: 200,
    headers: {
      'content-type': 'application/json',
      [DISCOVERY_SIGNATURE_HEADER]: signatures.join(','),
    },
    body,
  };
}
