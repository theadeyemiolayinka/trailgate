import { Codes, TrailGateError } from './errors.ts';
import type { ResourceOwnerResolver } from './ports.ts';

export async function assertResourceAllowed(
  selectors: readonly string[],
  resourceId: string,
  owner: ResourceOwnerResolver,
  subject: string | undefined,
): Promise<void> {
  if (!selectors.includes(resourceId)) {
    throw new TrailGateError(Codes.REQUEST_RESOURCE_DENIED, 'resource outside grant scope', {
      resource: resourceId,
    });
  }
  const resourceOwner = await owner.ownerOf(resourceId);
  if (resourceOwner === undefined) {
    throw new TrailGateError(Codes.REQUEST_RESOURCE_DENIED, 'resource is unknown to this site');
  }
  if (subject !== undefined && resourceOwner !== subject) {
    throw new TrailGateError(Codes.REQUEST_RESOURCE_DENIED, 'resource belongs to another context');
  }
}
