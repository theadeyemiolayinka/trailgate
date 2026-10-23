import { Codes, TrailGateError } from './errors.ts';
import { callPort, type ResourceOwnerResolver } from './ports.ts';

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
  const resourceOwner = await callPort(
    () => owner.ownerOf(resourceId),
    'resource ownership cannot be checked',
  );
  if (resourceOwner === undefined) {
    throw new TrailGateError(Codes.REQUEST_RESOURCE_DENIED, 'resource is unknown to this site');
  }
  if (resourceOwner !== subject) {
    throw new TrailGateError(Codes.REQUEST_RESOURCE_DENIED, 'resource belongs to another context');
  }
}
