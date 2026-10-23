import { Codes, TrailGateError } from './errors.ts';

const PERMISSION_PATTERN = /^tg\.[a-z0-9_]+(\.[a-z0-9_]+)+$/;

export function isPermissionId(value: string): boolean {
  return PERMISSION_PATTERN.test(value);
}

export function assertRequestedPermissionsKnown(
  requested: readonly string[],
  advertised: readonly string[],
): void {
  const known = new Set(advertised);
  const unknown = requested.filter((permission) => !known.has(permission));
  if (unknown.length > 0) {
    throw new TrailGateError(
      Codes.GRANT_UNKNOWN_PERMISSION,
      'requested permission is not in the site vocabulary',
      { unknown },
    );
  }
}

export function assertPermissionGranted(granted: readonly string[], required: string): void {
  if (!isPermissionId(required)) {
    throw new TrailGateError(
      Codes.REQUEST_MALFORMED,
      'required permission is not a valid identifier',
    );
  }
  if (!granted.includes(required)) {
    throw new TrailGateError(Codes.REQUEST_PERMISSION_DENIED, 'permission not granted', {
      required,
    });
  }
}
