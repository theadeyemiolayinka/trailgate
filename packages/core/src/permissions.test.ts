import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Codes, TrailGateError } from './errors.ts';
import {
  assertPermissionGranted,
  assertRequestedPermissionsKnown,
  isPermissionId,
} from './permissions.ts';

function expectCode(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TrailGateError);
    assert.equal((err as TrailGateError).code, code);
    return;
  }
  assert.fail(`expected ${code}`);
}

describe('isPermissionId', () => {
  it('accepts the tg.<domain>.<action> shape', () => {
    assert.equal(isPermissionId('tg.cart.read'), true);
    assert.equal(isPermissionId('tg.wallet.charge_v2'), true);
  });

  it('rejects malformed identifiers', () => {
    assert.equal(isPermissionId('cart.read'), false);
    assert.equal(isPermissionId('tg..read'), false);
    assert.equal(isPermissionId('TG.cart.read'), false);
    assert.equal(isPermissionId(''), false);
  });
});

describe('assertRequestedPermissionsKnown', () => {
  it('passes when all requested permissions are advertised', () => {
    assertRequestedPermissionsKnown(['tg.cart.read'], ['tg.cart.read', 'tg.order.create']);
  });

  it('rejects unknown permission requests', () => {
    expectCode(Codes.GRANT_UNKNOWN_PERMISSION, () =>
      assertRequestedPermissionsKnown(['tg.admin.delete'], ['tg.cart.read']),
    );
  });
});

describe('assertPermissionGranted', () => {
  it('passes when the permission is granted', () => {
    assertPermissionGranted(['tg.cart.read'], 'tg.cart.read');
  });

  it('denies missing permissions exactly', () => {
    expectCode(Codes.REQUEST_PERMISSION_DENIED, () =>
      assertPermissionGranted(['tg.cart.read'], 'tg.order.create'),
    );
    expectCode(Codes.REQUEST_PERMISSION_DENIED, () =>
      assertPermissionGranted(['tg.cart.readall'], 'tg.cart.read'),
    );
  });
});
