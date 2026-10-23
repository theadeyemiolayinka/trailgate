import assert from 'node:assert/strict';
import { test } from 'node:test';
import { packageName } from './index.ts';

test('exports the package name', () => {
  assert.equal(packageName, '@trailgate/mcp-adapter');
});
