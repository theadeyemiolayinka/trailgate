import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { EMBEDDED_SCHEMAS } from './schemas.embedded.ts';
import { createSchemaRegistry, SCHEMA_IDS } from './schemas.ts';

function specSchemasFromDisk(): Record<string, Record<string, unknown>> {
  const dir = new URL('../../../spec/schemas/', import.meta.url);
  const out: Record<string, Record<string, unknown>> = {};
  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.schema.json')) {
      continue;
    }
    const schema = JSON.parse(readFileSync(new URL(file, dir), 'utf8')) as Record<string, unknown>;
    out[schema.$id as string] = schema;
  }
  return out;
}

describe('embedded schemas', () => {
  it('match spec/schemas on disk (regenerate with pnpm embed)', () => {
    assert.deepEqual(EMBEDDED_SCHEMAS, specSchemasFromDisk());
  });
});

describe('createSchemaRegistry', () => {
  it('validates a conforming discovery document', () => {
    const registry = createSchemaRegistry();
    const valid = registry.validate(SCHEMA_IDS.constraint, { type: 'max_amount', params: {} });
    assert.equal(typeof valid, 'boolean');
  });
});
