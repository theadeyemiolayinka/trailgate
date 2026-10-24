import { readdirSync, readFileSync } from 'node:fs';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { Codes, TrailGateError } from './errors.ts';
import { EMBEDDED_SCHEMAS } from './schemas.embedded.ts';

export const SCHEMA_IDS = {
  discovery: 'urn:trailgate:schemas:discovery',
  grantRequest: 'urn:trailgate:schemas:grant-request',
  grant: 'urn:trailgate:schemas:grant',
  constraint: 'urn:trailgate:schemas:constraint',
  receipt: 'urn:trailgate:schemas:receipt',
  error: 'urn:trailgate:schemas:error',
  auditEvent: 'urn:trailgate:schemas:audit-event',
  grantRevocation: 'urn:trailgate:schemas:grant-revocation',
} as const;

export type SchemaId = (typeof SCHEMA_IDS)[keyof typeof SCHEMA_IDS];

export interface SchemaRegistry {
  validate(id: SchemaId, doc: unknown): boolean;
  errors(id: SchemaId): string;
}

function loadSpecSchemaFiles(): Map<string, Record<string, unknown>> {
  const dir = new URL('../../../spec/schemas/', import.meta.url);
  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    // Bundled single-file builds have no spec/ tree on disk; the checked-in
    // generated module (scripts/embed-schemas.mjs) carries the same schemas.
    return new Map(Object.entries(EMBEDDED_SCHEMAS));
  }
  const schemas = new Map<string, Record<string, unknown>>();
  for (const file of files) {
    if (!file.endsWith('.schema.json')) {
      continue;
    }
    const schema = JSON.parse(readFileSync(new URL(file, dir), 'utf8')) as Record<string, unknown>;
    const id = schema.$id;
    if (typeof id !== 'string') {
      throw new TrailGateError(Codes.INTERNAL_ERROR, `schema ${file} has no $id`);
    }
    schemas.set(id, schema);
  }
  return schemas;
}

export function createSchemaRegistry(
  schemas?: Map<string, Record<string, unknown>>,
): SchemaRegistry {
  const map = schemas ?? loadSpecSchemaFiles();
  const ajv = new Ajv2020({ allErrors: true });
  for (const schema of map.values()) {
    ajv.addSchema(schema);
  }
  const validators = new Map<string, ValidateFunction>();
  return {
    validate(id: SchemaId, doc: unknown): boolean {
      let validator = validators.get(id);
      if (validator === undefined) {
        const schema = map.get(id);
        if (schema === undefined) {
          throw new TrailGateError(Codes.INTERNAL_ERROR, `unknown schema id: ${id}`);
        }
        validator = ajv.compile(schema);
        validators.set(id, validator);
      }
      return validator(doc);
    },
    errors(id: SchemaId): string {
      const validator = validators.get(id);
      return ajv.errorsText(validator?.errors);
    },
  };
}

let defaultRegistry: SchemaRegistry | undefined;

export function schemaRegistry(): SchemaRegistry {
  defaultRegistry ??= createSchemaRegistry();
  return defaultRegistry;
}
