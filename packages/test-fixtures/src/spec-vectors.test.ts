import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const specRoot = new URL('../../../spec/', import.meta.url);
const REGISTERED_CONSTRAINT_TYPES = new Set([
  'max_amount',
  'cumulative_budget',
  'rate_limit',
  'valid_window',
  'spend_window',
]);

function loadJson(relativePath) {
  return JSON.parse(readFileSync(new URL(relativePath, specRoot), 'utf8'));
}

function sameOriginCheck(doc) {
  const origin = new URL(doc.issuer).origin;
  return Object.values(doc.endpoints ?? {}).every((url) => new URL(url).origin === origin);
}

function constraintEvaluationCheck(doc) {
  return REGISTERED_CONSTRAINT_TYPES.has(doc.type);
}

const POST_CHECKS = {
  same_origin: (doc) => sameOriginCheck(doc),
  constraint_evaluation: (doc) => constraintEvaluationCheck(doc),
};

const ajv = new Ajv2020({ allErrors: true });
const validators = new Map();
for (const file of readdirSync(new URL('schemas/', specRoot))) {
  if (!file.endsWith('.schema.json')) continue;
  const schema = loadJson(`schemas/${file}`);
  ajv.addSchema(schema);
  validators.set(schema.$id, ajv.compile(schema));
}

test('all spec schemas compile', () => {
  const expected = [
    'discovery',
    'grant-request',
    'grant',
    'constraint',
    'receipt',
    'error',
    'audit-event',
    'grant-revocation',
  ];
  for (const name of expected) {
    assert.ok(validators.has(`urn:trailgate:schemas:${name}`), `missing schema: ${name}`);
  }
});

const EXAMPLE_SCHEMAS = {
  'discovery.json': 'urn:trailgate:schemas:discovery',
  'grant-request.json': 'urn:trailgate:schemas:grant-request',
  'grant-payload.json': 'urn:trailgate:schemas:grant',
  'receipt-payload.json': 'urn:trailgate:schemas:receipt',
  'error.json': 'urn:trailgate:schemas:error',
};

for (const [file, schemaId] of Object.entries(EXAMPLE_SCHEMAS)) {
  test(`example ${file} validates`, () => {
    const doc = loadJson(`examples/${file}`);
    const validate = validators.get(schemaId);
    assert.equal(validate(doc), true, ajv.errorsText(validate?.errors));
  });
}

const vectors = loadJson('vectors/vectors.json');
for (const vectorCase of vectors.cases) {
  test(`vector ${vectorCase.id}`, () => {
    if (vectorCase.kind === 'schema') {
      const validate = validators.get(vectorCase.schema);
      assert.ok(validate, `unknown schema ${vectorCase.schema}`);
      const result = validate(vectorCase.doc);
      assert.equal(result, vectorCase.valid, ajv.errorsText(validate.errors));
      for (const check of vectorCase.post_checks ?? []) {
        const checkFn = POST_CHECKS[check.rule];
        assert.ok(checkFn, `unknown post-check rule: ${check.rule}`);
        const passed = checkFn(vectorCase.doc);
        const negative = check.expect === 'reject' || check.expect === 'deny';
        assert.equal(
          negative ? !passed : passed,
          true,
          `post-check ${check.rule} expected ${check.expect}`,
        );
      }
      return;
    }
    if (vectorCase.kind === 'decision') {
      assert.ok(['deny', 'allow'].includes(vectorCase.expect.decision));
      if (vectorCase.expect.code !== undefined) {
        assert.match(vectorCase.expect.code, /^tg\.[a-z0-9_]+(\.[a-z0-9_]+)+$/);
      }
      assert.ok(vectorCase.description.length > 0);
      return;
    }
    assert.fail(`unknown vector kind: ${vectorCase.kind}`);
  });
}
