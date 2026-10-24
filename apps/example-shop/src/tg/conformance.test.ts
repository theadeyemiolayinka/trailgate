import { runPortContractSuite } from '@trailgate/conformance';
import { openDatabase } from '../db/database.ts';
import {
  createAgentKeyDirectory,
  createAuditSink,
  createGrantRegistry,
  createGrantRequestStore,
  createIdempotencyStore,
  createNonceStore,
  createRateLimiter,
  createSpendingLedger,
} from './stores.ts';

// ExampleShop's SQLite port implementations against the shared contract
// suite: CAS transitions, atomic nonce and idempotency claims, atomic ledger
// reserve with spend windows (spec sections 10.4, 11.4, 12).
runPortContractSuite('example-shop sqlite stores', () => {
  const db = openDatabase(':memory:');
  return {
    grantRequests: createGrantRequestStore(db),
    agentKeys: createAgentKeyDirectory(db),
    grants: createGrantRegistry(db),
    nonces: createNonceStore(db),
    idempotency: createIdempotencyStore(db),
    ledger: createSpendingLedger(db, () => Math.floor(Date.now() / 1000)),
    rateLimiter: createRateLimiter(db),
    audit: createAuditSink(db),
  };
});
