import {
  createInMemoryAgentKeyDirectory,
  createInMemoryApprovalStore,
  createInMemoryAuditSink,
  createInMemoryGrantRegistry,
  createInMemoryGrantRequestStore,
  createInMemoryIdempotencyStore,
  createInMemoryLedger,
  createInMemoryNonceStore,
  createInMemoryRateLimiter,
} from '@trailgate/server';
import { runPortContractSuite } from './port-contracts.ts';

// The in-memory reference stores must satisfy the same contract a production
// store must honor; the suite then runs unchanged against ExampleShop's
// SQLite implementations in apps/example-shop.
runPortContractSuite('in-memory reference stores', () => ({
  grantRequests: createInMemoryGrantRequestStore(),
  agentKeys: createInMemoryAgentKeyDirectory(),
  grants: createInMemoryGrantRegistry(),
  nonces: createInMemoryNonceStore(),
  idempotency: createInMemoryIdempotencyStore(),
  ledger: createInMemoryLedger(() => Math.floor(Date.now() / 1000)),
  rateLimiter: createInMemoryRateLimiter(),
  audit: createInMemoryAuditSink(),
  approvals: createInMemoryApprovalStore(),
}));
