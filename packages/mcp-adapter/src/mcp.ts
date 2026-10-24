#!/usr/bin/env node
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { PendingGrantRequest } from '@trailgate/agent';
import {
  createAgentClient,
  FileDiscoveryCache,
  FileGrantStore,
  FileKeyProvider,
  fetchTransport,
} from '@trailgate/agent';
import { serveMcpStdio } from './server.ts';
import { createTrailGateTools } from './tools.ts';

/**
 * `trailgate-mcp`: stdio MCP server exposing the TrailGate tool surface.
 *
 * State directory (`TRAILGATE_STATE_DIR`, default `.trailgate`) is the same
 * layout the `trailgate` CLI uses: keys.json (0600 private JWKs),
 * pending.json (PKCE verifiers), grants.json, discovery.json. Sharing it
 * means a grant requested by an MCP-connected agent can be inspected or
 * revoked from the CLI and vice versa.
 *
 * stdout carries JSON-RPC only; diagnostics go to stderr.
 */

const stateDir = process.env['TRAILGATE_STATE_DIR'] ?? '.trailgate';
const pendingPath = join(stateDir, 'pending.json');
const log = (line: string): void => {
  process.stderr.write(`trailgate-mcp: ${line}\n`);
};

async function loadPending(): Promise<PendingGrantRequest[]> {
  try {
    const parsed: unknown = JSON.parse(await readFile(pendingPath, 'utf8'));
    return Array.isArray(parsed) ? (parsed as PendingGrantRequest[]) : [];
  } catch {
    return [];
  }
}

async function savePending(record: PendingGrantRequest): Promise<void> {
  const all = (await loadPending()).filter((r) => r.requestId !== record.requestId);
  all.push(record);
  await mkdir(dirname(pendingPath), { recursive: true });
  const tmp = `${pendingPath}.tmp`;
  await writeFile(tmp, JSON.stringify(all), { encoding: 'utf8', mode: 0o600 });
  await rename(tmp, pendingPath);
}

async function dropPending(requestId: string): Promise<void> {
  const all = (await loadPending()).filter((r) => r.requestId !== requestId);
  await mkdir(dirname(pendingPath), { recursive: true });
  const tmp = `${pendingPath}.tmp`;
  await writeFile(tmp, JSON.stringify(all), { encoding: 'utf8', mode: 0o600 });
  await rename(tmp, pendingPath);
}

const keyProvider = new FileKeyProvider(join(stateDir, 'keys.json'));
const client = createAgentClient({
  transport: fetchTransport(),
  grantStore: new FileGrantStore(join(stateDir, 'grants.json')),
  discoveryCache: new FileDiscoveryCache(join(stateDir, 'discovery.json')),
});

const signers = await keyProvider.list();
if (signers.length === 0) {
  // First run: generate a dev-grade key so the agent can request grants
  // immediately. `trailgate keys` shows the thumbprint.
  signers.push(await keyProvider.generate('ed25519'));
  log('no agent key found; generated an ed25519 key in the state dir');
}
for (const signer of signers) {
  client.useKey(signer);
}
for (const record of await loadPending()) {
  client.restorePending(record);
}

const tools = createTrailGateTools(client);

// Persist consent sessions so `redeem` works after a restart, mirroring
// the CLI's pending.json. The verifier never leaves the state dir.
for (const tool of tools) {
  if (tool.name === 'trailgate.request') {
    const inner = tool.handler;
    tool.handler = async (args) => {
      const out = await inner(args);
      const requestId = out.structuredContent?.['requestId'];
      if (typeof requestId === 'string') {
        const record = client.exportPending(requestId);
        if (record !== undefined) {
          await savePending(record);
        }
      }
      return out;
    };
  }
  if (tool.name === 'trailgate.redeem') {
    const inner = tool.handler;
    tool.handler = async (args) => {
      const out = await inner(args);
      const requestId = args['requestId'];
      if (typeof requestId === 'string' && out.isError !== true) {
        await dropPending(requestId);
      }
      return out;
    };
  }
}

log(`serving ${tools.length} tools; state dir ${stateDir}`);
await serveMcpStdio(tools, {
  serverInfo: { name: 'trailgate-mcp', version: '0.0.0' },
  log,
});
