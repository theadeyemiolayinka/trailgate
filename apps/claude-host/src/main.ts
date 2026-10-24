#!/usr/bin/env node
import { join } from 'node:path';
/**
 * claude-host: a minimal terminal host that lets a Claude model drive the
 * TrailGate tool surface through the Anthropic messages API.
 *
 * What this is: a demonstration that an ordinary model API + the TrailGate
 * agent SDK = a working delegated-shopping agent. The model proposes tool
 * calls; every call runs through the real AgentClient, so discovery,
 * signing, grants, and constraints are enforced by the same code paths the
 * CLI and MCP server use. The model never sees keys, grant tokens, or PKCE
 * verifiers - tools return metadata only.
 *
 * Human in the loop: mutating tools (`request`, `redeem`, `fetch`,
 * `revoke`) prompt the operator for a y/N confirmation before they run,
 * and a pending consent prints the consent URL for the human to open.
 *
 * Required env:
 *   ANTHROPIC_API_KEY   - your Claude API key (never printed or logged)
 * Optional env:
 *   ANTHROPIC_MODEL     - default claude-sonnet-4-5
 *   TRAILGATE_STATE_DIR - shared with the CLI/MCP server (default .trailgate)
 *   NODE_EXTRA_CA_CERTS - trust the ExampleShop dev CA for local HTTPS
 *
 * Usage: pnpm start "check my cart on https://localhost:3443"
 *        pnpm start              (interactive prompt loop)
 */
import { createInterface } from 'node:readline/promises';
import {
  createAgentClient,
  FileDiscoveryCache,
  FileGrantStore,
  FileKeyProvider,
  fetchTransport,
} from '@trailgate/agent';
import { createTrailGateTools } from '@trailgate/mcp-adapter';

const API_URL = 'https://api.anthropic.com/v1/messages';
const MODEL = process.env.ANTHROPIC_MODEL ?? 'claude-sonnet-4-5';
const API_KEY = process.env.ANTHROPIC_API_KEY;
const STATE_DIR = process.env.TRAILGATE_STATE_DIR ?? '.trailgate';

if (API_KEY === undefined || API_KEY === '') {
  console.error('ANTHROPIC_API_KEY is required. Set it in your environment; do not paste it here.');
  process.exit(2);
}

const rl = createInterface({ input: process.stdin, output: process.stdout });

async function confirm(line: string): Promise<boolean> {
  const answer = await rl.question(`${line} [y/N] `);
  return answer.trim().toLowerCase() === 'y';
}

const keyProvider = new FileKeyProvider(join(STATE_DIR, 'keys.json'));
const client = createAgentClient({
  transport: fetchTransport(),
  grantStore: new FileGrantStore(join(STATE_DIR, 'grants.json')),
  discoveryCache: new FileDiscoveryCache(join(STATE_DIR, 'discovery.json')),
});
const signers = await keyProvider.list();
if (signers.length === 0) {
  signers.push(await keyProvider.generate('ed25519'));
  console.error('no agent key found; generated an ed25519 key in the state dir');
}
for (const signer of signers) {
  client.useKey(signer);
}

const tools = createTrailGateTools(client, {
  // The operator approves every mutating tool call in the terminal. Consent
  // itself still happens on the site's own page; this gate only decides
  // whether the agent may take the action at all.
  beforeAction: async (toolName, args) => {
    if (toolName === 'trailgate.fetch' && String(args.method ?? 'GET') === 'GET') {
      return; // reads still gate on grant checks server-side
    }
    const allowed = await confirm(`agent wants ${toolName} ${JSON.stringify(args)}.`);
    if (!allowed) {
      throw new Error('operator denied the action');
    }
  },
});

const apiTools = tools.map((tool) => ({
  name: tool.name.replaceAll('.', '_'),
  description: tool.description,
  input_schema: tool.inputSchema,
}));
const byApiName = new Map(tools.map((tool) => [tool.name.replaceAll('.', '_'), tool]));

interface Message {
  role: 'user' | 'assistant';
  content: unknown;
}

const SYSTEM = [
  'You are operating a shopping agent with trailgate_* tools only.',
  'Discover a site with trailgate_discover before assuming it supports TrailGate.',
  'Check trailgate_actions to map the user intent to an advertised action before fetching.',
  'Never invent endpoints. Never attempt to bypass a denial. Report error codes honestly.',
  'Only call trailgate_request when the user explicitly asks to connect or expand access; pass user_authorized true then and only then.',
  'When a call is denied for missing access, tell the user what you lack and stop. Do not start a new access request on your own.',
  'If trailgate_request returns a consentUrl, relay only the link to the user and wait. Do not mention request ids, protocol internals, or the word TrailGate.',
  'Send an idempotencyKey for any mutating trailgate_fetch.',
].join(' ');

async function callApi(messages: Message[]): Promise<Record<string, unknown>> {
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY as string,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 1024,
      system: SYSTEM,
      tools: apiTools,
      messages,
    }),
  });
  const body: unknown = await res.json();
  if (!res.ok) {
    const detail =
      typeof body === 'object' && body !== null && 'error' in body
        ? JSON.stringify((body as { error: unknown }).error)
        : String(body);
    throw new Error(`anthropic api ${res.status}: ${detail}`);
  }
  return body as Record<string, unknown>;
}

async function runTask(task: string): Promise<void> {
  const messages: Message[] = [{ role: 'user', content: task }];
  for (let round = 0; round < 24; round += 1) {
    const res = await callApi(messages);
    const content = (res.content ?? []) as Record<string, unknown>[];
    messages.push({ role: 'assistant', content });
    for (const block of content) {
      if (block.type === 'text' && typeof block.text === 'string') {
        console.log(`\n${block.text}`);
      }
    }
    if (res.stop_reason !== 'tool_use') {
      return;
    }
    const results: Record<string, unknown>[] = [];
    for (const block of content) {
      if (block.type !== 'tool_use') {
        continue;
      }
      const tool = byApiName.get(String(block.name));
      const args =
        typeof block.input === 'object' && block.input !== null
          ? (block.input as Record<string, unknown>)
          : {};
      let toolResult: unknown;
      if (tool === undefined) {
        toolResult = { error: { code: 'agent.error', message: `unknown tool ${block.name}` } };
      } else {
        const out = await tool.handler(args);
        toolResult = out.structuredContent ?? { text: out.content[0]?.text ?? '' };
        const consentUrl = out.structuredContent?.consentUrl;
        if (typeof consentUrl === 'string') {
          console.log(`\nHuman approval required. Open this URL and decide:\n  ${consentUrl}\n`);
        }
      }
      results.push({
        type: 'tool_result',
        tool_use_id: block.id,
        content: JSON.stringify(toolResult),
      });
    }
    messages.push({ role: 'user', content: results });
  }
  console.error('stopped after 24 tool rounds without an answer');
}

const argTask = process.argv.slice(2).join(' ');
if (argTask !== '') {
  await runTask(argTask);
  rl.close();
} else {
  console.log('claude-host: describe a task, or "quit" to exit.');
  for (;;) {
    const task = await rl.question('\n> ');
    if (task.trim() === 'quit' || task.trim() === 'exit') {
      break;
    }
    if (task.trim() !== '') {
      await runTask(task);
    }
  }
  rl.close();
}
