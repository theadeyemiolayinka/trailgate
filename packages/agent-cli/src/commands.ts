import { join } from 'node:path';
import type { AgentClient } from '@trailgate/agent';
import {
  AgentError,
  createAgentClient,
  FileDiscoveryCache,
  FileGrantStore,
  fetchTransport,
} from '@trailgate/agent';
import { isTrailGateError } from '@trailgate/core';
import {
  dropPending,
  generateAndStoreKey,
  loadPending,
  loadSigners,
  savePending,
} from './state.ts';

export interface CliDeps {
  /** Working state directory; defaults to `.trailgate`. */
  stateDir?: string;
  /** Injectable client factory for tests and alternative transports. */
  clientFactory?: (options: { stateDir: string }) => Promise<AgentClient>;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
}

export const DEFAULT_STATE_DIR = '.trailgate';

async function defaultClientFactory(options: { stateDir: string }): Promise<AgentClient> {
  const client = createAgentClient({
    transport: fetchTransport(),
    grantStore: new FileGrantStore(join(options.stateDir, 'grants.json')),
    discoveryCache: new FileDiscoveryCache(join(options.stateDir, 'discovery.json')),
  });
  const { stateDir } = options;
  for (const signer of await loadSigners(stateDir)) {
    client.useKey(signer);
  }
  for (const record of await loadPending(stateDir)) {
    client.restorePending(record);
  }
  return client;
}

interface ParsedArgs {
  positional: string[];
  flags: Map<string, string[]>;
}

const MULTI = new Set(['permission', 'resource', 'constraint']);

function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] as string;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    let value: string;
    if (eq !== -1) {
      value = arg.slice(eq + 1);
    } else if (
      MULTI.has(name) ||
      i + 1 >= argv.length ||
      (argv[i + 1] as string).startsWith('--')
    ) {
      value = 'true';
      if (MULTI.has(name) && i + 1 < argv.length && !(argv[i + 1] as string).startsWith('--')) {
        i += 1;
        value = argv[i] as string;
      }
    } else {
      i += 1;
      value = argv[i] as string;
    }
    const list = flags.get(name) ?? [];
    list.push(value);
    flags.set(name, list);
  }
  return { positional, flags };
}

function flag(args: ParsedArgs, name: string): string | undefined {
  return args.flags.get(name)?.[0];
}

function flagAll(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) ?? [];
}

function usage(): string {
  return [
    'trailgate - developer CLI for the TrailGate agent SDK',
    '',
    'commands:',
    '  discover <url> [--refresh]                    validate and print site capabilities and actions',
    '  actions <url>                                 list advertised actions with local grant coverage',
    '  keygen [--alg ed25519|p256]                   generate a signing key into the state dir',
    '  keys                                          list stored key thumbprints',
    '  request <url> --permission p [--permission q]',
    '       [--resource r] [--redirect uri] [--state s] [--seconds n] [--key jkt] [--wait]',
    '                                               submit a grant request; --wait polls and redeems',
    '  redeem <url> --request-id id                  redeem an approved pending request',
    '  status <url> (--request-id id | --grant-id id)',
    '                                               query grant status (informational)',
    '  access <url> [--permission p] [--key jkt] [--fresh]',
    '                                               check local grant availability; --fresh also queries status',
    '  fetch <url> <target> [--method M] [--body s]',
    '       [--grant-id jti] [--permission p] [--idempotency-key k]',
    '                                               send a signed request to a same-origin target',
    '  grants [--issuer origin]                      list stored grants',
    '  revoke <url> --grant-id jti [--reason r]      revoke a grant via the signed endpoint',
    '  action-status <url> <action-id|status-url> [--grant-id jti]',
    '                                               poll a queued pending action result',
    '',
    'options:',
    '  --state-dir <dir>   where keys.json, pending.json, grants.json live (default .trailgate)',
  ].join('\n');
}

function grantView(record: {
  jti: string;
  issuer: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  permissions: string[];
  resources: string[];
  subject?: string;
}) {
  // Deliberately excludes `token`: the CLI prints metadata, not credentials.
  const view: Record<string, unknown> = {
    jti: record.jti,
    issuer: record.issuer,
    keyId: record.keyId,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    permissions: record.permissions,
    resources: record.resources,
  };
  if (record.subject !== undefined) {
    view.subject = record.subject;
  }
  return view;
}

export async function runCli(argv: string[], deps: CliDeps = {}): Promise<number> {
  const stdout = deps.stdout ?? ((line) => console.log(line));
  const stderr = deps.stderr ?? ((line) => console.error(line));
  const print = (value: unknown) => stdout(JSON.stringify(value, null, 2));

  const parsed = parseArgs(argv);
  const stateDir = flag(parsed, 'state-dir') ?? deps.stateDir ?? DEFAULT_STATE_DIR;
  const command = parsed.positional[0];
  const rest = parsed.positional.slice(1);

  if (command === undefined || command === 'help' || command === '--help' || command === '-h') {
    stdout(usage());
    return 0;
  }

  try {
    switch (command) {
      case 'keygen': {
        const alg = flag(parsed, 'alg') ?? 'ed25519';
        if (alg !== 'ed25519' && alg !== 'p256') {
          stderr(`unknown --alg ${alg}; expected ed25519 or p256`);
          return 2;
        }
        const signer = await generateAndStoreKey(stateDir, alg);
        print({ jkt: signer.jkt, publicJwk: signer.publicJwk, algorithm: signer.algorithm });
        return 0;
      }

      case 'keys': {
        const signers = await loadSigners(stateDir);
        print(signers.map((s) => ({ jkt: s.jkt, algorithm: s.algorithm, publicJwk: s.publicJwk })));
        return 0;
      }

      case 'discover': {
        const url = rest[0];
        if (url === undefined) {
          stderr('discover requires a site url');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const ctx = await client.discover(url, { refresh: parsed.flags.has('refresh') });
        print({
          issuer: ctx.issuer,
          origin: ctx.origin,
          protocolVersion: ctx.protocolVersion,
          endpoints: ctx.document.endpoints,
          permissions: ctx.document.permissions,
          constraintTypes: ctx.document.constraint_types,
          capabilities: ctx.document.capabilities ?? {},
          actions: ctx.document.actions ?? [],
        });
        return 0;
      }

      case 'actions': {
        const url = rest[0];
        if (url === undefined) {
          stderr('actions requires a site url');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const coverage = await client.listActions(url);
        print(
          coverage.map((entry) => ({
            id: entry.action.id,
            method: entry.action.method,
            path: entry.action.path,
            permission: entry.action.permission,
            description: entry.action.description,
            mutates: entry.action.mutates ?? true,
            resource: entry.action.resource,
            spend: entry.action.spend,
            covered: entry.covered,
            grant: entry.grant?.jti,
            missing: entry.missing,
          })),
        );
        return 0;
      }

      case 'request': {
        const url = rest[0];
        if (url === undefined) {
          stderr('request requires a site url');
          return 2;
        }
        const permissions = flagAll(parsed, 'permission');
        if (permissions.length === 0) {
          stderr('request requires at least one --permission');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        // Subject-derived templates (`cart:{user}`) advertised by matching
        // actions are requested verbatim; the site binds them at consent.
        // Path-parameter templates (`order:{id}`) are skipped: they cannot be
        // bound before the resource exists.
        const wanted = new Set(permissions);
        const derived: string[] = [];
        try {
          for (const entry of await client.listActions(url)) {
            const resource = entry.action.resource;
            if (
              resource?.includes('{user}') &&
              wanted.has(entry.action.permission) &&
              !derived.includes(resource)
            ) {
              derived.push(resource);
            }
          }
        } catch {
          // no usable catalog; explicit --resource flags still apply
        }
        const signer = await pickSigner(stateDir, flag(parsed, 'key'));
        const session = await client.requestGrant(url, {
          permissions,
          resources: [...new Set([...flagAll(parsed, 'resource'), ...derived])],
          constraints: parseConstraints(flagAll(parsed, 'constraint')),
          ...(flag(parsed, 'redirect') !== undefined
            ? { redirectUri: flag(parsed, 'redirect') as string }
            : {}),
          ...(flag(parsed, 'state') !== undefined
            ? { state: flag(parsed, 'state') as string }
            : {}),
          ...(flag(parsed, 'seconds') !== undefined
            ? { requestedSeconds: Number.parseInt(flag(parsed, 'seconds') as string, 10) }
            : {}),
          ...(signer !== undefined ? { key: signer } : {}),
        });
        // Persist the pending session (including the code_verifier) so
        // `redeem` works in a later invocation. pending.json is 0600.
        const record = client.exportPending(session.requestId);
        if (record !== undefined) {
          await savePending(stateDir, record);
        }
        print({
          requestId: session.requestId,
          consentUrl: session.consentUrl,
          expiresAt: session.expiresAt,
        });
        if (parsed.flags.has('wait')) {
          const grant = await client.awaitApproval(session.requestId);
          await dropPending(stateDir, session.requestId);
          print({ redeemed: grantView(grant) });
        }
        return 0;
      }

      case 'redeem': {
        const url = rest[0];
        const requestId = flag(parsed, 'request-id');
        if (url === undefined || requestId === undefined) {
          stderr('redeem requires a site url and --request-id');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const grant = await client.redeemGrant(requestId);
        await dropPending(stateDir, requestId);
        print(grantView(grant));
        return 0;
      }

      case 'status': {
        const url = rest[0];
        if (url === undefined) {
          stderr('status requires a site url');
          return 2;
        }
        const requestId = flag(parsed, 'request-id');
        const grantId = flag(parsed, 'grant-id');
        if (requestId === undefined && grantId === undefined) {
          stderr('status requires --request-id or --grant-id');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const status = await client.grantStatus(url, {
          ...(requestId !== undefined ? { requestId } : {}),
          ...(grantId !== undefined ? { grantId } : {}),
        });
        print(status);
        return 0;
      }

      case 'access': {
        const url = rest[0];
        if (url === undefined) {
          stderr('access requires a site url');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const result = await client.checkAccess(url, {
          ...(flag(parsed, 'permission') !== undefined
            ? { permissions: flagAll(parsed, 'permission') }
            : {}),
          ...(flag(parsed, 'key') !== undefined ? { keyId: flag(parsed, 'key') as string } : {}),
          confirmFresh: parsed.flags.has('fresh'),
        });
        const view: Record<string, unknown> = { status: result.status };
        if ('grant' in result) {
          view.grant = grantView(result.grant);
        }
        if (result.status === 'insufficient_permission') {
          view.missing = result.missing;
        }
        if (result.status === 'unsupported_version') {
          view.site = result.site;
          view.client = result.client;
        }
        print(view);
        return result.status === 'ready' ? 0 : 1;
      }

      case 'fetch': {
        const url = rest[0];
        const target = rest[1];
        if (url === undefined || target === undefined) {
          stderr('fetch requires a site url and a target path');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const res = await client.fetchProtected(url, {
          method: (flag(parsed, 'method') ?? 'GET').toUpperCase(),
          target,
          ...(flag(parsed, 'body') !== undefined ? { body: flag(parsed, 'body') as string } : {}),
          ...(flag(parsed, 'grant-id') !== undefined
            ? { grantId: flag(parsed, 'grant-id') as string }
            : {}),
          ...(flag(parsed, 'permission') !== undefined
            ? { permission: flag(parsed, 'permission') as string }
            : {}),
          ...(flag(parsed, 'idempotency-key') !== undefined
            ? { idempotencyKey: flag(parsed, 'idempotency-key') as string }
            : {}),
        });
        const body = new TextDecoder().decode(res.body);
        let parsedBody: unknown = body;
        try {
          parsedBody = JSON.parse(body);
        } catch {
          // Non-JSON body prints as text.
        }
        print({
          status: res.status,
          ...(res.pending !== undefined ? { pending_action: res.pending } : {}),
          ...(res.error !== undefined ? { error: res.error } : {}),
          receipt:
            res.receipt === undefined
              ? 'absent'
              : res.receipt.verified
                ? { verified: true, decision: res.receipt.payload.tg.decision }
                : { verified: false, reason: res.receipt.reason },
          body: parsedBody,
        });
        return res.status < 400 ? 0 : 1;
      }

      case 'grants': {
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const issuer = flag(parsed, 'issuer');
        const records = await client.listGrants(issuer !== undefined ? { issuer } : undefined);
        print(records.map(grantView));
        return 0;
      }

      case 'action-status': {
        const url = rest[0];
        const ref = rest[1];
        if (url === undefined || ref === undefined) {
          stderr('action-status requires a site url and an action id or status url');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        const id = ref.includes('/') ? (ref.split('/').pop() ?? ref) : ref;
        const view = await client.actionStatus(url, id, {
          ...(flag(parsed, 'grant-id') !== undefined
            ? { grantId: flag(parsed, 'grant-id') as string }
            : {}),
        });
        print({ pending_action: view });
        return view.status === 'failed' || view.status === 'rejected' ? 1 : 0;
      }

      case 'revoke': {
        const url = rest[0];
        const grantId = flag(parsed, 'grant-id');
        if (url === undefined || grantId === undefined) {
          stderr('revoke requires a site url and --grant-id');
          return 2;
        }
        const client = await (deps.clientFactory ?? defaultClientFactory)({ stateDir });
        await client.revokeGrant(url, grantId, {
          ...(flag(parsed, 'reason') !== undefined
            ? { reason: flag(parsed, 'reason') as string }
            : {}),
        });
        print({ revoked: grantId });
        return 0;
      }

      default:
        stderr(`unknown command ${command}`);
        stdout(usage());
        return 2;
    }
  } catch (err) {
    if (err instanceof AgentError) {
      stderr(`error (${err.kind}): ${err.message}`);
      return 1;
    }
    if (isTrailGateError(err)) {
      stderr(`error (${err.code}): ${err.message}`);
      return 1;
    }
    stderr(`error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

async function pickSigner(stateDir: string, jkt?: string) {
  const signers = await loadSigners(stateDir);
  if (jkt === undefined) {
    return signers.length === 1 ? signers[0] : undefined;
  }
  const found = signers.find((s) => s.jkt === jkt);
  if (found === undefined) {
    throw new AgentError('no_key', `no stored key with jkt ${jkt}`);
  }
  return found;
}

function parseConstraints(values: string[]) {
  return values.map((raw) => {
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof (parsed as { type?: unknown }).type !== 'string'
    ) {
      throw new AgentError(
        'unknown_request',
        `--constraint must be JSON like {"type":"max_amount","params":{...}}`,
      );
    }
    return parsed as { type: string; params?: Record<string, unknown> };
  });
}
