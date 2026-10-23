import type { AgentClient } from '@trailgate/agent';
import { AgentError } from '@trailgate/agent';
import { isTrailGateError } from '@trailgate/core';

/**
 * Model-facing tool boundary for MCP integration.
 *
 * MCP is an adapter for compatible agent runtimes; it is not the protocol.
 * This module deliberately avoids a dependency on `@modelcontextprotocol/sdk`:
 * it produces plain tool descriptors (`name`, `description`, `inputSchema`,
 * `handler`) that a thin Phase 4 adapter maps onto the MCP SDK's `tool()`
 * registration.
 *
 * The security boundary is the same one the Agent SDK enforces plus one
 * stricter rule: nothing in a `ToolResult` may contain private key material,
 * `code_verifier` values, or grant tokens. Tool handlers return scoped
 * metadata and structured results only. Tests assert this directly.
 */

export interface ToolResult {
  /** Human/model-readable summary, JSON-encoded protocol-visible data. */
  content: Array<{ type: 'text'; text: string }>;
  /** Structured result for runtimes that support it. */
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export interface ToolDefinition {
  name: string;
  description: string;
  /** JSON Schema for the tool's arguments object. */
  inputSchema: Record<string, unknown>;
  handler(args: Record<string, unknown>): Promise<ToolResult>;
}

function ok(result: Record<string, unknown>): ToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    structuredContent: result,
  };
}

function fail(err: unknown): ToolResult {
  if (isTrailGateError(err)) {
    return okError(err.code, err.message);
  }
  if (err instanceof AgentError) {
    return okError(`agent.${err.kind}`, err.message);
  }
  return okError('agent.error', err instanceof Error ? err.message : String(err));
}

function okError(code: string, message: string): ToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: { code, message } }) }],
    structuredContent: { error: { code, message } },
    isError: true,
  };
}

function requireString(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new AgentError('ambiguous', `tool argument ${name} must be a non-empty string`);
  }
  return value;
}

function stringList(args: Record<string, unknown>, name: string): string[] {
  const value = args[name];
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new AgentError('ambiguous', `tool argument ${name} must be a string array`);
  }
  return value as string[];
}

const URL_ARG = { type: 'string', description: 'site url or https origin' } as const;

/** Metadata view of a stored grant. Excludes the grant token deliberately. */
function grantView(record: {
  jti: string;
  issuer: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  permissions: string[];
  resources: string[];
  subject?: string;
}): Record<string, unknown> {
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

export interface TrailGateToolOptions {
  /**
   * Local policy gate invoked before sensitive tools (`trailgate.request`,
   * `trailgate.fetch`, `trailgate.redeem`, `trailgate.revoke`). Use it to
   * require user confirmation, an allowlist, or runtime policy before the
   * adapter acts. Throwing denies the call and returns a typed error; the
   * tool handler is never reached. Read-only tools skip the gate.
   */
  beforeAction?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>;
}

/**
 * The MCP tool surface over an `AgentClient`.
 * @provisional Phase 4 deliverable: names, inputs, and result shapes may
 * change when the real MCP SDK integration lands. The boundary rules above
 * are not provisional.
 */
export function createTrailGateTools(
  client: AgentClient,
  options: TrailGateToolOptions = {},
): ToolDefinition[] {
  const gate = async (
    name: string,
    args: Record<string, unknown>,
  ): Promise<ToolResult | undefined> => {
    if (options.beforeAction === undefined) {
      return undefined;
    }
    try {
      await options.beforeAction(name, args);
      return undefined;
    } catch (err) {
      return fail(err);
    }
  };
  return [
    {
      name: 'trailgate.discover',
      description:
        "Discover a site's TrailGate support and return its validated capabilities. Fails when the site does not implement the protocol.",
      inputSchema: {
        type: 'object',
        properties: { url: URL_ARG },
        required: ['url'],
        additionalProperties: false,
      },
      handler: async (args) => {
        try {
          const ctx = await client.discover(requireString(args, 'url'));
          return ok({
            issuer: ctx.issuer,
            protocolVersion: ctx.protocolVersion,
            permissions: ctx.document.permissions,
            constraintTypes: ctx.document.constraint_types,
            capabilities: ctx.document.capabilities ?? {},
          });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.request',
      description:
        'Start a TrailGate consent flow. Returns a consent_url for the user to open on the site; authority is only delegated after the user approves.',
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          permissions: { type: 'array', items: { type: 'string' } },
          resources: { type: 'array', items: { type: 'string' } },
          constraints: { type: 'array', items: { type: 'object' } },
          wait: { type: 'boolean', description: 'poll for the decision and redeem' },
        },
        required: ['url', 'permissions'],
        additionalProperties: false,
      },
      handler: async (args) => {
        const denied = await gate('trailgate.request', args);
        if (denied !== undefined) {
          return denied;
        }
        try {
          const session = await client.requestGrant(requireString(args, 'url'), {
            permissions: stringList(args, 'permissions'),
            resources: stringList(args, 'resources'),
            constraints: (args.constraints as never) ?? [],
          });
          if (args.wait === true) {
            const grant = await client.awaitApproval(session.requestId);
            return ok({ status: 'issued', grant: grantView(grant) });
          }
          return ok({
            status: 'pending',
            requestId: session.requestId,
            consentUrl: session.consentUrl,
            expiresAt: session.expiresAt,
          });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.status',
      description:
        "Query grant or request status. Informational only; the site's enforcement remains authoritative.",
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          requestId: { type: 'string' },
          grantId: { type: 'string' },
        },
        required: ['url'],
        additionalProperties: false,
      },
      handler: async (args) => {
        try {
          const requestId = args.requestId;
          const grantId = args.grantId;
          const status = await client.grantStatus(requireString(args, 'url'), {
            ...(typeof requestId === 'string' ? { requestId } : {}),
            ...(typeof grantId === 'string' ? { grantId } : {}),
          });
          return ok({ ...status });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.fetch',
      description:
        'Send a TrailGate-signed request to a path on a discovered site. The target cannot leave the site origin.',
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          target: { type: 'string', description: 'path or same-origin url' },
          method: { type: 'string' },
          body: { type: 'string' },
          grantId: { type: 'string' },
          permission: { type: 'string' },
          idempotencyKey: { type: 'string' },
        },
        required: ['url', 'target'],
        additionalProperties: false,
      },
      handler: async (args) => {
        const denied = await gate('trailgate.fetch', args);
        if (denied !== undefined) {
          return denied;
        }
        try {
          const res = await client.fetchProtected(requireString(args, 'url'), {
            target: requireString(args, 'target'),
            method: typeof args.method === 'string' ? args.method : 'GET',
            ...(typeof args.body === 'string' ? { body: args.body } : {}),
            ...(typeof args.grantId === 'string' ? { grantId: args.grantId } : {}),
            ...(typeof args.permission === 'string' ? { permission: args.permission } : {}),
            ...(typeof args.idempotencyKey === 'string'
              ? { idempotencyKey: args.idempotencyKey }
              : {}),
          });
          const text = new TextDecoder().decode(res.body);
          let body: unknown = text;
          try {
            body = JSON.parse(text);
          } catch {
            // Non-JSON bodies pass through as text.
          }
          return ok({
            status: res.status,
            ...(res.error !== undefined ? { error: res.error } : {}),
            receipt:
              res.receipt === undefined
                ? { present: false }
                : res.receipt.verified
                  ? { present: true, verified: true, decision: res.receipt.payload.tg.decision }
                  : { present: true, verified: false },
            body,
          });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.grants',
      description: 'List stored grant metadata (ids, issuers, scope, expiry).',
      inputSchema: {
        type: 'object',
        properties: { issuer: { type: 'string' } },
        additionalProperties: false,
      },
      handler: async (args) => {
        try {
          const issuer = args.issuer;
          const records = await client.listGrants(
            typeof issuer === 'string' ? { issuer } : undefined,
          );
          return ok({ grants: records.map(grantView) });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.redeem',
      description: 'Redeem an approved grant request for its grant.',
      inputSchema: {
        type: 'object',
        properties: { requestId: { type: 'string' } },
        required: ['requestId'],
        additionalProperties: false,
      },
      handler: async (args) => {
        const denied = await gate('trailgate.redeem', args);
        if (denied !== undefined) {
          return denied;
        }
        try {
          const grant = await client.redeemGrant(requireString(args, 'requestId'));
          return ok({ status: 'issued', grant: grantView(grant) });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.revoke',
      description:
        'Revoke a grant at the issuing site (provisional endpoint in draft 0.1). Removes the local record on success.',
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          grantId: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['url', 'grantId'],
        additionalProperties: false,
      },
      handler: async (args) => {
        const denied = await gate('trailgate.revoke', args);
        if (denied !== undefined) {
          return denied;
        }
        try {
          await client.revokeGrant(requireString(args, 'url'), requireString(args, 'grantId'), {
            ...(typeof args.reason === 'string' ? { reason: args.reason } : {}),
          });
          return ok({ revoked: args['grantId'] });
        } catch (err) {
          return fail(err);
        }
      },
    },
  ];
}
