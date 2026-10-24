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

/**
 * Layman-readable one-liners for results the model relays to the user.
 * Tool output stays jargon-light: `summary` is what the user should hear,
 * while `code` remains for machines.
 */
function summaryFor(code: string): string {
  switch (code) {
    case 'tg.request.permission_denied':
      return "You haven't allowed that yet.";
    case 'tg.request.resource_denied':
      return "You haven't allowed access to that.";
    case 'tg.request.grant_invalid':
      return 'The access on file is no longer valid.';
    case 'tg.request.grant_expired':
      return 'The access has expired.';
    case 'tg.request.grant_revoked':
      return 'You revoked this access.';
    case 'tg.constraint.approval_required':
      return 'This needs your approval for this specific charge.';
    case 'tg.constraint.violated':
      return 'This goes over a limit you set.';
    case 'tg.request.rate_limited':
      return 'The site is limiting how fast new access can be requested.';
    case 'agent.no_grant':
      return 'No access has been granted for this site yet.';
    case 'agent.insufficient_permission':
      return 'The access on file does not cover this.';
    case 'agent.denied':
      return 'This was not allowed.';
    default:
      return 'Something was not allowed.';
  }
}

/** Plain-English wording for local access-check statuses. */
function accessSummary(status: string): string {
  switch (status) {
    case 'ready':
      return 'Access is in place.';
    case 'no_grant':
      return 'Nothing has been granted for this site yet.';
    case 'insufficient_permission':
      return 'The access on file does not cover this.';
    case 'expired':
      return 'The access has expired.';
    case 'revoked':
      return 'You revoked this access.';
    case 'wrong_key':
      return 'The access belongs to a different key.';
    case 'unsupported_version':
      return 'This site speaks a version this client does not understand.';
    default:
      return 'Access is not usable.';
  }
}

/**
 * Model-facing advice attached to failures. Denials are terminal from the
 * agent's point of view: the correct response is to report back to the
 * user, never to self-escalate with a fresh access request.
 */
function guidanceFor(code: string): string | undefined {
  switch (code) {
    case 'tg.request.permission_denied':
    case 'tg.request.resource_denied':
    case 'tg.request.grant_invalid':
    case 'tg.request.grant_expired':
    case 'tg.request.grant_revoked':
    case 'agent.no_grant':
    case 'agent.insufficient_permission':
      return 'Access was denied. Do not start a new access request, retry a different way, or work around it. Report the missing permission to the user; only they can decide to grant more access.';
    case 'tg.constraint.approval_required':
      return 'This action needs the user to approve this specific charge. Share the approval URL and wait for them to decide; do not work around it or split the amount.';
    case 'agent.denied':
      return 'This action was refused. Stop and report back to the user instead of retrying.';
    default:
      return undefined;
  }
}

function okError(code: string, message: string): ToolResult {
  const error: Record<string, unknown> = { code, message, summary: summaryFor(code) };
  const guidance = guidanceFor(code);
  if (guidance !== undefined) {
    error.guidance = guidance;
  }
  return {
    content: [{ type: 'text', text: JSON.stringify({ error }) }],
    structuredContent: { error },
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
        "Discover a site's TrailGate support and return its validated capabilities and advertised actions. Fails when the site does not implement the protocol.",
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
            actions: ctx.document.actions ?? [],
          });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.actions',
      description:
        'List what a site lets agents do, each with a plain-English `name` to use when talking to the user. `covered` means existing access already allows it; uncovered entries are reported to the user as things they have not allowed yet. Use this to map what the user asked for onto the right endpoint. Coverage is advisory: the site decides on every request.',
      inputSchema: {
        type: 'object',
        properties: { url: URL_ARG },
        required: ['url'],
        additionalProperties: false,
      },
      handler: async (args) => {
        try {
          const coverage = await client.listActions(requireString(args, 'url'));
          return ok({
            actions: coverage.map((entry) => ({
              name: entry.action.description,
              id: entry.action.id,
              method: entry.action.method,
              path: entry.action.path,
              covered: entry.covered,
              permission: entry.action.permission,
              mutates: entry.action.mutates ?? true,
              resource: entry.action.resource,
              spend: entry.action.spend,
            })),
            note: 'Describe these to the user using `name`, never raw ids or permission strings. For uncovered entries, report what is not yet allowed rather than requesting access on your own.',
          });
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.request',
      description:
        "Create a NEW access request for a site. Call this only when the user's latest message explicitly asks to grant, connect, or expand access. Never call it in reaction to a denied action or an assumed need. It returns an approval link: relay the link to the user plainly and stop; nothing is authorized until they open it and decide. The user may approve a narrower scope than asked.",
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          permissions: { type: 'array', items: { type: 'string' } },
          resources: { type: 'array', items: { type: 'string' } },
          constraints: { type: 'array', items: { type: 'object' } },
          requested_seconds: {
            type: 'integer',
            description:
              'How long the access should last, in seconds. The site may shorten it.',
          },
          user_authorized: {
            type: 'boolean',
            description:
              'Must be true, and means the user explicitly asked for this new or expanded access in their latest message. False or missing rejects the call.',
          },
        },
        required: ['url', 'permissions', 'user_authorized'],
        additionalProperties: false,
      },
      handler: async (args) => {
        if (args.user_authorized !== true) {
          return okError(
            'agent.denied',
            'access requests require the user to explicitly ask for new or expanded access; relay what is missing and wait for them to decide',
          );
        }
        const denied = await gate('trailgate.request', args);
        if (denied !== undefined) {
          return denied;
        }
        try {
          const requestedSeconds = args.requested_seconds;
          if (
            requestedSeconds !== undefined &&
            (typeof requestedSeconds !== 'number' ||
              !Number.isInteger(requestedSeconds) ||
              requestedSeconds < 1)
          ) {
            return okError(
              'agent.denied',
              'requested_seconds must be a positive integer number of seconds',
            );
          }
          const session = await client.requestGrant(requireString(args, 'url'), {
            permissions: stringList(args, 'permissions'),
            resources: stringList(args, 'resources'),
            constraints: (args.constraints as never) ?? [],
            ...(requestedSeconds !== undefined
              ? { requestedSeconds: requestedSeconds as number }
              : {}),
          });
          return ok({
            status: 'pending',
            consentUrl: session.consentUrl,
            requestId: session.requestId,
            expiresAt: session.expiresAt,
            note: 'Share only the consentUrl with the user and wait for their decision; do not expose request internals.',
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
      name: 'trailgate.access',
      description:
        "Check whether usable access already exists locally for a site and scope before acting. Statuses: ready, no_grant, insufficient_permission, expired, wrong_key, revoked, unsupported_version. Set fresh to true to also ask the site for the grant's current scope, which picks up permissions the user added or removed on the site since granting. A shortfall means report it to the user, not start a new request. Never proves access: the site decides at enforcement.",
      inputSchema: {
        type: 'object',
        properties: {
          url: URL_ARG,
          permissions: { type: 'array', items: { type: 'string' } },
          fresh: { type: 'boolean', description: 'also query live grant_status' },
        },
        required: ['url'],
        additionalProperties: false,
      },
      handler: async (args) => {
        try {
          const result = await client.checkAccess(requireString(args, 'url'), {
            permissions: stringList(args, 'permissions'),
            confirmFresh: args.fresh === true,
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
          view.summary = accessSummary(result.status);
          if (result.status !== 'ready') {
            const hint = guidanceFor(`agent.${result.status}`);
            if (hint !== undefined) {
              view.guidance = hint;
            }
          }
          return ok(view);
        } catch (err) {
          return fail(err);
        }
      },
    },
    {
      name: 'trailgate.fetch',
      description:
        "Send a signed request to a path on a site the user already authorized. The target cannot leave the site origin. If the site denies for missing permission or scope, report the denial to the user verbatim and stop; do not start a new access request. Receipts are verified against the site's published keys and reported honestly.",
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
          const hint = res.error !== undefined ? guidanceFor(res.error.code) : undefined;
          return ok({
            status: res.status,
            ...(res.error !== undefined
              ? {
                  error: {
                    ...res.error,
                    summary: summaryFor(res.error.code),
                    ...(hint !== undefined ? { guidance: hint } : {}),
                  },
                }
              : {}),
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
        'Revoke a grant at the issuing site via the ratified self-revocation endpoint. Removes the local record on success.',
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
          return ok({ revoked: args.grantId });
        } catch (err) {
          return fail(err);
        }
      },
    },
  ];
}
