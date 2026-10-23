import type { AgentHttpRequest, AgentHttpResponse, HttpTransport } from './transport.ts';

/** Shared fakes for agent tests. Not part of the package build. */

export function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): AgentHttpResponse {
  return {
    status,
    headers: { 'content-type': 'application/json', ...headers },
    body: new TextEncoder().encode(JSON.stringify(body)),
  };
}

export function textResponse(
  status: number,
  body: string,
  headers: Record<string, string> = {},
): AgentHttpResponse {
  return { status, headers, body: new TextEncoder().encode(body) };
}

export interface FakeTransport {
  transport: HttpTransport;
  requests: AgentHttpRequest[];
}

/** Records every request and delegates the response to `handler`. */
export function fakeTransport(
  handler: (req: AgentHttpRequest) => AgentHttpResponse | Promise<AgentHttpResponse>,
): FakeTransport {
  const requests: AgentHttpRequest[] = [];
  return {
    transport: {
      send: async (req) => {
        requests.push(req);
        return handler(req);
      },
    },
    requests,
  };
}

/** Decodes a recorded request's JSON body. */
export function requestJson(req: AgentHttpRequest): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(req.body)) as Record<string, unknown>;
}
