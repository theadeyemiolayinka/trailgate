/**
 * Minimal standalone host application for the TrailGate Server SDK.
 * A photo-library site (not ExampleShop) wiring every protocol surface on
 * node:http with in-memory stores. Development only: keys and state reset on
 * every start.
 *
 * Run from the repo root after `pnpm -r build`:
 *   node --experimental-strip-types packages/server/examples/photo-host.ts
 * Node 22.18+ strips types natively; on newer Node the flag is unnecessary.
 *
 * The issuer is a fixed https identity for signing; transport is loopback
 * http. A real deployment serves these routes on the issuer origin over TLS.
 */
import { createServer } from 'node:http';
import {
  createTrailGateServer,
  generateSigningKeyPair,
  type HostRequest,
  type HostResponse,
} from '@trailgate/server';

const ISSUER = 'https://photos.example.com';
const PORT = Number(process.env.PORT ?? 8787);

const albums = new Map<string, { owner: string; photos: string[] }>([
  ['alb_f1', { owner: 'user_1', photos: [] }],
]);
const sessions = new Map([['sess_1', 'user_1']]);

const tg = createTrailGateServer({
  issuer: ISSUER,
  signingKeys: [{ privateJwk: generateSigningKeyPair().privateJwk }],
  permissions: ['tg.album.create', 'tg.album.read', 'tg.photo.upload'],
  resourceOwners: {
    ownerOf: async (selector) => {
      const [type, id] = selector.split(':');
      return type === 'album' && id !== undefined ? albums.get(id)?.owner : undefined;
    },
  },
});

const sessionUser = (req: HostRequest) =>
  sessions.get(req.headers.cookie?.replace('session=', '') ?? '');

const bodyJson = (req: HostRequest): Record<string, unknown> => {
  const text =
    req.body === undefined
      ? ''
      : typeof req.body === 'string'
        ? req.body
        : new TextDecoder().decode(req.body);
  return text === '' ? {} : (JSON.parse(text) as Record<string, unknown>);
};

async function routes(req: HostRequest): Promise<HostResponse> {
  const { pathname, searchParams } = new URL(req.url);
  if (pathname === '/.well-known/trailgate') {
    return { status: 200, body: tg.discoveryDocument() };
  }
  if (pathname === '/tg/grant-request') return tg.handleGrantRequest(req);
  if (pathname === '/tg/grant-redemption') return tg.handleRedemption(req);
  if (pathname === '/tg/grant-status') return tg.handleStatus(req);
  if (pathname === '/tg/consent') {
    if (sessionUser(req) === undefined) return { status: 401, body: { error: 'login' } };
    const view = await tg.getConsent(searchParams.get('request_id') ?? '');
    return view === undefined ? { status: 404, body: {} } : { status: 200, body: view };
  }
  if (pathname === '/tg/consent/decide') {
    const user = sessionUser(req);
    if (user === undefined) return { status: 401, body: { error: 'login' } };
    const body = bodyJson(req);
    const outcome = await tg.decideConsent(
      body.request_id as string,
      body.approve === true ? 'approve' : 'deny',
      user,
    );
    return { status: 200, body: outcome };
  }
  const match = /^\/albums\/(alb_[^/]+)$/.exec(pathname);
  if (match !== null) {
    const id = match[1] as string;
    return tg.protect({ permission: 'tg.album.read', resource: `album:${id}` }, async () => ({
      status: 200,
      body: { id, album: albums.get(id) },
    }))(req);
  }
  return { status: 404, body: { error: 'not found' } };
}

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const body = Buffer.concat(chunks);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value as string);
  }
  const out = await routes({
    method: req.method as string,
    url: `${ISSUER}${req.url}`,
    headers,
    ...(body.length > 0 ? { body: new Uint8Array(body) } : {}),
  });
  res.writeHead(out.status, { 'content-type': 'application/json', ...(out.headers ?? {}) });
  res.end(out.body === undefined ? '' : JSON.stringify(out.body));
}).listen(PORT, () => {
  console.log(`photo-host listening on http://127.0.0.1:${PORT} (issuer ${ISSUER})`);
  console.log('routes: /.well-known/trailgate, /tg/*, /tg/consent, /albums/:id');
  console.log('demo session cookie: session=sess_1 (user_1 owns alb_f1)');
});
