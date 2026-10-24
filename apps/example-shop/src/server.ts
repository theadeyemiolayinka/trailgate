import { existsSync, readFileSync } from 'node:fs';
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createShopApp } from './app.ts';
import { loadConfig } from './config.ts';
import { openDatabase } from './db/database.ts';
import { seedIfEmpty } from './db/seed.ts';

const MAX_BODY_BYTES = 65_536;
const appRoot = fileURLToPath(new URL('..', import.meta.url));
const publicDir = join(appRoot, 'public');

const SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'same-origin',
  'x-frame-options': 'DENY',
  'content-security-policy':
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
};

const STATIC_MIME: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

function staticFile(path: string): { filePath: string; type: string } | undefined {
  if (!path.startsWith('/static/')) {
    return undefined;
  }
  let rel: string;
  try {
    rel = decodeURIComponent(path.slice('/static/'.length));
  } catch {
    return undefined;
  }
  if (rel === '' || rel.includes('..') || rel.includes('\0')) {
    return undefined;
  }
  const filePath = join(publicDir, rel);
  if (!filePath.startsWith(`${publicDir}/`) || !existsSync(filePath)) {
    return undefined;
  }
  const type = STATIC_MIME[filePath.slice(filePath.lastIndexOf('.')).toLowerCase()];
  return type === undefined ? undefined : { filePath, type };
}

function collectBody(req: IncomingMessage): Promise<Uint8Array | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      resolve(chunks.length === 0 ? undefined : new Uint8Array(Buffer.concat(chunks)));
    });
    req.on('error', reject);
  });
}

function headersOf(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) {
      continue;
    }
    out[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

async function route(
  app: ReturnType<typeof createShopApp>,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  try {
    const body = await collectBody(req);
    const url = req.url ?? '/';
    const path = new URL(url, 'https://local').pathname;
    const file = staticFile(path);
    if (file !== undefined && req.method === 'GET') {
      res.writeHead(200, {
        'content-type': file.type,
        'cache-control': 'public, max-age=3600',
        ...SECURITY_HEADERS,
      });
      res.end(readFileSync(file.filePath));
      return;
    }
    const out = await app.handle({
      method: req.method ?? 'GET',
      url,
      headers: headersOf(req),
      ...(body !== undefined ? { body } : {}),
    });
    res.writeHead(out.status, { ...SECURITY_HEADERS, ...(out.headers ?? {}) });
    res.end(out.body ?? '');
  } catch (err) {
    const status = err instanceof Error && err.message === 'request body too large' ? 413 : 500;
    if (status === 500) {
      console.error('unhandled error:', err);
    }
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    res.end(status === 413 ? 'request too large' : 'internal error');
  }
}

export function startServer(): void {
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  if (config.seed) {
    seedIfEmpty(db);
  }
  const app = createShopApp(db, config);

  createHttpServer((req, res) => void route(app, req, res)).listen(
    config.httpPort,
    config.host,
    () => {
      console.log(`ExampleShop storefront:  http://127.0.0.1:${config.httpPort}`);
      console.log(`TrailGate issuer identity: ${config.issuer}`);
    },
  );

  const keyPath = join(config.certsDir, 'server.key');
  const certPath = join(config.certsDir, 'server.crt');
  if (existsSync(keyPath) && existsSync(certPath)) {
    const tlsOptions = { key: readFileSync(keyPath), cert: readFileSync(certPath) };
    createHttpsServer(tlsOptions, (req, res) => void route(app, req, res)).listen(
      config.tlsPort,
      config.host,
      () => {
        console.log(`TLS listener (issuer origin): https://localhost:${config.tlsPort}`);
      },
    );
  } else {
    console.log(
      `TLS listener inactive (no dev certs in ${config.certsDir}); run "pnpm certs" to enable, or use the loopback transport for agent flows.`,
    );
  }
}

startServer();
