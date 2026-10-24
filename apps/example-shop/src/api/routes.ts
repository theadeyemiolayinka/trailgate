import { Codes, decodeCompactJws, TrailGateError } from '@trailgate/core';
import type {
  EnforcementContext,
  HostRequest,
  HostResponse,
  TrailGateServer,
} from '@trailgate/server';
import type { Db } from '../db/database.ts';
import { CartError, getCart, setCartQty } from '../domain/cart.ts';
import { getProduct, listProducts } from '../domain/catalog.ts';
import {
  createOrderFromCart,
  getInvoice,
  getOrder,
  listOrderItems,
  listOrders,
  OrderError,
  payOrder,
} from '../domain/orders.ts';
import { getWallet, InsufficientFundsError, listWalletEntries } from '../domain/wallet.ts';
import { cartSelector, orderSelector, walletSelector } from '../tg/vocabulary.ts';

/**
 * Agent-facing JSON API. Every route runs through `tg.protect`, so the
 * spec section 11 pipeline (signature, grant, replay, idempotency,
 * permission, resource, constraints, site policy) executes before the
 * handler. Handlers see only verified context (`ctx.subject`,
 * `ctx.grant`) and perform business logic on authoritative database state.
 */

interface ApiRoute {
  method: string;
  pattern: string;
  handle: (req: HostRequest) => Promise<HostResponse>;
}

function json(status: number, body: unknown): HostResponse {
  return { status, headers: { 'content-type': 'application/json' }, body };
}

function err(status: number, code: string, message: string): HostResponse {
  return json(status, { error: { code, message } });
}

function matchPath(pattern: string, path: string): Record<string, string> | undefined {
  const want = pattern.split('/').filter((s) => s !== '');
  const got = path.split('/').filter((s) => s !== '');
  if (want.length !== got.length) {
    return undefined;
  }
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    const segment = want[i] as string;
    if (segment.startsWith(':')) {
      params[segment.slice(1)] = decodeURIComponent(got[i] as string);
    } else if (segment !== got[i]) {
      return undefined;
    }
  }
  return params;
}

function paramsOf(req: HostRequest, pattern: string): Record<string, string> {
  const params = matchPath(pattern, new URL(req.url).pathname);
  if (params === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request path did not match route');
  }
  return params;
}

function param(params: Record<string, string>, name: string): string {
  const value = params[name];
  if (value === undefined) {
    throw new TrailGateError(Codes.REQUEST_MALFORMED, `missing path parameter ${name}`);
  }
  return value;
}

function bodyObject(req: HostRequest): Record<string, unknown> {
  const body = req.body;
  if (body === undefined) {
    return {};
  }
  const text = typeof body === 'string' ? body : new TextDecoder().decode(body);
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new TrailGateError(Codes.REQUEST_MALFORMED, 'request body must be a json object');
}

/**
 * Persists the signed receipt a protected response carries (spec section
 * 14) so users can inspect issued receipts later. The payload is decoded
 * unverified for indexing only; display-time verification runs against
 * `verifyReceipt` with the real signing keys.
 */
function captureReceipt(db: Db, req: HostRequest, res: HostResponse): void {
  const token = res.headers?.['trailgate-receipt'];
  if (typeof token !== 'string') {
    return;
  }
  try {
    const payload = decodeCompactJws(token).payload as {
      jti?: string;
      tg?: { grant_id?: string; decision?: string; code?: string };
    };
    if (typeof payload.tg?.grant_id !== 'string' || typeof payload.tg.decision !== 'string') {
      return;
    }
    db.prepare(
      `INSERT INTO tg_receipts (id, grant_id, decision, code, receipt_jws, method, target, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      payload.jti ?? `rcp_${Date.now()}`,
      payload.tg.grant_id,
      payload.tg.decision,
      payload.tg.code ?? null,
      token,
      req.method.toUpperCase(),
      new URL(req.url).pathname,
      Math.floor(Date.now() / 1000),
    );
  } catch {
    // Receipt persistence is best-effort; a malformed receipt still reaches the agent.
  }
}

function requireSubject(ctx: EnforcementContext): string {
  if (ctx.subject === undefined) {
    throw new TrailGateError(
      Codes.AUTHORIZATION_DENIED,
      'this endpoint requires a grant issued under a user account',
    );
  }
  return ctx.subject;
}

function productView(p: ReturnType<typeof getProduct> & object): unknown {
  return {
    sku: p.sku,
    name: p.name,
    category: p.category,
    description: p.description,
    price: p.price,
    stock: p.stock,
  };
}

function cartView(db: Db, userId: string): unknown {
  const cart = getCart(db, userId);
  return {
    id: cart.id,
    selector: cartSelector(userId),
    items: cart.lines.map((line) => ({
      sku: line.sku,
      name: line.name,
      qty: line.qty,
      unit_price: line.unitPrice,
      line_total: line.lineTotal,
    })),
    total: cart.total,
  };
}

function orderView(db: Db, orderId: string): unknown {
  const order = getOrder(db, orderId);
  if (order === undefined) {
    return undefined;
  }
  return {
    id: order.id,
    status: order.status,
    total: order.total,
    placed_via: order.placedVia,
    created_at: order.createdAt,
    selector: orderSelector(order.id),
    items: listOrderItems(db, orderId).map((line) => ({
      sku: line.sku,
      name: line.name,
      qty: line.qty,
      unit_price: line.unitPrice,
      line_total: line.lineTotal,
    })),
  };
}

/**
 * Builds the dispatch table. Each entry pairs a path pattern with a
 * `tg.protect`-wrapped handler; `dispatch` returns undefined for paths
 * outside the API so the adapter can fall through to the site's own routes.
 */
export function createAgentApi(
  db: Db,
  tg: TrailGateServer,
  spendingPolicy: { maxCharge: { amount: number; currency: string } },
): { dispatch: (req: HostRequest) => Promise<HostResponse | undefined> } {
  const routes: ApiRoute[] = [
    {
      method: 'GET',
      pattern: '/api/products',
      handle: tg.protect(
        {
          permission: 'tg.catalog.read',
          mutating: false,
          action: {
            id: 'products.list',
            method: 'GET',
            path: '/api/products',
            description: 'list the product catalog',
          },
        },
        async () =>
          json(200, {
            products: listProducts(db).map((p) => productView(p)),
          }),
      ),
    },
    {
      method: 'GET',
      pattern: '/api/products/:sku',
      handle: tg.protect(
        {
          permission: 'tg.catalog.read',
          mutating: false,
          action: {
            id: 'products.read',
            method: 'GET',
            path: '/api/products/{sku}',
            description: 'read one product by sku',
          },
        },
        async (req) => {
          const sku = param(paramsOf(req, '/api/products/:sku'), 'sku');
          const product = getProduct(db, sku);
          return product === undefined
            ? err(404, 'shop.product.not_found', 'unknown product')
            : json(200, productView(product));
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/cart',
      handle: tg.protect(
        {
          permission: 'tg.cart.read',
          resource: (_req, ctx) =>
            ctx.subject === undefined ? undefined : cartSelector(ctx.subject),
          mutating: false,
          action: {
            id: 'cart.read',
            method: 'GET',
            path: '/api/cart',
            description: 'read the items and total in your shopping cart',
            resource: 'cart:{user}',
          },
        },
        async (_req, ctx) => json(200, cartView(db, requireSubject(ctx))),
      ),
    },
    {
      method: 'POST',
      pattern: '/api/cart/items',
      handle: tg.protect(
        {
          permission: 'tg.cart.write',
          resource: (_req, ctx) =>
            ctx.subject === undefined ? undefined : cartSelector(ctx.subject),
          action: {
            id: 'cart.items.set',
            method: 'POST',
            path: '/api/cart/items',
            description: 'add an item to the cart or change its quantity (body: {sku, qty})',
            resource: 'cart:{user}',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const body = bodyObject(req);
          const sku = body.sku;
          const qty = body.qty;
          if (typeof sku !== 'string' || typeof qty !== 'number') {
            return err(
              400,
              'shop.request.invalid',
              'body must carry sku (string) and qty (integer)',
            );
          }
          try {
            setCartQty(db, subject, sku, qty);
          } catch (e) {
            if (e instanceof CartError) {
              return err(400, 'shop.cart.invalid', e.message);
            }
            throw e;
          }
          return json(200, cartView(db, subject));
        },
      ),
    },
    {
      method: 'DELETE',
      pattern: '/api/cart/items/:sku',
      handle: tg.protect(
        {
          permission: 'tg.cart.write',
          resource: (_req, ctx) =>
            ctx.subject === undefined ? undefined : cartSelector(ctx.subject),
          action: {
            id: 'cart.items.remove',
            method: 'DELETE',
            path: '/api/cart/items/{sku}',
            description: 'remove an item from the cart',
            resource: 'cart:{user}',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const sku = param(paramsOf(req, '/api/cart/items/:sku'), 'sku');
          try {
            setCartQty(db, subject, sku, 0);
          } catch (e) {
            if (e instanceof CartError) {
              return err(400, 'shop.cart.invalid', e.message);
            }
            throw e;
          }
          return json(200, cartView(db, subject));
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/orders',
      handle: tg.protect(
        {
          permission: 'tg.order.read',
          mutating: false,
          action: {
            id: 'orders.list',
            method: 'GET',
            path: '/api/orders',
            description: 'list your orders',
          },
        },
        async (_req, ctx) => {
          const subject = requireSubject(ctx);
          const orders = listOrders(db, subject).map((order) => ({
            id: order.id,
            status: order.status,
            total: order.total,
            placed_via: order.placedVia,
            created_at: order.createdAt,
            selector: orderSelector(order.id),
          }));
          return json(200, { orders });
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/orders',
      handle: tg.protect(
        {
          permission: 'tg.order.create',
          action: {
            id: 'orders.create',
            method: 'POST',
            path: '/api/orders',
            description: 'create an order from the current cart contents (checkout)',
          },
        },
        async (_req, ctx) => {
          const subject = requireSubject(ctx);
          try {
            const order = createOrderFromCart(db, subject, {
              placedVia: 'agent',
              grantJti: ctx.grant.jti,
            });
            return json(201, orderView(db, order.id));
          } catch (e) {
            if (e instanceof OrderError) {
              return err(400, 'shop.order.invalid', e.message);
            }
            throw e;
          }
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/orders/:id',
      handle: tg.protect(
        {
          permission: 'tg.order.read',
          resource: (req) => {
            const id = matchPath('/api/orders/:id', new URL(req.url).pathname)?.id;
            return id === undefined ? undefined : orderSelector(id);
          },
          mutating: false,
          action: {
            id: 'orders.read',
            method: 'GET',
            path: '/api/orders/{id}',
            description: 'read one order by id',
            resource: 'order:{id}',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const id = param(paramsOf(req, '/api/orders/:id'), 'id');
          const order = getOrder(db, id, subject);
          return order === undefined
            ? err(404, 'shop.order.not_found', 'unknown order')
            : json(200, orderView(db, id));
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/orders/:id/invoice',
      handle: tg.protect(
        {
          permission: 'tg.order.read',
          resource: (req) => {
            const id = matchPath('/api/orders/:id/invoice', new URL(req.url).pathname)?.id;
            return id === undefined ? undefined : orderSelector(id);
          },
          mutating: false,
          action: {
            id: 'orders.invoice',
            method: 'GET',
            path: '/api/orders/{id}/invoice',
            description: 'read the invoice and billing details for an order',
            resource: 'order:{id}',
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const id = param(paramsOf(req, '/api/orders/:id/invoice'), 'id');
          const invoice = getInvoice(db, id, subject);
          if (invoice === undefined) {
            return err(404, 'shop.order.not_found', 'unknown order');
          }
          return json(200, {
            order: orderView(db, id),
            billed_to: { name: invoice.userName, email: invoice.userEmail },
          });
        },
      ),
    },
    {
      method: 'POST',
      pattern: '/api/orders/:id/pay',
      handle: tg.protect(
        {
          permission: 'tg.wallet.charge',
          resource: (_req, ctx) =>
            ctx.subject === undefined ? undefined : walletSelector(ctx.subject),
          amount: (req) => {
            const id = matchPath('/api/orders/:id/pay', new URL(req.url).pathname)?.id;
            if (id === undefined) {
              return undefined;
            }
            return getOrder(db, id)?.total;
          },
          action: {
            id: 'orders.pay',
            method: 'POST',
            path: '/api/orders/{id}/pay',
            description: 'pay an order total from your wallet balance',
            resource: 'wallet:{user}',
            spend: true,
          },
        },
        async (req, ctx) => {
          const subject = requireSubject(ctx);
          const id = param(paramsOf(req, '/api/orders/:id/pay'), 'id');
          const order = getOrder(db, id);
          if (order === undefined || order.userId !== subject) {
            return err(404, 'shop.order.not_found', 'unknown order');
          }
          // Site spending policy: per-charge cap enforced server-side.
          if (order.total.amount > spendingPolicy.maxCharge.amount) {
            return err(
              403,
              'shop.policy.max_charge',
              `order total exceeds the site maximum charge of ${spendingPolicy.maxCharge.amount} ${spendingPolicy.maxCharge.currency}`,
            );
          }
          try {
            payOrder(db, id, subject);
          } catch (e) {
            if (e instanceof InsufficientFundsError) {
              return err(402, 'shop.wallet.insufficient', 'wallet balance cannot cover this order');
            }
            if (e instanceof OrderError) {
              return err(400, 'shop.order.invalid', e.message);
            }
            throw e;
          }
          return json(200, orderView(db, id));
        },
      ),
    },
    {
      method: 'GET',
      pattern: '/api/wallet',
      handle: tg.protect(
        {
          permission: 'tg.wallet.read',
          resource: (_req, ctx) =>
            ctx.subject === undefined ? undefined : walletSelector(ctx.subject),
          mutating: false,
          action: {
            id: 'wallet.read',
            method: 'GET',
            path: '/api/wallet',
            description: 'read wallet balance, ledger entries, and spend under this grant',
            resource: 'wallet:{user}',
          },
        },
        async (_req, ctx) => {
          const subject = requireSubject(ctx);
          const wallet = getWallet(db, subject);
          const grant = ctx.grant;
          const consumed = await tg.config.stores.ledger.consumedMinorUnits(
            grant.jti,
            wallet.currency,
          );
          const reserved = await tg.config.stores.ledger.reservedMinorUnits(
            grant.jti,
            wallet.currency,
          );
          return json(200, {
            wallet: {
              id: `wlt_${subject}`,
              selector: walletSelector(subject),
              balance: wallet.balance,
            },
            grant: {
              id: grant.jti,
              consumed_under_grant: { amount: consumed, currency: wallet.currency },
              reserved_under_grant: { amount: reserved, currency: wallet.currency },
            },
            entries: listWalletEntries(db, subject, 50).map((entry) => ({
              id: entry.id,
              kind: entry.kind,
              amount: entry.amount,
              ref: entry.ref ?? null,
              balance_after: entry.balanceAfter,
              at: entry.createdAt,
            })),
          });
        },
      ),
    },
  ];

  const table = routes.map((route) => ({ ...route, segments: route.pattern }));

  return {
    dispatch: async (req) => {
      const path = new URL(req.url).pathname;
      for (const route of table) {
        if (route.method !== req.method.toUpperCase()) {
          continue;
        }
        if (matchPath(route.segments, path) !== undefined) {
          try {
            const res = await route.handle(req);
            captureReceipt(db, req, res);
            return res;
          } catch (e) {
            if (e instanceof TrailGateError) {
              return json(e.httpStatus, {
                error: {
                  code: e.code,
                  message: e.message,
                  ...(e.detail ? { detail: e.detail } : {}),
                },
              });
            }
            throw e;
          }
        }
      }
      return undefined;
    },
  };
}
