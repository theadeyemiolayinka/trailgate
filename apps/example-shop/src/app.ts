import { Codes, isTrailGateError, TrailGateError, verifyReceipt } from '@trailgate/core';
import type { HostRequest, HostResponse } from '@trailgate/server';
import { createAgentApi } from './api/routes.ts';
import type { ShopConfig } from './config.ts';
import type { Db } from './db/database.ts';
import { CartError, getCart, setCartQty } from './domain/cart.ts';
import { getProduct, listCategories, listProducts, searchProducts } from './domain/catalog.ts';
import {
  cancelOrder,
  createOrderFromCart,
  getInvoice,
  getOrder,
  listOrderItems,
  listOrders,
  OrderError,
  payOrder,
  refundOrder,
} from './domain/orders.ts';
import {
  AuthError,
  authenticate,
  createSession,
  createUser,
  deleteAddress,
  destroySession,
  getAddress,
  getSession,
  getUser,
  listAddresses,
  saveAddress,
  ValidationError,
} from './domain/users.ts';
import {
  getWallet,
  InsufficientFundsError,
  listWalletEntries,
  topUp,
  WalletError,
} from './domain/wallet.ts';
import { CsrfError, parseCookies, parseForm, parseFormValues, requireCsrf } from './http/forms.ts';
import { html, redirect } from './http/responses.ts';
import type { AppRequest, AppResponse } from './http/router.ts';
import { Router } from './http/router.ts';
import { createShopTrailGate, type ShopTrailGate } from './tg/server.ts';
import { bindShopSelectors } from './tg/vocabulary.ts';
import { page } from './ui/layout.ts';
import { renderAddresses, renderProfile } from './ui/pages/account.ts';
import { type ActivityRow, renderActivity } from './ui/pages/activity.ts';
import { renderError, renderLogin, renderNotFound, renderRegister } from './ui/pages/auth.ts';
import { renderCart } from './ui/pages/cart.ts';
import { renderCatalog } from './ui/pages/catalog.ts';
import { renderCheckout } from './ui/pages/checkout.ts';
import {
  type GrantRequestView,
  type IssuedGrantView,
  renderConnections,
  renderGrantDetail,
} from './ui/pages/connections.ts';
import { renderConsent } from './ui/pages/consent.ts';
import { renderHome } from './ui/pages/home.ts';
import { renderInvoice } from './ui/pages/invoice.ts';
import { renderOrderDetail, renderOrderList } from './ui/pages/orders.ts';
import { renderProduct } from './ui/pages/product.ts';
import {
  type ReceiptVerdict,
  renderReceiptDetail,
  renderReceiptList,
  type StoredReceiptRow,
} from './ui/pages/receipts.ts';
import { renderRequestApproval } from './ui/pages/request-approval.ts';
import { renderWallet } from './ui/pages/wallet.ts';

const SESSION_COOKIE = 'shop_session';

export interface ShopApp {
  /** Handles a node:http request; used by both the HTTP and HTTPS listeners. */
  handle(req: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: Uint8Array;
  }): Promise<AppResponse>;
  tg: ShopTrailGate;
  /** The authoritative database handle (exposed for tests and tooling). */
  db: Db;
}

interface Ctx {
  db: Db;
  config: ShopConfig;
  tg: ShopTrailGate;
}

function isProtectedPath(path: string): boolean {
  return (
    path === '/.well-known/trailgate' ||
    path.startsWith('/api/') ||
    path === '/tg/grant-request' ||
    path === '/tg/grant-redemption' ||
    path === '/tg/grant-revocation' ||
    path === '/tg/grant-status'
  );
}

function sessionCookie(id: string, tls: boolean, maxAge: number): string {
  const parts = [
    `${SESSION_COOKIE}=${id}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ];
  if (tls) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

function clearSessionCookie(tls: boolean): string {
  return sessionCookie('', tls, 0);
}

function reqSession(
  req: AppRequest,
):
  | { session: NonNullable<AppRequest['session']>; user: NonNullable<AppRequest['user']> }
  | undefined {
  if (req.session === undefined || req.user === undefined) {
    return undefined;
  }
  return { session: req.session, user: req.user };
}

function loginRedirect(path: string): AppResponse {
  return redirect(`/login?next=${encodeURIComponent(path)}`);
}

function hostToAppRequest(
  ctx: Ctx,
  req: { method: string; url: string; headers: Record<string, string>; body?: Uint8Array },
): AppRequest {
  const url = new URL(req.url, ctx.config.issuer);
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[SESSION_COOKIE];
  const session = sessionId !== undefined ? getSession(ctx.db, sessionId) : undefined;
  const user = session !== undefined ? getUser(ctx.db, session.userId) : undefined;
  return {
    method: req.method.toUpperCase(),
    path: url.pathname,
    url,
    params: {},
    query: url.searchParams,
    headers: req.headers,
    cookies,
    ...(req.body !== undefined ? { body: req.body } : {}),
    ...(session !== undefined ? { session } : {}),
    ...(user !== undefined ? { user } : {}),
  };
}

function render(
  ctx: Ctx,
  req: AppRequest,
  options: Parameters<typeof page>[0] & { status?: number },
): AppResponse {
  const cart = req.user !== undefined ? getCart(ctx.db, req.user.id) : undefined;
  return html(
    page({
      ...options,
      ...(req.user !== undefined ? { user: req.user } : {}),
      ...(cart !== undefined ? { cartCount: cart.itemCount } : {}),
    }),
    options.status ?? 200,
  );
}

export function createShopApp(db: Db, config: ShopConfig): ShopApp {
  const tg = createShopTrailGate(db, config);
  const ctx: Ctx = { db, config, tg };
  const api = createAgentApi(db, tg.tg, tg.spendingPolicy);
  const router = buildRoutes(ctx);

  return {
    tg,
    db,
    handle: async (raw) => {
      // Protocol and agent-API traffic goes through the SDK with the
      // issuer-absolute URI the agent signed (the adapter rule in
      // INTEGRATION.md).
      const url = new URL(raw.url, config.issuer);
      if (isProtectedPath(url.pathname)) {
        const hostReq: HostRequest = {
          method: raw.method,
          url: `${config.issuer}${raw.url}`,
          headers: raw.headers,
          ...(raw.body !== undefined ? { body: raw.body } : {}),
        };
        const res = await protocolOrApi(ctx, api.dispatch, hostReq);
        return {
          status: res.status,
          headers: res.headers ?? {},
          body:
            res.body === undefined
              ? ''
              : typeof res.body === 'string'
                ? res.body
                : JSON.stringify(res.body),
        };
      }
      const req = hostToAppRequest(ctx, raw);
      try {
        const matched = router.match(req.method, req.path);
        if (matched === undefined) {
          return render(ctx, req, {
            title: 'Not found',
            status: 404,
            body: renderNotFound(),
          });
        }
        req.params = matched.params;
        return await matched.handler(req);
      } catch (err) {
        if (err instanceof CsrfError) {
          return render(ctx, req, {
            title: 'Form expired',
            body: renderError('Your form session expired. Go back and try again.'),
          });
        }
        throw err;
      }
    },
  };
}

async function protocolOrApi(
  ctx: Ctx,
  apiDispatch: (req: HostRequest) => Promise<HostResponse | undefined>,
  req: HostRequest,
): Promise<HostResponse> {
  const path = new URL(req.url).pathname;
  if (path === '/.well-known/trailgate') {
    const res = await ctx.tg.tg.handleDiscovery();
    res.headers = { ...res.headers, 'cache-control': 'max-age=300' };
    return res;
  }
  if (path === '/tg/grant-request') {
    return ctx.tg.tg.handleGrantRequest(req);
  }
  if (path === '/tg/grant-redemption') {
    return ctx.tg.tg.handleRedemption(req);
  }
  if (path === '/tg/grant-revocation') {
    return ctx.tg.tg.handleRevocation(req);
  }
  if (path === '/tg/grant-status') {
    return ctx.tg.tg.handleStatus(req);
  }
  const apiRes = await apiDispatch(req);
  if (apiRes !== undefined) {
    return apiRes;
  }
  return {
    status: 404,
    headers: { 'content-type': 'application/json' },
    body: { error: { code: 'shop.route.not_found', message: 'unknown route' } },
  };
}

function nextPath(req: AppRequest, form: Record<string, string>): string {
  const local = (v: string | null | undefined): string | undefined =>
    typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') ? v : undefined;
  return local(form.next) ?? local(req.url.searchParams.get('next')) ?? '/';
}

const LOGIN_WINDOW_SECONDS = 600;
const LOGIN_MAX_FAILURES = 5;

/** Bounded in-memory throttle on failed sign-ins, keyed by normalized email. */
function createLoginLimiter() {
  const failures = new Map<string, { count: number; resetAt: number }>();
  const key = (email: string) => email.trim().toLowerCase();
  return {
    throttled(email: string, now: number): boolean {
      const entry = failures.get(key(email));
      return entry !== undefined && entry.resetAt > now && entry.count >= LOGIN_MAX_FAILURES;
    },
    recordFailure(email: string, now: number): void {
      if (failures.size > 10_000) {
        for (const [k, v] of failures) {
          if (v.resetAt <= now) {
            failures.delete(k);
          }
        }
      }
      const k = key(email);
      const entry = failures.get(k);
      if (entry === undefined || entry.resetAt <= now) {
        failures.set(k, { count: 1, resetAt: now + LOGIN_WINDOW_SECONDS });
      } else {
        entry.count += 1;
      }
    },
    reset(email: string): void {
      failures.delete(key(email));
    },
  };
}

function siteIdentity(ctx: Ctx) {
  return {
    name: 'ExampleShop',
    issuer: ctx.config.issuer,
    spendingPolicy: {
      maxCharge: ctx.tg.spendingPolicy.maxCharge,
      maxGrantBudget: ctx.tg.spendingPolicy.maxGrantBudget,
    },
  };
}

function buildRoutes(ctx: Ctx): Router {
  const { db } = ctx;
  const router = new Router();
  const loginLimiter = createLoginLimiter();

  const authed = (
    handler: (
      req: AppRequest,
      user: NonNullable<AppRequest['user']>,
    ) => Promise<AppResponse> | AppResponse,
  ): ((req: AppRequest) => Promise<AppResponse> | AppResponse) => {
    return (req) => {
      const auth = reqSession(req);
      if (auth === undefined) {
        return loginRedirect(req.path + (req.url.search === '' ? '' : req.url.search));
      }
      return handler(req, auth.user);
    };
  };

  // ---------- storefront ----------

  router.get('/', (req) =>
    render(ctx, req, {
      title: 'Goods for a considered desk',
      section: 'home',
      body: renderHome({ ...(req.user !== undefined ? { user: req.user } : {}) }, listProducts(db)),
    }),
  );

  router.get('/products', (req) => {
    const category = req.query.get('category') ?? undefined;
    const q = req.query.get('q') ?? undefined;
    const sort = req.query.get('sort') ?? 'featured';
    const products =
      q !== undefined && q.trim() !== ''
        ? searchProducts(db, q)
        : category !== undefined
          ? listProducts(db, category)
          : listProducts(db);
    switch (sort) {
      case 'name':
        products.sort((a, b) => a.name.localeCompare(b.name));
        break;
      case 'price_asc':
        products.sort((a, b) => a.price.amount - b.price.amount);
        break;
      case 'price_desc':
        products.sort((a, b) => b.price.amount - a.price.amount);
        break;
      default:
        break;
    }
    return render(ctx, req, {
      title: 'Catalog',
      section: 'products',
      body: renderCatalog({}, products, listCategories(db), category, q, sort),
    });
  });

  router.get('/products/:sku', (req) => {
    const product = getProduct(db, req.params.sku as string);
    if (product === undefined) {
      return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
    }
    const related = listProducts(db, product.category)
      .filter((p) => p.sku !== product.sku)
      .slice(0, 4);
    return render(ctx, req, {
      title: product.name,
      section: 'products',
      body: renderProduct(
        {
          ...(req.session !== undefined ? { session: req.session } : {}),
          ...(req.user !== undefined ? { user: req.user } : {}),
        },
        product,
        related,
      ),
    });
  });

  // ---------- cart ----------

  router.get(
    '/cart',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Your cart',
        section: 'cart',
        body: renderCart(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          getCart(db, user.id),
        ),
      }),
    ),
  );

  const cartPost = (fn: (form: Record<string, string>, userId: string) => void, target = '/cart') =>
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      try {
        fn(form, user.id);
      } catch (err) {
        if (err instanceof CartError) {
          return render(ctx, req, {
            title: 'Your cart',
            section: 'cart',
            body: renderCart(
              {
                ...(req.session !== undefined ? { session: req.session } : {}),
                flash: { kind: 'error', text: err.message },
              },
              getCart(db, user.id),
            ),
            flash: { kind: 'error', text: err.message },
          });
        }
        throw err;
      }
      return redirect(target);
    });

  router.post(
    '/cart/add',
    cartPost((form, userId) => {
      setCartQty(db, userId, form.sku ?? '', Number.parseInt(form.qty ?? '1', 10));
    }),
  );
  router.post(
    '/cart/update',
    cartPost((form, userId) => {
      setCartQty(db, userId, form.sku ?? '', Number.parseInt(form.qty ?? '0', 10));
    }),
  );
  router.post(
    '/cart/remove',
    cartPost((form, userId) => {
      setCartQty(db, userId, form.sku ?? '', 0);
    }),
  );

  // ---------- checkout ----------

  router.get(
    '/checkout',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Checkout',
        section: 'cart',
        body: renderCheckout(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          getCart(db, user.id),
          getWallet(db, user.id),
          listAddresses(db, user.id),
        ),
      }),
    ),
  );

  router.post(
    '/checkout',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const addressId = form.address_id === '' ? undefined : form.address_id;
      try {
        const order = createOrderFromCart(db, user.id, {
          ...(addressId !== undefined ? { addressId } : {}),
          placedVia: 'user',
        });
        payOrder(db, order.id, user.id);
        return redirect(`/orders/${order.id}`);
      } catch (err) {
        if (
          err instanceof OrderError ||
          err instanceof InsufficientFundsError ||
          err instanceof WalletError
        ) {
          return render(ctx, req, {
            title: 'Checkout',
            section: 'cart',
            body: renderCheckout(
              { ...(req.session !== undefined ? { session: req.session } : {}) },
              getCart(db, user.id),
              getWallet(db, user.id),
              listAddresses(db, user.id),
              err.message,
            ),
          });
        }
        throw err;
      }
    }),
  );

  // ---------- orders ----------

  router.get(
    '/orders',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Orders',
        section: 'orders',
        body: renderOrderList({}, listOrders(db, user.id)),
      }),
    ),
  );

  router.get(
    '/orders/:id',
    authed((req, user) => {
      const order = getOrder(db, req.params.id as string, user.id);
      if (order === undefined) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      const address =
        order.addressId !== undefined ? getAddress(db, order.addressId, user.id) : undefined;
      return render(ctx, req, {
        title: `Order ${order.id}`,
        section: 'orders',
        body: renderOrderDetail(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          order,
          listOrderItems(db, order.id),
          getWallet(db, user.id),
          address,
        ),
      });
    }),
  );

  router.get(
    '/orders/:id/invoice',
    authed((req, user) => {
      const invoice = getInvoice(db, req.params.id as string, user.id);
      if (invoice === undefined) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      return render(ctx, req, {
        title: `Invoice ${invoice.order.id}`,
        section: 'orders',
        body: renderInvoice({}, invoice),
      });
    }),
  );

  router.post(
    '/orders/:id/pay',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const id = req.params.id as string;
      try {
        payOrder(db, id, user.id);
      } catch (err) {
        if (err instanceof OrderError || err instanceof InsufficientFundsError) {
          return redirect(`/orders/${id}`);
        }
        throw err;
      }
      return redirect(`/orders/${id}`);
    }),
  );

  router.post(
    '/orders/:id/cancel',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const id = req.params.id as string;
      try {
        cancelOrder(db, id, user.id);
      } catch (err) {
        if (!(err instanceof OrderError)) {
          throw err;
        }
      }
      return redirect(`/orders/${id}`);
    }),
  );

  router.post(
    '/orders/:id/refund',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const id = req.params.id as string;
      try {
        const order = getOrder(db, id, user.id);
        const { refund } = refundOrder(db, id, user.id);
        // Spec section 12: refunds restore grant headroom as offsetting entries.
        if (order?.grantJti !== undefined) {
          await ctx.tg.tg.config.stores.ledger.postRefund({
            grantId: order.grantJti,
            amount: refund,
            now: Math.floor(Date.now() / 1000),
          });
        }
      } catch (err) {
        if (!(err instanceof OrderError)) {
          throw err;
        }
      }
      return redirect(`/orders/${id}`);
    }),
  );

  // ---------- account ----------

  router.get(
    '/account',
    authed((req, user) =>
      render(ctx, req, { title: 'Account', section: 'account', body: renderProfile({ user }) }),
    ),
  );

  router.get(
    '/account/addresses',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Addresses',
        section: 'account',
        body: renderAddresses(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          listAddresses(db, user.id),
        ),
      }),
    ),
  );

  router.post(
    '/account/addresses',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      try {
        saveAddress(db, user.id, {
          label: form.label ?? '',
          line1: form.line1 ?? '',
          ...(form.line2 !== undefined && form.line2 !== '' ? { line2: form.line2 } : {}),
          city: form.city ?? '',
          ...(form.region !== undefined && form.region !== '' ? { region: form.region } : {}),
          postcode: form.postcode ?? '',
          country: form.country ?? '',
          isDefault: form.is_default === 'on',
        });
      } catch (err) {
        if (err instanceof ValidationError) {
          return render(ctx, req, {
            title: 'Addresses',
            section: 'account',
            body: renderAddresses(
              {
                ...(req.session !== undefined ? { session: req.session } : {}),
                flash: { kind: 'error', text: err.message },
              },
              listAddresses(db, user.id),
            ),
            flash: { kind: 'error', text: err.message },
          });
        }
        throw err;
      }
      return redirect('/account/addresses');
    }),
  );

  router.post(
    '/account/addresses/:id/delete',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      deleteAddress(db, req.params.id as string, user.id);
      return redirect('/account/addresses');
    }),
  );

  // ---------- wallet ----------

  router.get(
    '/account/wallet',
    authed((req, user) =>
      render(ctx, req, {
        title: 'Wallet',
        section: 'account',
        body: renderWallet(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          getWallet(db, user.id),
          listWalletEntries(db, user.id),
        ),
      }),
    ),
  );

  router.post(
    '/account/wallet/topup',
    authed((req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const amount = Number.parseFloat(form.amount ?? '0');
      try {
        // Form posts major units; convert to integer minor units.
        const minor = Math.round(amount * 100);
        topUp(db, user.id, { amount: minor, currency: 'USD' });
      } catch (err) {
        if (err instanceof WalletError) {
          return render(ctx, req, {
            title: 'Wallet',
            section: 'account',
            body: renderWallet(
              { ...(req.session !== undefined ? { session: req.session } : {}) },
              getWallet(db, user.id),
              listWalletEntries(db, user.id),
            ),
            flash: { kind: 'error', text: err.message },
          });
        }
        throw err;
      }
      return redirect('/account/wallet');
    }),
  );

  // ---------- agent connections and activity ----------

  router.get(
    '/account/connections',
    authed((req, user) => {
      const requestRows = db
        .prepare(
          'SELECT request_id, created_at, expires_at, status, body, agent_jkt, grant_id FROM tg_grant_requests WHERE subject = ? ORDER BY created_at DESC',
        )
        .all(user.id) as {
        request_id: string;
        created_at: number;
        expires_at: number;
        status: string;
        body: string;
        agent_jkt: string;
        grant_id: string | null;
      }[];
      const requests: GrantRequestView[] = requestRows.map((row) => {
        const body = JSON.parse(row.body) as { permissions?: string[] };
        return {
          requestId: row.request_id,
          createdAt: row.created_at,
          expiresAt: row.expires_at,
          status: row.status,
          agentJkt: row.agent_jkt,
          permissions: body.permissions ?? [],
          ...(row.grant_id !== null ? { grantId: row.grant_id } : {}),
        };
      });
      const grantRows = db
        .prepare('SELECT * FROM tg_grants WHERE subject = ? ORDER BY issued_at DESC')
        .all(user.id) as Parameters<typeof grantViewOf>[0][];
      const grants: IssuedGrantView[] = grantRows.map(grantViewOf);
      return render(ctx, req, {
        title: 'Agent connections',
        section: 'account',
        body: renderConnections(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          requests,
          grants,
          ctx.tg.spendingPolicy,
        ),
      });
    }),
  );

  router.post(
    '/account/connections/:jti/revoke',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const jti = req.params.jti as string;
      const grant = db.prepare('SELECT subject FROM tg_grants WHERE jti = ?').get(jti) as
        | { subject: string | null }
        | undefined;
      if (grant?.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      await ctx.tg.tg.revokeGrant(jti, {
        reason:
          typeof form.reason === 'string' && form.reason !== ''
            ? form.reason
            : 'revoked from account page',
        actor: `user:${user.id}`,
      });
      // Redirect to the detail page, which re-reads the stored record and
      // shows the actual persisted status rather than optimistic UI state.
      return redirect(`/account/connections/${jti}`);
    }),
  );

  const SCOPE_RESOURCE_TEMPLATE: Record<string, string> = {
    'tg.cart.read': 'cart:{user}',
    'tg.cart.write': 'cart:{user}',
    'tg.wallet.read': 'wallet:{user}',
    'tg.wallet.charge': 'wallet:{user}',
  };
  // Post-issuance scope control: the user ticks what the agent may do on
  // the connection page and the site applies it in place. Only the site
  // can change a grant's scope; the set is validated against the site's
  // advertised vocabulary and resource selectors are derived from the
  // subject's own resources through the same consent-time binding.
  router.post(
    '/account/connections/:jti/scope',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const formValues = parseFormValues(req);
      const jti = req.params.jti as string;
      const grantRow = db.prepare('SELECT * FROM tg_grants WHERE jti = ?').get(jti) as
        | ({
            subject: string | null;
          } & Parameters<typeof grantViewOf>[0])
        | undefined;
      if (grantRow?.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      const selected = formValues.perm ?? [];
      if (selected.length === 0) {
        return render(ctx, req, {
          title: 'Nothing selected',
          status: 400,
          body: renderError('Keep at least one permission, or revoke the connection instead.'),
        });
      }
      // Permissions that touch subject-owned resources get their selectors
      // from the same {user} binding used at consent time.
      const templates = selected
        .map((perm) => SCOPE_RESOURCE_TEMPLATE[perm])
        .filter((t): t is string => t !== undefined);
      const resources = templates.length > 0 ? bindShopSelectors(templates, user.id) : undefined;
      // Spending limits are editable per grant; they clamp to the site
      // policy caps and every other constraint the grant carries is kept.
      const current = grantViewOf(grantRow);
      const currency = ctx.tg.spendingPolicy.currency;
      const kept = current.constraints.filter(
        (c) => c.type !== 'max_amount' && c.type !== 'cumulative_budget',
      );
      const moneyField = (name: string, cap: number): number => {
        const raw = form[name];
        if (raw === undefined || raw.trim() === '') {
          return cap;
        }
        const minor = Math.round(Number.parseFloat(raw) * 100);
        if (!Number.isFinite(minor) || minor < 0) {
          throw new TrailGateError(Codes.REQUEST_MALFORMED, `${name} must be a positive amount`);
        }
        return Math.min(minor, cap);
      };
      try {
        const constraints: IssuedGrantView['constraints'] = [
          ...kept,
          {
            type: 'max_amount',
            params: {
              amount: moneyField('max_charge', ctx.tg.spendingPolicy.maxCharge.amount),
              currency,
            },
          },
          {
            type: 'cumulative_budget',
            params: {
              amount: moneyField('total_budget', ctx.tg.spendingPolicy.maxGrantBudget.amount),
              currency,
            },
          },
        ];
        await ctx.tg.tg.updateGrantScope(jti, {
          permissions: selected,
          ...(resources !== undefined ? { resources } : {}),
          constraints,
          actor: `user:${user.id}`,
        });
      } catch (err) {
        return render(ctx, req, {
          title: 'Could not update permissions',
          status: 400,
          body: renderError(err instanceof Error ? err.message : 'The change was refused.'),
        });
      }
      return redirect(`/account/connections/${jti}`);
    }),
  );

  const grantViewOf = (row: {
    jti: string;
    agent_jkt: string;
    issued_at: number;
    expires_at: number;
    status: 'active' | 'revoked';
    request_id: string;
    permissions: string;
    effective_permissions: string | null;
    effective_resources: string | null;
    effective_constraints: string | null;
    revoked_at: number | null;
    revocation_reason: string | null;
    revocation_actor: string | null;
  }): IssuedGrantView => {
    const reqRow = db
      .prepare(
        'SELECT effective_resources, effective_constraints FROM tg_grant_requests WHERE request_id = ?',
      )
      .get(row.request_id) as
      | {
          effective_resources: string | null;
          effective_constraints: string | null;
        }
      | undefined;
    const jsonField = (value: string | null | undefined): unknown[] =>
      value === null || value === undefined ? [] : (JSON.parse(value) as unknown[]);
    const issuedPermissions = jsonField(row.permissions) as string[];
    return {
      jti: row.jti,
      agentJkt: row.agent_jkt,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      status: row.status,
      issuedPermissions,
      permissions: jsonField(row.effective_permissions ?? row.permissions) as string[],
      resources: jsonField(row.effective_resources ?? reqRow?.effective_resources) as string[],
      constraints: jsonField(
        row.effective_constraints ?? reqRow?.effective_constraints,
      ) as IssuedGrantView['constraints'],
      ...(row.revoked_at !== null ? { revokedAt: row.revoked_at } : {}),
      ...(row.revocation_reason !== null ? { revocationReason: row.revocation_reason } : {}),
      ...(row.revocation_actor !== null ? { revocationActor: row.revocation_actor } : {}),
    };
  };

  router.get(
    '/account/connections/:jti',
    authed(async (req, user) => {
      const jti = req.params.jti as string;
      const row = db.prepare('SELECT * FROM tg_grants WHERE jti = ?').get(jti) as
        | {
            jti: string;
            agent_jkt: string;
            issued_at: number;
            expires_at: number;
            status: 'active' | 'revoked';
            request_id: string;
            subject: string | null;
            permissions: string;
            effective_permissions: string | null;
            effective_resources: string | null;
            effective_constraints: string | null;
            revoked_at: number | null;
            revocation_reason: string | null;
            revocation_actor: string | null;
          }
        | undefined;
      if (row === undefined || row.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      const grant = grantViewOf(row);
      const budgets = grant.constraints
        .filter((c) => c.type === 'cumulative_budget')
        .map((c) => c.params as { amount: number; currency: string });
      const consumed = await ctx.tg.tg.config.stores.ledger.consumedMinorUnits(
        jti,
        ctx.tg.spendingPolicy.currency,
      );
      const reserved = await ctx.tg.tg.config.stores.ledger.reservedMinorUnits(
        jti,
        ctx.tg.spendingPolicy.currency,
      );
      const receipts = db
        .prepare(
          'SELECT id, decision, target, method, created_at FROM tg_receipts WHERE grant_id = ? ORDER BY created_at DESC LIMIT 50',
        )
        .all(jti) as {
        id: string;
        decision: string;
        target: string;
        method: string;
        created_at: number;
      }[];
      return render(ctx, req, {
        title: `Grant ${jti}`,
        section: 'account',
        body: renderGrantDetail(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          grant,
          { consumed, reserved, budgets },
          ctx.tg.audit.listForGrant(jti),
          receipts,
          ctx.tg.spendingPolicy,
        ),
      });
    }),
  );

  router.get(
    '/account/receipts',
    authed((req, user) => {
      const rows = db
        .prepare(
          `SELECT r.id, r.grant_id, r.decision, r.code, r.method, r.target, r.created_at
           FROM tg_receipts r JOIN tg_grants g ON g.jti = r.grant_id
           WHERE g.subject = ? ORDER BY r.created_at DESC LIMIT 200`,
        )
        .all(user.id) as unknown as StoredReceiptRow[];
      return render(ctx, req, {
        title: 'Receipts',
        section: 'account',
        body: renderReceiptList(
          { ...(req.session !== undefined ? { session: req.session } : {}) },
          rows,
        ),
      });
    }),
  );

  const siteKeyResolver = {
    resolve: async (kid: string) =>
      ctx.tg.tg.config.signingKeys.find((k) => k.kid === kid)?.publicJwk,
  };
  const verify = async (token: string): Promise<ReceiptVerdict> => {
    try {
      const payload = await verifyReceipt(token, {
        resolveSiteKey: siteKeyResolver,
        issuer: ctx.config.issuer,
        audience: ctx.config.issuer,
      });
      return { kind: 'verified', payload };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        kind: msg.includes('json') || msg.includes('compact') ? 'malformed' : 'unverified',
        reason: msg,
      };
    }
  };

  router.get(
    '/account/receipts/:id',
    authed(async (req, user) => {
      const id = req.params.id as string;
      const row = db
        .prepare(
          `SELECT r.* FROM tg_receipts r JOIN tg_grants g ON g.jti = r.grant_id
           WHERE r.id = ? AND g.subject = ?`,
        )
        .get(id, user.id) as (StoredReceiptRow & { receipt_jws: string }) | undefined;
      if (row === undefined) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      const verdict = await verify(row.receipt_jws);
      return render(ctx, req, {
        title: `Receipt ${id}`,
        section: 'account',
        body: renderReceiptDetail(verdict, row.receipt_jws, {
          grant_id: row.grant_id,
          method: row.method,
          target: row.target,
          created_at: row.created_at,
        }),
      });
    }),
  );

  router.post(
    '/account/receipts/verify',
    authed(async (req, _user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const token = (form.receipt ?? '').trim();
      const verdict =
        token === ''
          ? ({ kind: 'malformed', reason: 'no token provided' } as ReceiptVerdict)
          : await verify(token);
      return render(ctx, req, {
        title: 'Verify a receipt',
        section: 'account',
        body: renderReceiptDetail(verdict, token),
      });
    }),
  );

  router.get(
    '/account/activity',
    authed((req, user) => {
      const grants = db
        .prepare('SELECT jti, request_id FROM tg_grants WHERE subject = ?')
        .all(user.id) as { jti: string; request_id: string }[];
      const requestIds = db
        .prepare('SELECT request_id FROM tg_grant_requests WHERE subject = ?')
        .all(user.id) as { request_id: string }[];
      const rows: ActivityRow[] = [];
      for (const grant of grants) {
        rows.push(...ctx.tg.audit.listForGrant(grant.jti));
        rows.push(...ctx.tg.audit.listForRequest(grant.request_id));
      }
      for (const row of requestIds) {
        rows.push(...ctx.tg.audit.listForRequest(row.request_id));
      }
      const seen = new Set<string>();
      const deduped = rows.filter((row) => {
        if (seen.has(row.id)) {
          return false;
        }
        seen.add(row.id);
        return true;
      });
      deduped.sort((a, b) => b.event.at - a.event.at);
      const agentOrders = listOrders(db, user.id).filter((o) => o.placedVia === 'agent');
      return render(ctx, req, {
        title: 'Activity',
        section: 'account',
        body: renderActivity({}, deduped, agentOrders),
      });
    }),
  );

  // ---------- consent (spec section 10.3, host-owned) ----------

  router.get(
    '/tg/consent',
    authed(async (req, _user) => {
      const requestId = req.query.get('request_id') ?? '';
      const view = await ctx.tg.tg.getConsent(requestId);
      if (view === undefined) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      return render(ctx, req, {
        title: 'Approve agent access',
        section: 'account',
        body: renderConsent(
          {
            ...(req.user !== undefined ? { user: req.user } : {}),
            ...(req.session !== undefined ? { session: req.session } : {}),
          },
          view,
          siteIdentity(ctx),
        ),
      });
    }),
  );

  router.post(
    '/tg/consent/decide',
    authed(async (req, user) => {
      const form = parseForm(req);
      const formValues = parseFormValues(req);
      requireCsrf(req, form);
      const requestId = form.request_id ?? '';
      const decision = form.decision === 'approve' ? 'approve' : 'deny';
      try {
        // The scope editor posts each approved permission as a repeated
        // `perm` field; unchecked permissions are simply not narrowed in.
        if (decision === 'approve' && (formValues.perm ?? []).length === 0) {
          throw new TrailGateError(
            Codes.REQUEST_MALFORMED,
            'select at least one permission, or deny the request',
          );
        }
        const lifetimeSeconds =
          form.lifetime_seconds !== undefined
            ? Number.parseInt(form.lifetime_seconds, 10)
            : undefined;
        const narrow =
          decision === 'approve'
            ? {
                permissions: formValues.perm ?? [],
                ...(lifetimeSeconds !== undefined ? { lifetimeSeconds } : {}),
              }
            : undefined;
        const outcome = await ctx.tg.tg.decideConsent(requestId, decision, user.id, narrow);
        if (outcome.redirectTo !== undefined) {
          return { status: 302, headers: { location: outcome.redirectTo } };
        }
        return redirect('/account/connections');
      } catch (err) {
        if (isTrailGateError(err)) {
          const view = await ctx.tg.tg.getConsent(requestId);
          return render(ctx, req, {
            title: 'Approve agent access',
            section: 'account',
            status: err.httpStatus === 404 ? 404 : 400,
            body:
              view === undefined
                ? renderError(err.message)
                : renderConsent(
                    {
                      ...(req.user !== undefined ? { user: req.user } : {}),
                      ...(req.session !== undefined ? { session: req.session } : {}),
                    },
                    view,
                    siteIdentity(ctx),
                  ),
            flash: { kind: 'error', text: err.message },
          });
        }
        throw err;
      }
    }),
  );

  // ---------- per-request approval (approval_threshold, spec section 12.4) ----------

  router.get(
    '/tg/request-approval',
    authed(async (req, user) => {
      const id = req.query.get('id') ?? '';
      const record = await ctx.tg.tg.config.stores.approvals.get(id);
      if (record === undefined) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      const grant = await ctx.tg.tg.config.stores.grants.get(record.grantId);
      if (grant === undefined || grant.subject !== user.id) {
        return render(ctx, req, { title: 'Not found', status: 404, body: renderNotFound() });
      }
      return render(ctx, req, {
        title: 'Approve agent charge',
        section: 'account',
        body: renderRequestApproval(
          {
            ...(req.user !== undefined ? { user: req.user } : {}),
            ...(req.session !== undefined ? { session: req.session } : {}),
          },
          { record, grantJti: record.grantId },
        ),
      });
    }),
  );

  router.post(
    '/tg/request-approval/decide',
    authed(async (req, user) => {
      const form = parseForm(req);
      requireCsrf(req, form);
      const approvalId = form.approval_id ?? '';
      const decision = form.decision === 'approve' ? 'approve' : 'deny';
      try {
        await ctx.tg.tg.decideRequestApproval(approvalId, decision, user.id);
        return redirect('/account/connections');
      } catch (err) {
        if (isTrailGateError(err)) {
          return render(ctx, req, {
            title: 'Approve agent charge',
            section: 'account',
            status: err.httpStatus === 404 ? 404 : 400,
            body: renderError(err.message),
          });
        }
        throw err;
      }
    }),
  );

  // ---------- auth ----------

  router.get('/login', (req) => {
    if (req.user !== undefined) {
      return redirect('/');
    }
    const next = req.query.get('next') ?? '/';
    return render(ctx, req, { title: 'Sign in', body: renderLogin({}, next) });
  });

  router.post('/login', async (req) => {
    const form = parseForm(req);
    const next = nextPath(req, form);
    const email = form.email ?? '';
    const now = Math.floor(Date.now() / 1000);
    if (loginLimiter.throttled(email, now)) {
      return render(ctx, req, {
        title: 'Sign in',
        status: 429,
        body: renderLogin({}, next, 'Too many sign-in attempts. Try again later.'),
      });
    }
    try {
      const user = authenticate(db, email, form.password ?? '');
      loginLimiter.reset(email);
      const session = createSession(db, user.id);
      return {
        status: 303,
        headers: {
          location: next,
          'set-cookie': sessionCookie(
            session.id,
            ctx.config.tls,
            session.expiresAt - Math.floor(Date.now() / 1000),
          ),
        },
      };
    } catch (err) {
      if (err instanceof AuthError) {
        loginLimiter.recordFailure(email, now);
        return render(ctx, req, {
          title: 'Sign in',
          status: 401,
          body: renderLogin({}, next, err.message),
        });
      }
      throw err;
    }
  });

  router.get('/register', (req) => {
    if (req.user !== undefined) {
      return redirect('/');
    }
    const next = req.query.get('next') ?? '/';
    return render(ctx, req, { title: 'Create account', body: renderRegister({}, next) });
  });

  router.post('/register', async (req) => {
    const form = parseForm(req);
    const next = nextPath(req, form);
    try {
      const user = createUser(db, {
        email: form.email ?? '',
        name: form.name ?? '',
        password: form.password ?? '',
      });
      const session = createSession(db, user.id);
      return {
        status: 303,
        headers: {
          location: next,
          'set-cookie': sessionCookie(
            session.id,
            ctx.config.tls,
            session.expiresAt - Math.floor(Date.now() / 1000),
          ),
        },
      };
    } catch (err) {
      if (err instanceof ValidationError) {
        return render(ctx, req, {
          title: 'Create account',
          status: 400,
          body: renderRegister({}, next, err.message),
        });
      }
      throw err;
    }
  });

  router.post('/logout', (req) => {
    if (req.session !== undefined) {
      destroySession(db, req.session.id);
    }
    return {
      status: 303,
      headers: { location: '/', 'set-cookie': clearSessionCookie(ctx.config.tls) },
    };
  });

  return router;
}
