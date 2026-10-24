# ExampleShop UI Overhaul

This document records the complete storefront rebuild of `apps/example-shop`:
the references studied, the problems found, what was redesigned, the
responsive fixes, what was verified end to end, and what remains.

The architecture is unchanged. ExampleShop is still a server-rendered Node
application producing HTML from template-string renderers; all business
logic, session handling, CSRF, wallet, order, and TrailGate enforcement code
is preserved. The overhaul replaced the presentation layer (shared shell,
stylesheet, and every page renderer) and added the minimal routing changes
needed to support the new UX (catalogue sorting, related products, homepage
data, static product imagery).

## References studied

- **ASOS** (asos.com): ecommerce structure. Adopted: a persistent header
  with wordmark, search, account and cart controls; category discovery
  tiles on the homepage; dense, consistent product grids; product cards
  driven entirely by catalogue data (name, price, availability, image).
- **Stripe design language** (stripe.design): visual discipline. Adopted:
  a small semantic token set (paper, ink, accent, borders, status colors),
  a restrained type hierarchy (display serif for headings and prices, a
  readable sans for UI text), generous but consistent spacing, and flat
  surfaces separated by hairline rules instead of heavy cards and shadows.
- **Stripe checkout guidance**: Adopted: a single-column focused checkout,
  order summary beside the form, wallet balance visible before committing,
  a distinct insufficient-funds state with a direct path to wallet top-up,
  and a clear order confirmation with status-specific next actions.
- **Desk/home goods retail**: the catalogue is desk accessories, stationery,
  drinkware, kitchen, and home goods, so the visual identity follows
  design-led homeware stores (warm paper background, forest-green accent,
  editorial serif) rather than a fashion or electronics template.

## Problems identified in the old UI

- The product catalogue had no imagery at all; cards were text-only boxes.
- The homepage was a sparse product list with no hero, no category
  discovery, and no brand identity.
- No shared shell: navigation, search, and cart state were inconsistent
  or missing between pages; there was no mobile navigation.
- Product pages were minimal; cart lines had no imagery or thumbnails.
- Checkout gave no visibility into the wallet balance or failure modes.
- The wallet page buried the balance in a table; funding controls were
  ambiguous.
- Consent was a dense technical dump: raw permission strings with no
  plain-language explanation of what the agent could do.
- Account, grant, receipt, and audit views were raw tables that forced
  horizontal page scroll on mobile.
- No design tokens: ad-hoc colors, spacing, and type sizes throughout.
- Horizontal overflow at phone widths on several pages.

## What was redesigned

### Shared system

- `src/server.ts`: static serving generalized from a hard-coded file map
  to safe `/static/*` resolution covering `app.css`, `favicon.svg`, and
  `public/products/`.
- `src/ui/layout.ts`: rewritten as the shared shell. Announcement bar,
  brand mark, catalogue/orders nav, live search box, account and cart
  controls with an item-count badge, a mobile hamburger menu, and a
  footer with category and account links. Plus shared primitives:
  `pageHead`, `statusBadge`, `emptyState`, `productCard` (image, name,
  category, price, stock), `productImage`/thumbnail helpers, `price`,
  `csrfField`, and an inline SVG icon set.
- `public/app.css`: replaced wholesale with a token-based design system:
  color, spacing, radius, and type tokens; header and mobile-nav; hero;
  category tiles; product grids and cards; product detail layout; cart
  and checkout compositions; forms; account navigation; responsive
  tables; consent/grant/receipt/audit surfaces; print styles for
  invoices; reduced-motion support.

### Storefront pages

- **Home** (`pages/home.ts`): editorial hero with photography and a real
  CTA, five category tiles, a featured-products row, and a restrained
  TrailGate explainer section. `app.ts` now supplies category and
  featured-product data.
- **Catalogue** (`pages/catalog.ts`): search, category chips, sort
  (featured, price asc/desc, name), product grid with badges, and a
  designed empty state. `app.ts` implements the sort.
- **Product** (`pages/product.ts`): two-column gallery + purchase panel,
  stock messaging, quantity control, related products (added in `app.ts`).
- **Cart** (`pages/cart.ts`): line items with thumbnails, per-line
  quantity forms, remove links, order summary card.
- **Checkout** (`pages/checkout.ts`): address selection, wallet payment
  explanation, balance-versus-total panel, insufficient-funds error with
  a top-up CTA, order summary.
- **Auth** (`pages/auth.ts`): centered split-feel login/register panels.

### Account and TrailGate pages

- **Account** (`pages/account.ts`) and **addresses**: sidebar account
  nav on desktop, horizontal tab strip on mobile.
- **Orders** (`pages/orders.ts`): table on desktop that becomes labeled
  cards on mobile; order detail with line thumbnails, status panel,
  invoice link, pay/cancel/refund actions by state.
- **Invoice** (`pages/invoice.ts`): print-friendly billing document.
- **Wallet** (`pages/wallet.ts`): prominent balance card, preset and
  custom top-up forms, mobile-friendly ledger.
- **Consent** (`pages/consent.ts`): restructured as a security decision
  surface: "at a glance" plain-language capability summary, site
  identity, agent key binding, requested vs effective terms, constraints
  and site spending policy, then the approve/deny area.
- **Connections** (`pages/connections.ts`): grant cards with status,
  permissions in plain language with protocol names, resources,
  constraints, expiry, and revoke.
- **Request approval** (`pages/request-approval.ts`): per-charge
  `approval_threshold` surface with amount, bound operation digest,
  expiry, and distinct approve/deny actions.
- **Receipts / activity** (`pages/receipts.ts`, `pages/activity.ts`):
  readable tables with mono IDs that wrap, inside horizontal scroll
  containers on mobile.

## Imagery

Thirteen photographs were sourced from Unsplash (license permits use
without attribution; unsplash.com/license), downloaded once, and served
locally from `apps/example-shop/public/products/` under SKU-keyed names
(`drk-mug-01.jpg`, `hero-desk.jpg`, etc.). Each maps to a real product or
the homepage hero. Cards and line items render an inline SVG placeholder
only if an image fails to load.

## Responsive fixes

Measured programmatically via headless Chrome + CDP (`scrollWidth` vs
`clientWidth` on every key route), not just eyeballed:

- Grid tracks changed to `minmax(0, 1fr)` so min-content children
  (tables, long IDs) can no longer blow out account/checkout columns.
- Long order/grant IDs wrap (`overflow-wrap: anywhere`).
- `.cat-tile-media` and cart line media needed `display: block` (inline
  spans ignore `aspect-ratio`, collapsing the tiles entirely).
- Account nav becomes a horizontally scrolling tab strip under 960px.
- Wide tables (receipts, activity, connections) sit inside
  `overflow-x` containers so only the table scrolls, never the page.
- Order lists switch to labeled cards under 760px.
- `.page-head` keeps eyebrow/title/lede grouped as a unit beside any
  page-level action.
- A specificity bug where `button.button` outranked `.button-secondary`
  and `.button-danger` made every secondary/danger `<button>` render as
  filled primary (cart "Set", "Deny", "Refund"). Fixed by removing the
  element-qualified selector.

Verified viewport sweep: 360x800, 390x844, 768x1024, 1024x768,
1280x800, 1440x900. Final measurements: `scrollWidth === clientWidth`
on every route checked, with no elements wider than the viewport.

## Verified journeys (real backend, real data)

- Register/login/session; catalog browse, search, sort, category filter.
- Product detail -> add to cart -> quantity update -> remove.
- Full checkout to a paid order; invoice; order list and detail.
- Insufficient-funds checkout returns the designed error state with a
  wallet top-up path.
- Wallet top-up and ledger entries.
- Real agent flow via the Agent SDK against the live server:
  consent page rendered with a genuine pending request; human approved
  through the browser form; grant `grt_...` issued and listed as active.
- Agent-placed order (`placed_via: agent`) visible in order history.
- `approval_threshold`: an 8,900-minor charge against a 5,000 threshold
  was denied with `tg.constraint.approval_required` and an approval URL;
  the human approved on `/tg/request-approval`; the retried charge
  settled and the order shows paid.
- Audit trail shows the full lifecycle (consent decision, signed
  requests, approval requested/decided, reservation created/consumed);
  receipts page lists signed receipts under the grant.

## Commands run

| Command | Result |
| --- | --- |
| `pnpm typecheck` (example-shop) | pass, 0 errors |
| `pnpm test` (example-shop) | 55 passed, 0 failed |
| `pnpm check` (repo, biome) | 0 errors; 9 lint warnings (specificity/`!important` hints in app.css) |
| `pnpm build` (repo) | all packages and the app build clean |

## Second pass (post-review refinement)

- Slogan copy removed: the announce bar now reads "Free shipping on all
  orders"; the footer carries one factual line ("demo storefront for the
  TrailGate protocol; wallet funds are simulated"); the hero lede dropped
  protocol jargon and keeps a single primary CTA.
- The "Shopping with an agent" card was flattened from a nested bordered
  panel into a clean three-column hairline strip ("Shop with an agent").
- The confusing "Agent-facing resource identifiers" panel was removed from
  the profile page; selectors now live behind a collapsed "Resource names
  an agent can request" disclosure on Agent connections.
- Receipts page labels simplified ("Receipts", "Receipt token" with a
  plain hint).
- Cart quantity action renamed "Set" to "Update" with matching control
  heights.
- Account nav active state is now a flat sunken background (the old
  rounded left-border treatment is gone); search field, cards, and inputs
  share one radius token; dashed empty states are solid hairlines; footer
  brand mark/name alignment fixed.

## Remaining limitations

- The audit table labels some `request_approval.*` events with their raw
  event names rather than friendly titles; readable, but slightly
  technical.
- Product images are fixed JPEGs (no srcset variants), sized
  appropriately but not art-directed per breakpoint.
- Search is a simple server-side name/description match; no pagination
  is needed at the current 12-product catalogue size.
- Mobile menu is a simple disclosure panel (no drawer animation), by
  design for a server-rendered app.
- Stock badges and prices are real; there are no ratings, reviews, or
  discount states because the data model does not carry them.
- `pnpm check` reports 9 Biome warnings (`noDescendingSpecificity`,
  `noImportantStyles` in print/reduced-motion blocks); they are
  intentional cascade and print overrides, not errors.
