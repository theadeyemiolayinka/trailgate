# 0010. Discovery action catalog

Status: accepted, draft 0.1 extension

## Context

Draft 0.1 discovery advertises `permissions` and `constraint_types` as flat
identifier lists. An agent that holds a grant for `tg.cart.read` still cannot
learn which URL to call, which method to use, or whether the route mutates
state, without out-of-band knowledge of the site. The stated goal of the
protocol is that an agent given a previously unknown origin can resolve "check
my cart" into a correctly shaped signed request after the user approves the
narrowest applicable grant.

A flat endpoint table alone is not enough either: the agent needs to know which
permission each route requires so it requests the right scope at consent time,
not after a denial.

## Decision

The discovery document gains an optional `actions` array of action
descriptors (spec section 5.2). Each descriptor declares `id`, `method`,
`path` (a `{name}`-templated path), `permission`, and optionally
`description`, `mutates`, `resource`, and `spend`.

Normative properties:

- Descriptors are advisory metadata. They carry no authority: authorization is
  still decided exclusively by the section 11 pipeline on every request.
- A site that advertises an action MUST enforce the declared permission on the
  named route. In the reference SDK the descriptor is emitted from the same
  `RouteProtection` declaration that drives enforcement, so drift between
  advertisement and enforcement is structurally prevented rather than audited.
- `permission` MUST appear in the document's `permissions` list.
- Absent `mutates` means agents MUST treat the action as mutating.
- `spend: true` tells the agent spend constraints can deny the action; it is a
  hint for UX and planning, not a budget declaration.

## Alternatives considered

- **OpenAPI/linkset embedding**: heavier than the problem requires, and the
  only fields the protocol actually needs are route, method, permission, and
  mutability. A site remains free to publish full API descriptions in an
  extension member (`additionalProperties` is open).
- **Actions inside `capabilities`**: rejected. `capabilities` describes
  protocol features of the site; `actions` is a catalog of resources. Keeping
  them separate lets schema validators and caches reason about each
  independently.

## Consequences

- Older agents ignore `actions` (`additionalProperties: true`); newer agents
  gain intent-to-endpoint mapping without any consent-flow change.
- The Server SDK emits the catalog automatically from `tg.protect` route
  declarations; hosts that bypass the SDK MUST keep the document consistent
  with their routes themselves.
- Advertised `path`/`resource` templates name structure, not data; sites MUST
  NOT embed per-user identifiers, because discovery is public.
