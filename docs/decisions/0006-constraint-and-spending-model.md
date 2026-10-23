# 0006. Constraint model and spending semantics

Status: accepted, 2026-10-23.

## Context

Grants carry constraints such as maximum amount, cumulative budget, and rate limits. Constraints must be deterministic, generic (not ecommerce-specific), and impossible for an agent to widen by editing a request.

## Decision

- A constraint is an object `{ "type": "<name>", "params": { ... } }` where `type` names a registered constraint type and `params` is type-specific. The type registry lives in `spec/protocol.md` and is append-only.
- Evaluation is conjunctive: every constraint in the grant must pass for the request to proceed. There is no disjunction, no priority, and no override in 0.1. Ambiguity fails closed.
- A grant containing a constraint type the server does not support MUST be rejected at issuance; a request evaluated against an unknown constraint type MUST be denied.
- Constraints are bound inside the signed grant. Agents may send proposed values (for example a charge amount) in the request; the server evaluates authoritative constraints against authoritative state, not against agent-supplied constraint copies.
- Money is integer minor units plus an ISO 4217 currency code, everywhere: constraints, requests, receipts, ledgers.
- Spending uses a reservation lifecycle: `reserved` then `consumed` or `released`. The cumulative budget check and the reservation insert are one atomic operation against the ledger, so concurrent requests cannot overspend. Failed operations release the reservation; refunds post as offsetting ledger entries; reconciliation is per-grant ledger state.

## Rationale

- Conjunctive evaluation with a type registry is the smallest model that covers the stated requirements while leaving the type space open. Disjunction and override semantics were rejected for 0.1: they add ordering questions and ambiguity with no demonstrated need yet.
- The atomicity rule is the only way the stated invariant (concurrent requests never exceed budget) holds.

## Consequences

- New constraint types require a spec change and registry entry; server implementers can propose types but cannot ship them unilaterally in the shared vocabulary.
- The model is generic: nothing in the constraint layer knows about carts, wallets, or ExampleShop.
