# Known limitations

Draft 0.1, honestly stated. Each item names what is true today, not what is
planned. See `docs/security-guarantees.md` for the guarantee model and
`docs/release-review-0.1.md` for the test evidence behind what IS covered.

## Protocol

- **Experimental draft.** No certification, no formal verification, no
  production-readiness claim. The wire format may change before 1.0.
- **Discovery trust is TOFU, not PKI.** Documents carry a
  `trailgate-discovery-signature` header and agents pin `signing_keys`
  across fetches, so substitution after first contact fails closed with
  `tg.discovery.key_changed`. First contact still relies on TLS plus the
  human consent check; a compromised CA at first contact is out of scope.
  Sites that omit the signature header serve unsigned documents.
- **`approval_threshold` decides per operation, not per policy.** A site
  wanting "approve once, then allow all 8900-charges for a day" must express
  that as application policy (stage 13), not a constraint.
- **No grant refresh or attenuation.** Grant expiry is final; re-request.
- **Constraint vocabulary is closed.** Six registered types; everything else
  fails closed at intake. Disjunctive logic, wildcards, percentage limits,
  and per-product conditions are deliberately out of 0.1.

## Implementation

- **`node:sqlite` is the reference store.** It is correct under
  `BEGIN IMMEDIATE` transactions and proven across processes, but it is a
  demo store. A production deployment implements the ports in
  `packages/server/src/ports.ts` over its own database and proves them with
  `runPortContractSuite` before trusting the deployment.
- **Key custody is development-grade.** ExampleShop stores its site signing
  JWK in SQLite; `SoftwareKeyProvider`/`FileKeyProvider` hold agent keys in
  process memory or a 0600 file. Production custody (KMS, OS keystore,
  hardware) goes behind the same interfaces.
- **No framework adapters.** The Server SDK speaks `HostRequest`/
  `HostResponse`; only a `node:http` adapter is exercised. Express/Fastify
  glue is host code.
- **Edge defenses are not a library.** Body and header size caps exist in
  the SDK; WAF, connection limits, and rate shaping belong to your
  infrastructure.
- **`node:sqlite` is flagged experimental by Node.** The API may change
  across Node versions.

## ExampleShop

- **The wallet is simulated.** Ledger semantics are real (reservations,
  refunds, reconciliation); money is not. No real payment integration,
  fraud analysis, or settlement exists.
- **Demo credentials ship in the seed.** `ada@example.com` /
  `demo-pass-1234` is for local evaluation only.
- **In-process test transport plus one live-HTTP test.** Most integration
  tests call `app.handle` directly; `milestone-a.test.ts` is the spawn-real-
  server proof. TLS mode is exercised manually via `pnpm certs`.
