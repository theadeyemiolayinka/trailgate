# Key providers

`AgentSigner` is the signing boundary: it exposes `jkt`, `publicJwk`, `algorithm`, and `sign`. It has no export method, so key material never crosses into model runtimes, logs, or tool results. `AgentKeyProvider` is the custody boundary: where signers are generated, listed, and removed.

## Providers

| Provider | Config | What it protects | If unavailable |
| --- | --- | --- | --- |
| `ProcessKeyProvider` | none | Nothing at rest; keys die with the process | Process exit destroys keys; re-consent required |
| `SoftwareKeyProvider` | `generate()` / `fromPrivateJwk()` | In-process custody only | Same as above; `exportPrivateJwk()` exists for CLI persistence only and is not part of `AgentSigner` |
| `FileKeyProvider` | `new FileKeyProvider(path)` | File mode 0600 only | Reads fail to an empty view; writes fail loudly. Corrupt entries are skipped, never trusted |

`FileKeyProvider` is a development provider, clearly weaker: any process running as the same OS user can read the keys. It is not suitable for production secrets or real funds.

## OS secure storage

The interface is designed so a production provider returns `AgentSigner` implementations whose `sign` call is delegated into a protected backend: Windows DPAPI or CNG, macOS Keychain or Secure Enclave, Linux libsecret, a KMS or HSM handle. In those backends the private key is never materialized in the process at all.

Honest limits, per `docs/threat-model.md`: a keychain or OS secure store protects a key **at rest**. It does not prevent a compromised process from *invoking* that key while it is authorized to do so. A provider must document which of these it resists: extraction at rest, offline file theft, live process compromise, or none.

## No silent downgrade

There is deliberately no fallback path: if a configured provider is unavailable or locked, `list`/`get`/`generate` fail rather than spilling keys into a plaintext file or process memory. Choosing `FileKeyProvider` is an explicit development decision, not a fallback.

## Rotation

Agent keys rotate by issuing a new grant bound to the new `jkt` (spec section 13); a grant is never re-bound. `checkAccess` surfaces `wrong_key` when a stored grant's bound key is absent.
