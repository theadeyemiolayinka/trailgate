# @trailgate/agent

Client SDK for agents using TrailGate: site discovery, grant status, key management, consent initiation, signed requests, and receipt verification.

Owner: D2.

Status: scaffolded. Implementation begins in Phase 2 against the contracts frozen in Phase 1.

Rules: the SDK must never expose private keys or unrestricted credentials to a model or model provider. The model sees scoped grants and structured results, not signing material.
