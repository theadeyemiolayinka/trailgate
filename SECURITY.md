# Security policy

This file is the public security surface of the project. It tells outside reporters how to disclose problems and what to expect.

TrailGate is experimental software. It has not been audited and is not a proven security standard. Do not use it with production systems, real credentials, or real funds.

## Reporting a vulnerability

Do not open a public issue for security problems. Preferred channel: a private security advisory on the repository's GitHub page, if this repository is hosted on GitHub. Otherwise, contact the maintainer listed on the repository.

Include: the affected component, reproduction steps, an impact assessment, and any suggested mitigation.

## Scope

In scope:

- Protocol design flaws: signature or proof-of-possession weaknesses, grant forgery, downgrade attacks.
- Constraint enforcement bypasses: spending limit, rate limit, or scope violations enforced by the server.
- Replay, request tampering, redirect or callback manipulation.
- Confused-deputy and cross-user isolation failures.
- Spending accounting errors: double spending, reservation leaks, rollback errors.
- Leaks of agent private keys or unrestricted credentials into model context.

Out of scope:

- Attacks that require features which do not exist yet.
- Vulnerabilities in third-party example infrastructure unrelated to the protocol.

## Response

This is a volunteer-maintained experimental project with no guaranteed response SLA. Valid reports will be acknowledged and triaged. Reporters are credited in advisories unless they decline.
