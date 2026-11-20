# CHAOS LAB: Application Threat Model

Scope: self-hosted, single-organisation deployment.

CHAOS LAB stores a map of an organisation's infrastructure weaknesses and how they connect. Because that inventory doubles as an attack blueprint if leaked, the security goals are confidentiality of inventory, integrity of findings and results, and accountability for every state change.

## Assets to protect

Inventory and topology · findings and evidence excerpts · scenario results and exported reports · user accounts and sessions · audit trail · deployment secrets (`POSTGRES_PASSWORD`, `CHAOSLAB_SECRET_KEY`).

## Actors

Viewer, analyst, and admin users (legitimate, mistaken, or malicious insiders) · unauthenticated network attacker reaching the web edge port · submitter of a crafted import file · someone with host or database access.

## Threats and mitigations (STRIDE)

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| S1 | Credential stuffing / brute force on login | argon2id hashes, per-account and per-IP rate limiting, generic failure responses, failed logins audited | no built-in MFA yet (OIDC/SSO planned) |
| S2 | Session theft | 256-bit random tokens hashed with SHA-256 at rest, `HttpOnly; Secure; SameSite=Strict`, idle + absolute expiry, revoked on logout/disable/reset | XSS in-session still dangerous -> see T3 |
| T1 | Malicious import XML (XXE, Billion Laughs) | `defusedxml` parser, DTD/entity resolution disabled, strict size caps | -- |
| T2 | Malicious CSV formula injection in exports | cells starting with `= + - @ \t \r` are prefixed with `'` on CSV export | -- |
| T3 | Stored XSS in imported names/descriptions | React default escaping, zero `dangerouslySetInnerHTML`, strict CSP headers, HTML reports autoescaped with `html.escape` | -- |
| T4 | Oversized or zip-bomb uploads | max 10 MB upload limit, max 50,000 rows, archive magic bytes rejected | -- |
| T5 | Tampering with findings or results | RBAC checks on every route, audit log for every mutation, SHA-256 hash chain on audit events, scenario input/result hashes | DB superuser can rewrite tables and chain together; archive audit events off-host |
| R1 | User denies running an export or changing status | append-only audit event with actor, timestamp, subject, and details | -- |
| I1 | Broken access control (UI-only checks) | every API endpoint requires an explicit permission via FastAPI dependency; test matrix asserts every role | -- |
| I2 | Secrets leaking into source or DB | secrets loaded from env / git-ignored `.env`; secret columns and PEM/token literals rejected on upload | users could still paste secrets into free-text notes |
| I3 | Fixture data leaking real internal IPs/names | fixtures restricted to RFC 5737 documentation IPs and `.example` domains; checked by tests | -- |
| I4 | Over-broad API responses | explicit Pydantic response schemas; ORM models never serialized directly | -- |
| D1 | Expensive path search used as DoS | per-run bounds (`max_depth`, `k_paths`, `max_expansions`), only analyst/admin can run | -- |
| E1 | Privilege escalation or last-admin lockout | admin-only user/role endpoints; HTTP `409 Conflict` blocks disabling/demoting last active admin | -- |
| X1 | Simulation reaching live hosts | pure stdlib analysis package enforced by AST test; `api` runs on `internal: true` Compose network | -- |

## Deployment assumptions

TLS terminated at an upstream reverse proxy in front of `web`; `db` and `api` unreachable from external networks; host disk and database backups encrypted; audit chain verified periodically (`python -m chaoslab verify-audit`). See [deployment.md](deployment.md).
