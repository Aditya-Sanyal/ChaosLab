# CHAOS LAB: Data Handling, Retention and Deployment Security

Default retention windows below assume a self-hosted, single-organisation deployment and can be adjusted via environment variables.

## Data collected

| Category | Examples | Source | Sensitivity |
|---|---|---|---|
| Asset inventory | hostnames, IPs, zones, OS, owners, services | imports, manual entry | high (targeting data) |
| Relationships | reachability rules, credential relationships (existence only), admin rights | imports, manual entry | high |
| Findings & evidence | weakness descriptions, scanner output excerpts, config excerpts | imports, manual entry | high |
| Scenario results & reports | modeled paths, scores, comparisons | generated | high |
| User accounts | email, display name, role, password hash, last login | admin | personal data |
| Sessions | hashed token, IP, user agent, timestamps | generated | personal data |
| Audit trail | actor, action, subject, time, details | generated | personal data + operational |

**Not collected:** credential values (passwords, keys, tokens), packet captures, host files, or external vendor telemetry. The backend makes no outbound calls.

## Retention defaults

| Data | Default | Notes |
|---|---|---|
| Inventory working set | until changed or deleted | updated by imports and edits |
| Snapshots | 180 days, except snapshots referenced by a kept run | |
| Scenario runs | 365 days | |
| Import files (raw uploads) | **not stored** after processing; only filename, size, sha256, counts and errors are kept | |
| Evidence excerpts | lifetime of the linked fact | max 8 KB each; redact secrets before importing |
| Sessions | 12 h idle / 7 days absolute expiry; rows purged 30 days after expiry | |
| Audit events | 2 years | export off-host for longer retention |
| Exported reports | not stored server-side; the export event is audited | |

Retention sweeps run via CLI (`python -m chaoslab run-retention --apply`), suitable for scheduled cron jobs.

## Secrets

- `CHAOSLAB_SECRET_KEY`, `CHAOSLAB_DATABASE_URL`, and `POSTGRES_PASSWORD` come from environment variables or a git-ignored `.env` file.
- `.env.example` documents all variables with placeholder values. No secret appears in source, fixtures, logs, or ordinary database rows.
- Future external connectors must use read-only, least-privilege roles (for example AWS `SecurityAudit`) and keep credentials outside the database.

## Deployment security checklist

1. Serve behind HTTPS and set `CHAOSLAB_COOKIE_SECURE=true` (keep `false` only for plain `http://localhost` evaluation).
2. Expose only the `web` service; keep `db` and `api` on the internal Compose network.
3. Run `api` and `db` without internet egress (`internal: true`).
4. Set a strong, unique `POSTGRES_PASSWORD` and `CHAOSLAB_SECRET_KEY`; rotate on staff changes.
5. Encrypt host disks and database backups; restrict backup access to admins.
6. Rotate or disable demo accounts before shared access, and create named per-person accounts.
7. Archive audit logs off-host periodically if independent write-once retention is required.
8. Handle exported HTML/Markdown reports as sensitive internal documents.

## Sample data policy

Fixtures and the bundled demo environment are synthetic: organisations are fictional, public addresses use RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), private addresses use `10.20.0.0/16`, and domains use `.example`. Never commit real scan exports.
