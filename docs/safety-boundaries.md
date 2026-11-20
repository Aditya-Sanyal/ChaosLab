# CHAOS LAB: Safety Boundaries

Normative safety guarantees for offline simulation vs. any future active capability.

## 1. Two capabilities, kept apart

| | **Offline simulation** (implemented) | **Live testing** (future, *not implemented*) |
|---|---|---|
| Operates on | imported or synthetic data in a frozen snapshot | real systems, within an approved scope |
| Network activity | none | bounded, approved, logged |
| Output label | "modeled path", "scenario result" | "test observation" (future) |
| Code location | `chaoslab/analysis`, `chaoslab/scenarios` | separate future service and permissions; nothing exists today |

There is no flag, plugin hook, or configuration setting that turns an offline simulation into live network activity.

## 2. Offline simulation guarantees

1. **Data only.** Simulations read a snapshot document. They do not send packets, resolve names, probe hosts, execute payloads, modify external systems, or use real credentials.
2. **No credential material.** Relationships such as `has_credential_for` record *that* a credential path exists and where (with evidence). Import validation rejects fields containing passwords, private keys, or API tokens.
3. **Labelled outputs.** Every result is labelled `"modeled path"` or `"scenario_result"` and carries the disclaimer: *A modeled path is not proof that an exploit works or that a live system is vulnerable.*
4. **Inspectable.** Every result includes the snapshot id and SHA-256 hash, evidence keys, rule IDs, prerequisites, assumptions, uncertainty markers, bounds, and engine/rule-set versions.
5. **Deterministic.** Identical snapshot + scenario + defensive actions + engine version yields the exact same `result_sha256`.

### Enforcement mechanisms

| Guarantee | Mechanism | Verified by |
|---|---|---|
| No network from the engine | `chaoslab/analysis` uses a Python stdlib allow-list with no I/O | `test_analysis_purity.py` (AST import scan) |
| No network during a scenario run | runs execute in-process against an in-memory model | `test_no_network.py` (socket connect/DNS patched to raise during an API run) |
| No outbound backend calls | no outbound HTTP client dependency; Compose isolates `api` on `internal: true` | dependency review & [deployment.md](deployment.md) |
| Reproducibility | canonical sorted inputs, deterministic tie-breaking, stored hashes | `test_reproducibility.py` |
| Labels and disclaimers | required `result_kind` and `disclaimer` response fields | API schema tests & UI checks |

## 3. Out of scope

Unrestricted scanning, exploit execution, payload delivery, automated live remediation, storing production secrets, or LLM-generated attack paths.

Importing **files exported from other tools** (such as an existing Nmap XML scan) is supported because CHAOS LAB parses the static file offline and never runs the scanner.

## 4. Future live testing: design constraints (not implemented)

If active validation is ever added later, it belongs in a separate service with isolated credentials and its own approval workflow:

| Control | Requirement |
|---|---|
| **Scope** | explicit allow-list of targets (CIDRs/hostnames/cloud accounts) and allowed techniques |
| **Exclusions** | explicit deny-list taking precedence over scope |
| **Approval** | separate requester and approver (two-person rule) pinned to the SHA-256 of the exact plan |
| **Time window** | bounded start/end window in the target's time zone; refused outside window |
| **Limits** | rate limits, concurrency caps, max targets, non-destructive checks by default |
| **Stop control** | immediate halt for requester, approver, and admins; checked before every action and audited |
| **Audit** | full action log with plan id, target, technique, timestamp, outcome, shipped off-host |
| **Isolation** | dedicated worker host/process, never inside the web API process |
| **Authorisation** | written owner sign-off referenced in the plan |
