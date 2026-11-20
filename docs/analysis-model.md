# CHAOS LAB: Analysis Model

Engine version `0.1.0`, rule set `2026.11-r1`.

This document defines what the engine models, how it scores paths, and what falls outside its scope. It serves as the reference for every "modeled path" and "scenario result" returned by the API.

> A modeled path is a chain of rule applications over **imported or synthetic data**. It is not
> proof that an exploit works or that a live system is vulnerable. The engine contacts no system.

## 1. Inputs: the snapshot

The engine runs only on an in-memory `EnvironmentModel` built from a frozen snapshot (see
[data-model.md](data-model.md#snapshots)). It uses:

- **Zones**: trust level (`untrusted`, `low`, `medium`, `high`), intra-zone policy (`allow` | `deny`).
- **Assets**: key, type, zone, criticality 1–5. Identities (users, service accounts, roles) are
  assets of type `identity` with no zone.
- **Reachability rules**: allowed flows `source (zone | asset) → target (zone | asset)` on ports.
- **Relationships**: `has_credential_for`, `admin_of`, `can_access` (others such as
  `depends_on`, `hosts` are shown in the UI but do not create attack steps).
- **Findings** with category, severity, confidence, status, affected assets/ports, and what a
  successful step grants (`user` | `admin`).
- **Controls** (active ones) that dampen or block specific rules on specific assets.

Every input fact carries provenance (`source`, `origin`, `observed_at`, `confidence`).

## 2. Attacker state

The attacker's state is a set of **capabilities**, which only grows along a path:

| Capability | Meaning |
|---|---|
| `start:<zone>` or `start:<asset>` | scenario start position (e.g. the `internet` zone, or an assumed-breach workstation) |
| `foothold:<asset>:user` / `:admin` | modeled ability to run code / act on an asset at that level (`admin` implies `user`) |
| `identity:<identity>` | modeled possession of a usable credential for an identity |

A scenario **goal** is reached when the state contains `foothold:<target>:<level>` (default
level `user`), or `identity:<target>` for identity targets.

## 3. Reachability

`reach(position, target_asset, port)` holds when either:

1. the position and target are in the same zone and that zone's intra-zone policy is `allow`
   (recorded as an *implicit* fact `ZONE-INTRA:<zone>`, confidence = zone confidence); or
2. a reachability rule matches: source matches the position's zone or asset, target matches the
   target's zone or asset, and the port is in the rule's port list (or the rule allows any port).

When several rules match, the engine chooses deterministically: asset-specific before zone-wide,
then higher confidence, then lowest key. The chosen rule is cited in the step's explanation. A
step that relies on a zone-wide rule is labelled **inferred reachability**.

Identity assets are never network targets. A position on asset A always reaches A itself.

## 4. Rule catalogue (`2026.11-r1`)

Each rule creates **steps**. A step has prerequisites, an effect, a heuristic likelihood, a
confidence, evidence, and reference labels. ATT&CK technique IDs are *reference labels* to help
readers; they do not imply the engine emulates the technique.

| Rule | Prerequisites | Effect | Base likelihood | Reference label |
|---|---|---|---|---|
| **R-EXP-REMOTE** — Exploit network-reachable weakness | a position P (start or foothold); finding F on target T with category `remote_exploitable`, status present, no auth required; `reach(P, T, F.port)` | `foothold:T:<F.grants>` | exploitability(F) | T1190 from an untrusted start zone, otherwise T1210 |
| **R-EXP-LOCAL** — Escalate privilege via local weakness | `foothold:A:user`; finding F on A with category `local_privesc`, status present | `foothold:A:admin` | exploitability(F) | T1068 |
| **R-CRED-USE** — Use credential material found on a foothold | `foothold:A:<rel.required_level>` (default `user`); relationship `A has_credential_for T` (T not an identity); `reach(A, T, rel.port)` | `foothold:T:<rel.access_level>` (default `user`) | 0.9 | T1552.001, T1078 |
| **R-CRED-HARVEST** — Harvest identity credential from a foothold | `foothold:A:<rel.required_level>` (default `admin`); relationship `A has_credential_for I` (I is an identity) | `identity:I` | 0.8 | T1003 (or T1552 if `rel.attributes.material = file`) |
| **R-IDENTITY-ACCESS** — Authenticate as a captured identity | `identity:I`; relationship `I admin_of T` (→ admin) or `I can_access T` (→ user); some held position P with `reach(P, T, rel.port)` | `foothold:T:<level>` | 0.9 | T1078 |

**Finding status.** `open`, `in_progress` and `accepted_risk` count as present. `remediated` and
`false_positive` are excluded. A per-asset status on the affected-asset link overrides the
finding-level status.

**Exploitability.** `finding.exploitability` if supplied (0–1), else the default by severity:
critical 0.8, high 0.6, medium 0.4, low 0.2, info 0.0 (info findings never create steps). These
are heuristic defaults, not measurements, and every step that uses one says so.

**Controls.** An active control on asset X with `affects_rules` containing rule R (and optional
port list) multiplies the likelihood of R-steps *targeting* X (for R-CRED-HARVEST and
R-EXP-LOCAL: steps *on* X; for R-IDENTITY-ACCESS: controls on the identity or the target) by its
`factor` (0–1). Factor 0 blocks the step. Each applied control is listed on the step.

## 5. Scoring (heuristic, inspectable)

For a path with steps *i = 1..n*, step likelihood *lᵢ* and step confidence *cᵢ*
(the minimum confidence of the facts the step relies on):

| Metric | Definition |
|---|---|
| path likelihood | Π lᵢ |
| path confidence | min cᵢ (weakest evidence) |
| weighted likelihood | Π (lᵢ · cᵢ) |
| impact | target criticality / 5 |
| **modeled score** (0–100) | round(100 · weighted likelihood · impact) |

Scenario headline = highest modeled score among returned paths, plus the path count. A path with
confidence < 0.5 is flagged **low confidence**. The score ranks modeled paths against each other
inside one product; it is not a probability of compromise and not comparable to CVSS.

## 6. Path search

- **Uniform-cost search** over capability sets with step cost −ln(lᵢ · cᵢ), so the highest
  weighted-likelihood paths are found first. Each capability set may be expanded at most *k*
  times (k-best paths).
- A step is only taken if it adds a capability the state does not already imply.
- When the goal is reached, the path is **minimised**: steps that did not contribute (directly or
  transitively) to the goal are dropped. Paths with identical step sets are deduplicated.
- **Limits** (scenario parameters, defaults): `max_depth = 6`, `k = 5` paths per target,
  `max_expansions = 20 000`. If a limit stops the search, the result is marked
  `search_truncated = true` and says that further modeled paths may exist.
- **Determinism**: all candidates are generated in sorted key order; ties are broken by path
  length, then by the lexicographic sequence of step keys. No randomness, clock or I/O. Output
  floats are rounded to 6 decimal places; the run stores
  `sha256(canonical_json(result))` so reruns can be checked.

## 7. Explanations (what every step shows)

`rule` (id, name, description) · `from` (position used) · `gains` (capability) · `prerequisites`
(each with the fact key that satisfied it: capability, finding, relationship, reachability rule
or implicit zone policy) · `evidence` (keys of evidence linked to those facts) · `controls_applied`
(key, factor) · likelihood breakdown (base, each factor) · confidence breakdown · reference labels
· `assumptions` (e.g. "reachability inferred from zone-wide rule RR-07", "exploitability default
for severity high").

Every result also lists: snapshot id and hash, engine and rule-set versions, scenario parameters,
global assumptions, limits and whether they were hit.

## 8. Defensive action comparison

Actions are applied to an **in-memory copy** of the snapshot; the stored snapshot never changes.

| Action | Effect on the copy |
|---|---|
| `remediate_finding` | finding (or one affected asset) marked `remediated` |
| `remove_relationship` | relationship dropped |
| `remove_reachability` | reachability rule dropped |
| `set_zone_isolation` | zone intra-zone policy set to `deny` |
| `add_control` / `activate_control` | control added or switched from `proposed` to `active` |

The comparison reports, per path: **removed**, **remaining** (with score change and which step
changed), or **new**, plus baseline vs. modified headline score.

## 9. Global assumptions (shown with every result)

1. The attacker starts at the scenario's start position with no credentials unless stated.
2. Imported reachability rules and relationships are taken as accurate at their observation time.
3. A finding marked present is assumed to apply to the listed asset and port.
4. Exploitability values are heuristic defaults unless the finding supplies one.
5. Steps are independent: likelihoods multiply; there is no detection/response model.

## 10. Current Scope Boundaries

Detection and response, time/dwell, attacker skill profiles, exploit chaining within one host
beyond `local_privesc`, user interaction (phishing), physical access, supply chain, denial of
service, data exfiltration volume, cloud IAM policy evaluation, Kerberos/AD-specific attacks,
compensating controls not entered as controls, or anything not present in the snapshot. Missing
data means missing paths: **no modeled path does not mean no risk.**
