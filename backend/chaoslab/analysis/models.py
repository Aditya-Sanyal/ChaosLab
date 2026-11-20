"""Pure domain models for offline attack-path analysis (stdlib only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ENGINE_VERSION = "0.1.0"
RULESET_VERSION = "2026.11-r1"
RESULT_DISCLAIMER = (
    "A modeled path is not proof that an exploit works or that a live system is vulnerable."
)

GLOBAL_ASSUMPTIONS: tuple[str, ...] = (
    "The attacker starts at the scenario's start position with no credentials unless stated.",
    (
        "Imported reachability rules and relationships are taken as accurate at their "
        "observation time."
    ),
    "A finding marked present is assumed to apply to the listed asset and port.",
    "Exploitability values are heuristic defaults unless the finding supplies one.",
    "Steps are independent: likelihoods multiply; there is no detection/response model.",
)

ACTIVE_FINDING_STATUSES: frozenset[str] = frozenset({"open", "in_progress", "accepted_risk"})

VALID_RULE_IDS: frozenset[str] = frozenset(
    {
        "R-EXP-REMOTE",
        "R-EXP-LOCAL",
        "R-CRED-USE",
        "R-CRED-HARVEST",
        "R-IDENTITY-ACCESS",
    }
)

VALID_DEFENSIVE_ACTION_KINDS: frozenset[str] = frozenset(
    {
        "remediate_finding",
        "remove_relationship",
        "remove_reachability",
        "set_zone_isolation",
        "add_control",
        "activate_control",
    }
)

DEFAULT_EXPLOITABILITY: dict[str, float] = {
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.2,
    "info": 0.0,
}


@dataclass(frozen=True)
class Provenance:
    origin: str
    source: str
    observed_at: str
    confidence: float


@dataclass(frozen=True)
class ZoneModel:
    key: str
    name: str
    trust_level: str
    intra_zone_policy: str
    provenance: Provenance


@dataclass(frozen=True)
class ServiceModel:
    key: str
    asset_key: str
    port: int
    protocol: str
    name: str
    provenance: Provenance


@dataclass(frozen=True)
class AssetModel:
    key: str
    name: str
    type: str
    zone_key: str | None
    criticality: int
    provenance: Provenance
    evidence_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationshipModel:
    key: str
    source_asset_key: str
    target_asset_key: str
    type: str
    attributes: dict[str, Any]
    provenance: Provenance
    evidence_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReachabilityRuleModel:
    key: str
    source_kind: str
    source_key: str
    target_kind: str
    target_key: str
    ports: tuple[int, ...]
    protocol: str
    description: str
    provenance: Provenance
    evidence_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingAssetModel:
    asset_key: str
    port: int | None
    status_override: str | None


@dataclass(frozen=True)
class FindingModel:
    key: str
    title: str
    category: str
    severity: str
    status: str
    exploitability: float | None
    grants: str
    requires_auth: bool
    affected_assets: tuple[FindingAssetModel, ...]
    provenance: Provenance
    evidence_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class ControlModel:
    key: str
    name: str
    type: str
    asset_key: str
    affects_rules: tuple[str, ...]
    ports: tuple[int, ...]
    factor: float
    status: str
    provenance: Provenance
    evidence_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceModel:
    key: str
    kind: str
    title: str
    excerpt: str
    sha256: str
    provenance: Provenance


def _prov(item: dict[str, Any]) -> Provenance:
    return Provenance(
        origin=str(item.get("origin", "manual")),
        source=str(item.get("source", "unknown")),
        observed_at=str(item.get("observed_at", "")),
        confidence=float(item.get("confidence", 1.0)),
    )


@dataclass(frozen=True)
class EnvironmentModel:
    environment_id: str
    environment_name: str
    zones: tuple[ZoneModel, ...]
    assets: tuple[AssetModel, ...]
    services: tuple[ServiceModel, ...]
    relationships: tuple[RelationshipModel, ...]
    reachability: tuple[ReachabilityRuleModel, ...]
    findings: tuple[FindingModel, ...]
    controls: tuple[ControlModel, ...]
    evidence: tuple[EvidenceModel, ...]
    zones_by_key: dict[str, ZoneModel] = field(default_factory=dict, repr=False)
    assets_by_key: dict[str, AssetModel] = field(default_factory=dict, repr=False)
    findings_by_key: dict[str, FindingModel] = field(default_factory=dict, repr=False)
    relationships_by_key: dict[str, RelationshipModel] = field(default_factory=dict, repr=False)
    reachability_by_key: dict[str, ReachabilityRuleModel] = field(default_factory=dict, repr=False)
    controls_by_key: dict[str, ControlModel] = field(default_factory=dict, repr=False)
    evidence_by_key: dict[str, EvidenceModel] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "zones_by_key", {z.key: z for z in self.zones})
        object.__setattr__(self, "assets_by_key", {a.key: a for a in self.assets})
        object.__setattr__(self, "findings_by_key", {f.key: f for f in self.findings})
        object.__setattr__(self, "relationships_by_key", {r.key: r for r in self.relationships})
        object.__setattr__(self, "reachability_by_key", {rr.key: rr for rr in self.reachability})
        object.__setattr__(self, "controls_by_key", {c.key: c for c in self.controls})
        object.__setattr__(self, "evidence_by_key", {e.key: e for e in self.evidence})

    @classmethod
    def from_snapshot_dict(cls, doc: dict[str, Any]) -> EnvironmentModel:
        env_meta = doc.get("environment", {})
        zones = tuple(
            sorted(
                (
                    ZoneModel(
                        key=z["key"],
                        name=z["name"],
                        trust_level=z["trust_level"],
                        intra_zone_policy=z["intra_zone_policy"],
                        provenance=_prov(z),
                    )
                    for z in doc.get("zones", [])
                ),
                key=lambda x: x.key,
            )
        )
        assets = tuple(
            sorted(
                (
                    AssetModel(
                        key=a["key"],
                        name=a["name"],
                        type=a["type"],
                        zone_key=a.get("zone_key"),
                        criticality=int(a["criticality"]),
                        provenance=_prov(a),
                        evidence_keys=tuple(sorted(a.get("evidence_keys", []))),
                    )
                    for a in doc.get("assets", [])
                ),
                key=lambda x: x.key,
            )
        )
        services = tuple(
            sorted(
                (
                    ServiceModel(
                        key=s["key"],
                        asset_key=s["asset_key"],
                        port=int(s["port"]),
                        protocol=s.get("protocol", "tcp"),
                        name=s["name"],
                        provenance=_prov(s),
                    )
                    for s in doc.get("services", [])
                ),
                key=lambda x: x.key,
            )
        )
        relationships = tuple(
            sorted(
                (
                    RelationshipModel(
                        key=r["key"],
                        source_asset_key=r["source_asset_key"],
                        target_asset_key=r["target_asset_key"],
                        type=r["type"],
                        attributes=dict(r.get("attributes") or {}),
                        provenance=_prov(r),
                        evidence_keys=tuple(sorted(r.get("evidence_keys", []))),
                    )
                    for r in doc.get("relationships", [])
                ),
                key=lambda x: x.key,
            )
        )
        reachability = tuple(
            sorted(
                (
                    ReachabilityRuleModel(
                        key=rr["key"],
                        source_kind=rr["source_kind"],
                        source_key=rr["source_key"],
                        target_kind=rr["target_kind"],
                        target_key=rr["target_key"],
                        ports=tuple(sorted(int(p) for p in rr.get("ports") or ())),
                        protocol=rr.get("protocol", "tcp"),
                        description=rr.get("description", ""),
                        provenance=_prov(rr),
                        evidence_keys=tuple(sorted(rr.get("evidence_keys", []))),
                    )
                    for rr in doc.get("reachability", [])
                ),
                key=lambda x: x.key,
            )
        )
        findings = tuple(
            sorted(
                (
                    FindingModel(
                        key=f["key"],
                        title=f["title"],
                        category=f["category"],
                        severity=f["severity"],
                        status=f["status"],
                        exploitability=(
                            None if f.get("exploitability") is None else float(f["exploitability"])
                        ),
                        grants=f.get("grants", "user"),
                        requires_auth=bool(f.get("requires_auth", False)),
                        affected_assets=tuple(
                            sorted(
                                (
                                    FindingAssetModel(
                                        asset_key=fa["asset_key"],
                                        port=(
                                            None if fa.get("port") is None else int(fa["port"])
                                        ),
                                        status_override=fa.get("status_override"),
                                    )
                                    for fa in f.get("affected_assets", [])
                                ),
                                key=lambda x: (x.asset_key, x.port or -1),
                            )
                        ),
                        provenance=_prov(f),
                        evidence_keys=tuple(sorted(f.get("evidence_keys", []))),
                    )
                    for f in doc.get("findings", [])
                ),
                key=lambda x: x.key,
            )
        )
        controls = tuple(
            sorted(
                (
                    ControlModel(
                        key=c["key"],
                        name=c["name"],
                        type=c["type"],
                        asset_key=c["asset_key"],
                        affects_rules=tuple(sorted(c.get("affects_rules", []))),
                        ports=tuple(sorted(int(p) for p in c.get("ports") or ())),
                        factor=float(c["factor"]),
                        status=c["status"],
                        provenance=_prov(c),
                        evidence_keys=tuple(sorted(c.get("evidence_keys", []))),
                    )
                    for c in doc.get("controls", [])
                ),
                key=lambda x: x.key,
            )
        )
        evidence = tuple(
            sorted(
                (
                    EvidenceModel(
                        key=e["key"],
                        kind=e["kind"],
                        title=e["title"],
                        excerpt=e["excerpt"],
                        sha256=e["sha256"],
                        provenance=_prov(e),
                    )
                    for e in doc.get("evidence", [])
                ),
                key=lambda x: x.key,
            )
        )
        return cls(
            environment_id=str(env_meta.get("id", "")),
            environment_name=str(env_meta.get("name", "")),
            zones=zones,
            assets=assets,
            services=services,
            relationships=relationships,
            reachability=reachability,
            findings=findings,
            controls=controls,
            evidence=evidence,
        )


@dataclass(frozen=True)
class Prerequisite:
    kind: str  # capability | finding | relationship | reachability | zone_policy
    key: str
    detail: str
    confidence: float


@dataclass(frozen=True)
class AppliedControl:
    key: str
    name: str
    factor: float


@dataclass(frozen=True)
class ModeledStep:
    step_key: str
    rule_id: str
    rule_name: str
    rule_description: str
    from_position: str
    target_key: str
    gains: str
    required_capabilities: tuple[str, ...]
    prerequisites: tuple[Prerequisite, ...]
    evidence_keys: tuple[str, ...]
    controls_applied: tuple[AppliedControl, ...]
    base_likelihood: float
    likelihood: float
    confidence: float
    reference_labels: tuple[str, ...]
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class ModeledPath:
    path_key: str
    target_key: str
    goal_capability: str
    modeled_score: int
    path_likelihood: float
    path_confidence: float
    weighted_likelihood: float
    impact: float
    low_confidence: bool
    steps: tuple[ModeledStep, ...]


@dataclass(frozen=True)
class TargetSpec:
    asset_key: str
    level: str = "user"  # user | admin | identity


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    start_kind: str  # zone | asset
    start_key: str
    start_level: str = "user"
    targets: tuple[TargetSpec, ...] = ()
    max_depth: int = 6
    k_paths: int = 5
    max_expansions: int = 20000


@dataclass(frozen=True)
class DefensiveAction:
    kind: str
    # Supported kinds:
    # - remediate_finding: finding_key, optional asset_key
    # - remove_relationship: relationship_key
    # - remove_reachability: reachability_key
    # - set_zone_isolation: zone_key, intra_zone_policy ("deny"|"allow")
    # - add_control: key, name, type, asset_key, affects_rules, ports, factor
    # - activate_control: control_key
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetAnalysisResult:
    target_key: str
    goal_capability: str
    paths: tuple[ModeledPath, ...]
    search_truncated: bool
    expansions_used: int


@dataclass(frozen=True)
class AnalysisOutput:
    headline_score: int
    total_paths: int
    search_truncated: bool
    results_by_target: tuple[TargetAnalysisResult, ...]
    paths: tuple[ModeledPath, ...]
    limits: dict[str, int]
