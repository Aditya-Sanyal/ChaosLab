"""Explicit Pydantic v2 request and response schemas for the CHAOS LAB API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str
    mode: Literal["offline_simulation"]


class ReadinessResponse(BaseModel):
    status: str
    database: str
    service: str
    version: str
    mode: str


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=512)


class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool


class ProvenanceOut(BaseModel):
    origin: str
    source: str
    observed_at: str | None
    confidence: float
    import_batch_id: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None


class EnvironmentSummary(BaseModel):
    id: str
    name: str
    description: str
    is_demo: bool
    created_at: str | None


class AssetSummary(BaseModel):
    id: str
    key: str
    name: str
    type: str
    zone_key: str | None
    criticality: int
    crown_jewel: bool
    owner: str
    hostname: str | None
    ip_addresses: list[str]
    os: str | None
    tags: list[str]
    internet_exposed: bool
    service_count: int
    finding_count: int
    max_severity: str | None
    provenance: ProvenanceOut


class ServiceOut(BaseModel):
    key: str
    port: int
    protocol: str
    name: str
    product: str | None
    version: str | None
    provenance: ProvenanceOut


class AssetRelationshipOut(BaseModel):
    key: str
    direction: str
    source_asset_key: str
    target_asset_key: str
    type: str
    attributes: dict[str, Any]
    provenance: ProvenanceOut


class AssetFindingOut(BaseModel):
    key: str
    title: str
    category: str
    severity: str
    status: str
    port: int | None
    cwe: str | None
    cve: str | None
    remediation_notes: str
    provenance: ProvenanceOut


class AssetControlOut(BaseModel):
    key: str
    name: str
    type: str
    affects_rules: list[str]
    ports: list[int]
    factor: float
    status: str
    provenance: ProvenanceOut


class EvidenceOut(BaseModel):
    key: str
    kind: str
    title: str
    excerpt: str
    sha256: str
    provenance: ProvenanceOut


class AssetDetailResponse(BaseModel):
    id: str
    key: str
    name: str
    type: str
    zone_key: str | None
    zone_name: str | None
    criticality: int
    crown_jewel: bool
    owner: str
    hostname: str | None
    ip_addresses: list[str]
    os: str | None
    tags: list[str]
    description: str
    internet_exposed: bool
    provenance: ProvenanceOut
    services: list[ServiceOut]
    relationships: list[AssetRelationshipOut]
    findings: list[AssetFindingOut]
    controls: list[AssetControlOut]
    evidence: list[EvidenceOut]


class GraphZoneOut(BaseModel):
    key: str
    name: str
    trust_level: str
    intra_zone_policy: str
    cidrs: list[str]


class GraphReachabilityEdgeOut(BaseModel):
    key: str
    source_kind: str
    source_key: str
    target_kind: str
    target_key: str
    ports: list[int]
    protocol: str
    description: str
    inferred_zone_flow: bool
    confidence: float


class GraphRelationshipEdgeOut(BaseModel):
    key: str
    source_asset_key: str
    target_asset_key: str
    type: str
    attributes: dict[str, Any]
    confidence: float


class TopologyGraphResponse(BaseModel):
    environment: dict[str, Any]
    zones: list[GraphZoneOut]
    assets: list[AssetSummary]
    reachability_edges: list[GraphReachabilityEdgeOut]
    relationship_edges: list[GraphRelationshipEdgeOut]


class AffectedAssetOut(BaseModel):
    asset_key: str
    port: int | None
    status_override: str | None


class FindingOut(BaseModel):
    id: str
    key: str
    title: str
    category: str
    severity: str
    status: str
    cwe: str | None
    cve: str | None
    exploitability: float | None
    grants: str
    requires_auth: bool
    description: str
    remediation_notes: str
    affected_assets: list[AffectedAssetOut]
    evidence_keys: list[str]
    status_history_count: int = 0
    provenance: ProvenanceOut


class FindingStatusHistoryEntry(BaseModel):
    at: str | None
    actor: str
    from_status: str
    to_status: str
    comment: str = ""


class FindingAffectedAssetDetailOut(BaseModel):
    asset_key: str
    asset_name: str
    zone_key: str | None
    port: int | None
    status_override: str | None
    effective_status: str


class FindingDetailResponse(BaseModel):
    id: str
    key: str
    title: str
    category: str
    severity: str
    status: str
    cwe: str | None
    cve: str | None
    exploitability: float | None
    grants: str
    requires_auth: bool
    description: str
    remediation_notes: str
    status_history: list[FindingStatusHistoryEntry]
    affected_assets: list[FindingAffectedAssetDetailOut]
    evidence: list[EvidenceOut]
    provenance: ProvenanceOut


class FindingAssetOverrideInput(BaseModel):
    asset_key: str = Field(min_length=1, max_length=128)
    port: int | None = Field(default=None, ge=1, le=65535)
    status_override: (
        Literal["open", "in_progress", "accepted_risk", "remediated", "false_positive"] | None
    ) = None


class FindingUpdateRequest(BaseModel):
    status: (
        Literal["open", "in_progress", "accepted_risk", "remediated", "false_positive"] | None
    ) = None
    remediation_notes: str | None = Field(default=None, max_length=8000)
    comment: str | None = Field(default=None, max_length=1000)
    asset_status_overrides: list[FindingAssetOverrideInput] | None = None


class SnapshotCreateRequest(BaseModel):
    label: str | None = Field(default=None, max_length=255)


class SnapshotSummary(BaseModel):
    id: str
    environment_id: str
    label: str
    sha256: str
    counts: dict[str, int]
    created_by: str
    created_at: str | None


class SnapshotDetail(SnapshotSummary):
    document: dict[str, Any]


class ScenarioSummary(BaseModel):
    id: str
    environment_id: str
    name: str
    description: str
    start_kind: str
    start_key: str
    start_level: str
    targets: list[dict[str, str]]
    parameters: dict[str, int]
    created_by: str
    created_at: str | None


class TargetInput(BaseModel):
    asset_key: str = Field(min_length=1, max_length=128)
    level: Literal["user", "admin", "identity"] = "user"


class InlineScenarioInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    start_kind: Literal["zone", "asset"]
    start_key: str = Field(min_length=1, max_length=128)
    start_level: Literal["user", "admin"] = "user"
    targets: list[TargetInput] = Field(min_length=1, max_length=20)
    max_depth: int = Field(default=6, ge=1, le=12)
    k_paths: int = Field(default=5, ge=1, le=20)
    max_expansions: int = Field(default=20000, ge=10, le=50000)


class ScenarioCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    start_kind: Literal["zone", "asset"]
    start_key: str = Field(min_length=1, max_length=128)
    start_level: Literal["user", "admin"] = "user"
    targets: list[TargetInput] = Field(min_length=1, max_length=20)
    max_depth: int = Field(default=6, ge=1, le=12)
    k_paths: int = Field(default=5, ge=1, le=20)
    max_expansions: int = Field(default=20000, ge=10, le=50000)


class DefensiveActionInput(BaseModel):
    kind: Literal[
        "remediate_finding",
        "remove_relationship",
        "remove_reachability",
        "set_zone_isolation",
        "add_control",
        "activate_control",
    ]
    params: dict[str, Any] = Field(default_factory=dict)


class ScenarioRunCreateRequest(BaseModel):
    scenario_id: str | None = None
    inline_scenario: InlineScenarioInput | None = None
    actions: list[DefensiveActionInput] = Field(default_factory=list, max_length=20)


class ScenarioRunResponse(BaseModel):
    id: str
    environment_id: str
    scenario_id: str | None
    snapshot_id: str
    result_kind: Literal["scenario_result"]
    disclaimer: str
    actions: list[dict[str, Any]]
    engine_version: str
    ruleset_version: str
    input_sha256: str
    result_sha256: str
    result: dict[str, Any]
    status: str
    duration_ms: int
    created_by: str
    created_at: str | None


class AuditEventOut(BaseModel):
    seq: int
    at: str | None
    actor_user_id: str | None
    actor_email: str | None
    action: str
    subject_type: str
    subject_id: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


class AuditListResponse(BaseModel):
    total: int
    items: list[AuditEventOut]


class AuditVerifyResponse(BaseModel):
    valid: bool
    checked_count: int
    first_broken_seq: int | None


class EnvironmentCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = Field(default="", max_length=2000)


class ImportIssueOut(BaseModel):
    severity: str
    entity: str
    row: int | None
    field: str | None
    code: str
    message: str


class ImportBatchSummary(BaseModel):
    id: str
    environment_id: str
    format: str
    filename: str
    sha256: str
    size_bytes: int
    status: str
    counts: dict[str, dict[str, int]]
    error_count: int
    created_by: str
    created_at: str | None


class ImportReportResponse(BaseModel):
    batch_id: str
    environment_id: str
    format: str
    filename: str
    sha256: str
    size_bytes: int
    status: str
    counts: dict[str, dict[str, int]]
    errors: list[ImportIssueOut]
    warnings: list[ImportIssueOut]
    created_by: str
    created_at: str | None


class ZoneBreakdownOut(BaseModel):
    key: str
    name: str
    trust_level: str
    intra_zone_policy: str
    asset_count: int
    exposed_count: int
    active_finding_count: int


class LatestRunBriefOut(BaseModel):
    id: str
    snapshot_id: str
    headline_score: int
    total_paths: int
    result_sha256: str
    created_by: str
    created_at: str | None


class EnvironmentOverviewResponse(BaseModel):
    environment: EnvironmentSummary
    counts: dict[str, int]
    findings_by_severity: dict[str, int]
    zones_breakdown: list[ZoneBreakdownOut]
    latest_snapshot: SnapshotSummary | None
    latest_run: LatestRunBriefOut | None
    recent_imports: list[ImportBatchSummary]


class AttackPathTargetSummaryOut(BaseModel):
    asset_key: str
    asset_name: str
    asset_type: str
    zone_key: str | None
    criticality: int
    crown_jewel: bool
    goal_capability: str
    path_count: int
    max_score: int
    search_truncated: bool
    expansions_used: int


class AttackPathSweepResponse(BaseModel):
    result_kind: Literal["modeled_attack_paths"]
    disclaimer: str
    engine_version: str
    ruleset_version: str
    snapshot_id: str
    snapshot_sha256: str
    start_kind: str
    start_key: str
    start_level: str
    target_mode: str
    goal_level: str
    headline_score: int
    total_paths: int
    search_truncated: bool
    limits: dict[str, int]
    targets_evaluated: list[AttackPathTargetSummaryOut]
    paths: list[dict[str, Any]]
    global_assumptions: list[str]
    input_sha256: str
    result_sha256: str


class RunBriefOut(BaseModel):
    id: str
    environment_id: str
    scenario_id: str | None
    scenario_name: str
    snapshot_id: str
    snapshot_sha256: str
    action_count: int
    actions: list[dict[str, Any]]
    effective_headline_score: int
    effective_path_count: int
    input_sha256: str
    result_sha256: str
    created_by: str
    created_at: str | None


class RunComparisonResponse(BaseModel):
    result_kind: Literal["run_comparison"] = "run_comparison"
    disclaimer: str
    run_a: RunBriefOut
    run_b: RunBriefOut
    same_snapshot: bool
    same_scenario: bool
    same_input_hash: bool
    same_result_hash: bool
    warnings: list[str]
    comparison: dict[str, Any]


class ReportExportRequest(BaseModel):
    format: Literal["html", "markdown"] = "markdown"


class ReportPreviewResponse(BaseModel):
    result_kind: str
    disclaimer: str
    run_id: str
    environment_id: str
    environment_name: str
    snapshot_id: str
    snapshot_label: str
    snapshot_sha256: str
    scenario_name: str
    result_sha256: str
    evidence_count: int
    limitations: list[str]
    markdown: str


class AdminUserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: Literal["viewer", "analyst", "admin"]
    is_active: bool
    active_session_count: int
    last_login_at: str | None
    created_at: str | None


class AdminUserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    is_active: bool = True


class AdminUserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: Literal["viewer", "analyst", "admin"] | None = None
    is_active: bool | None = None


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=128)


class AdminPasswordResetResponse(BaseModel):
    user_id: str
    email: str
    sessions_revoked: int


class RetentionSummaryResponse(BaseModel):
    dry_run: bool
    as_of: str | None
    policy_days: dict[str, int]
    counts: dict[str, int]
    audit_chain_preserved: bool
