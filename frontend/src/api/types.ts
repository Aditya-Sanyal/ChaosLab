export type Role = "viewer" | "analyst" | "admin";

export interface UserResponse {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
}

export interface ProvenanceOut {
  origin: string;
  source: string;
  observed_at: string | null;
  confidence: number;
  import_batch_id: string | null;
  created_at: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

export interface EnvironmentSummary {
  id: string;
  name: string;
  description: string;
  is_demo: boolean;
  created_at: string | null;
}

export interface AssetSummary {
  id: string;
  key: string;
  name: string;
  type: string;
  zone_key: string | null;
  criticality: number;
  crown_jewel: boolean;
  owner: string;
  hostname: string | null;
  ip_addresses: string[];
  os: string | null;
  tags: string[];
  internet_exposed: boolean;
  service_count: number;
  finding_count: number;
  max_severity: string | null;
  provenance: ProvenanceOut;
}

export interface ServiceOut {
  key: string;
  port: number;
  protocol: string;
  name: string;
  product: string | null;
  version: string | null;
  provenance: ProvenanceOut;
}

export interface AssetRelationshipOut {
  key: string;
  direction: string;
  source_asset_key: string;
  target_asset_key: string;
  type: string;
  attributes: Record<string, unknown>;
  provenance: ProvenanceOut;
}

export interface AssetFindingOut {
  key: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  port: number | null;
  cwe: string | null;
  cve: string | null;
  remediation_notes: string;
  provenance: ProvenanceOut;
}

export interface AssetControlOut {
  key: string;
  name: string;
  type: string;
  affects_rules: string[];
  ports: number[];
  factor: number;
  status: string;
  provenance: ProvenanceOut;
}

export interface EvidenceOut {
  key: string;
  kind: string;
  title: string;
  excerpt: string;
  sha256: string;
  provenance: ProvenanceOut;
}

export interface AssetDetailResponse {
  id: string;
  key: string;
  name: string;
  type: string;
  zone_key: string | null;
  zone_name: string | null;
  criticality: number;
  crown_jewel: boolean;
  owner: string;
  hostname: string | null;
  ip_addresses: string[];
  os: string | null;
  tags: string[];
  description: string;
  internet_exposed: boolean;
  provenance: ProvenanceOut;
  services: ServiceOut[];
  relationships: AssetRelationshipOut[];
  findings: AssetFindingOut[];
  controls: AssetControlOut[];
  evidence: EvidenceOut[];
}

export interface GraphZoneOut {
  key: string;
  name: string;
  trust_level: string;
  intra_zone_policy: string;
  cidrs: string[];
}

export interface GraphReachabilityEdgeOut {
  key: string;
  source_kind: string;
  source_key: string;
  target_kind: string;
  target_key: string;
  ports: number[];
  protocol: string;
  description: string;
  inferred_zone_flow: boolean;
  confidence: number;
}

export interface GraphRelationshipEdgeOut {
  key: string;
  source_asset_key: string;
  target_asset_key: string;
  type: string;
  attributes: Record<string, unknown>;
  confidence: number;
}

export interface TopologyGraphResponse {
  environment: {
    id: string;
    name: string;
    description: string;
    is_demo: boolean;
  };
  zones: GraphZoneOut[];
  assets: AssetSummary[];
  reachability_edges: GraphReachabilityEdgeOut[];
  relationship_edges: GraphRelationshipEdgeOut[];
}

export interface AffectedAssetOut {
  asset_key: string;
  port: number | null;
  status_override: string | null;
}

export interface FindingOut {
  id: string;
  key: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  cwe: string | null;
  cve: string | null;
  exploitability: number | null;
  grants: string;
  requires_auth: boolean;
  description: string;
  remediation_notes: string;
  affected_assets: AffectedAssetOut[];
  evidence_keys: string[];
  status_history_count?: number;
  provenance: ProvenanceOut;
}

export interface FindingStatusHistoryEntry {
  at: string | null;
  actor: string;
  from_status: string;
  to_status: string;
  comment: string;
}

export interface FindingAffectedAssetDetailOut {
  asset_key: string;
  asset_name: string;
  zone_key: string | null;
  port: number | null;
  status_override: string | null;
  effective_status: string;
}

export interface FindingDetailResponse {
  id: string;
  key: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  cwe: string | null;
  cve: string | null;
  exploitability: number | null;
  grants: string;
  requires_auth: boolean;
  description: string;
  remediation_notes: string;
  status_history: FindingStatusHistoryEntry[];
  affected_assets: FindingAffectedAssetDetailOut[];
  evidence: EvidenceOut[];
  provenance: ProvenanceOut;
}

export interface FindingUpdateRequest {
  status?: "open" | "in_progress" | "accepted_risk" | "remediated" | "false_positive";
  remediation_notes?: string;
  comment?: string;
  asset_status_overrides?: {
    asset_key: string;
    port: number | null;
    status_override:
      | "open"
      | "in_progress"
      | "accepted_risk"
      | "remediated"
      | "false_positive"
      | null;
  }[];
}

export interface SnapshotSummary {
  id: string;
  environment_id: string;
  label: string;
  sha256: string;
  counts: Record<string, number>;
  created_by: string;
  created_at: string | null;
}

export interface SnapshotZoneDoc {
  key: string;
  name: string;
  trust_level: string;
  intra_zone_policy: string;
  cidrs: string[];
}

export interface SnapshotAssetDoc {
  key: string;
  name: string;
  type: string;
  zone_key: string | null;
  criticality: number;
  tags: string[];
}

export interface SnapshotRelationshipDoc {
  key: string;
  source_asset_key: string;
  target_asset_key: string;
  type: string;
  attributes: Record<string, unknown>;
}

export interface SnapshotReachabilityDoc {
  key: string;
  source_kind: string;
  source_key: string;
  target_kind: string;
  target_key: string;
  ports: number[];
  protocol: string;
  description: string;
}

export interface SnapshotFindingDoc {
  key: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  affected_assets: { asset_key: string; port: number | null; status_override: string | null }[];
}

export interface SnapshotControlDoc {
  key: string;
  name: string;
  type: string;
  asset_key: string;
  affects_rules: string[];
  ports: number[];
  factor: number;
  status: string;
}

export interface SnapshotDocument {
  schema_version: number;
  environment: { name: string };
  zones: SnapshotZoneDoc[];
  assets: SnapshotAssetDoc[];
  relationships: SnapshotRelationshipDoc[];
  reachability: SnapshotReachabilityDoc[];
  findings: SnapshotFindingDoc[];
  controls: SnapshotControlDoc[];
}

export interface SnapshotDetail extends SnapshotSummary {
  document: SnapshotDocument;
}

export interface TargetInput {
  asset_key: string;
  level: "user" | "admin" | "identity";
}

export interface InlineScenarioInput {
  name: string;
  start_kind: "zone" | "asset";
  start_key: string;
  start_level: "user" | "admin";
  targets: TargetInput[];
  max_depth: number;
  k_paths: number;
  max_expansions: number;
}

export interface ScenarioCreateRequest {
  name: string;
  description: string;
  start_kind: "zone" | "asset";
  start_key: string;
  start_level: "user" | "admin";
  targets: TargetInput[];
  max_depth: number;
  k_paths: number;
  max_expansions: number;
}

export interface ScenarioSummary {
  id: string;
  environment_id: string;
  name: string;
  description: string;
  start_kind: string;
  start_key: string;
  start_level: string;
  targets: { asset_key: string; level: string }[];
  parameters: Record<string, number>;
  created_by: string;
  created_at: string | null;
}

export interface Prerequisite {
  kind: string;
  key: string;
  detail: string;
  confidence: number;
}

export interface AppliedControl {
  key: string;
  name: string;
  factor: number;
}

export interface ModeledStep {
  step_key: string;
  rule_id: string;
  rule_name: string;
  rule_description: string;
  from_position: string;
  target_key: string;
  gains: string;
  required_capabilities: string[];
  prerequisites: Prerequisite[];
  evidence_keys: string[];
  controls_applied: AppliedControl[];
  base_likelihood: number;
  likelihood: number;
  confidence: number;
  reference_labels: string[];
  assumptions: string[];
}

export interface ModeledPath {
  path_key: string;
  target_key: string;
  goal_capability: string;
  modeled_score: number;
  path_likelihood: number;
  path_confidence: number;
  weighted_likelihood: number;
  impact: number;
  low_confidence: boolean;
  steps: ModeledStep[];
}

export interface AnalysisSection {
  headline_score: number;
  total_paths: number;
  search_truncated: boolean;
  limits: {
    max_depth: number;
    k_paths: number;
    max_expansions: number;
  };
  paths: ModeledPath[];
}

export interface ComparisonDiffEntry {
  path_key: string;
  target_key: string;
  score_before: number;
  score_after: number;
  score_delta: number;
  status: string;
  changed_steps?: {
    step_key: string;
    likelihood_before: number;
    likelihood_after: number;
    controls_after: string[];
  }[];
}

export interface ComparisonSection {
  baseline_headline_score: number;
  modified_headline_score: number;
  score_delta: number;
  baseline_path_count: number;
  modified_path_count: number;
  removed: ComparisonDiffEntry[];
  remaining: ComparisonDiffEntry[];
  new: ComparisonDiffEntry[];
}

export interface DefensiveActionInput {
  kind:
    | "remediate_finding"
    | "remove_relationship"
    | "remove_reachability"
    | "set_zone_isolation"
    | "add_control"
    | "activate_control";
  params: Record<string, unknown>;
}

export interface ScenarioRunResultPayload {
  result_kind: "scenario_result";
  disclaimer: string;
  engine_version: string;
  ruleset_version: string;
  snapshot_id: string;
  snapshot_sha256: string;
  scenario: {
    name: string;
    start_kind: string;
    start_key: string;
    start_level: string;
    targets: { asset_key: string; level: string }[];
    max_depth?: number;
    k_paths?: number;
    max_expansions?: number;
  };
  actions: DefensiveActionInput[];
  global_assumptions: string[];
  baseline: AnalysisSection;
  modified: AnalysisSection | null;
  comparison: ComparisonSection | null;
  input_sha256: string;
  result_sha256: string;
}

export interface ScenarioRunResponse {
  id: string;
  environment_id: string;
  scenario_id: string | null;
  snapshot_id: string;
  result_kind: "scenario_result";
  disclaimer: string;
  actions: DefensiveActionInput[];
  engine_version: string;
  ruleset_version: string;
  input_sha256: string;
  result_sha256: string;
  result: ScenarioRunResultPayload;
  status: string;
  duration_ms: number;
  created_by: string;
  created_at: string | null;
}

export interface AuditEventOut {
  seq: number;
  at: string | null;
  actor_user_id: string | null;
  actor_email: string | null;
  action: string;
  subject_type: string;
  subject_id: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditListResponse {
  total: number;
  items: AuditEventOut[];
}

export interface AuditVerifyResponse {
  valid: boolean;
  checked_count: number;
  first_broken_seq: number | null;
}

export interface ImportIssueOut {
  severity: string;
  entity: string;
  row: number | null;
  field: string | null;
  code: string;
  message: string;
}

export interface ImportBatchSummary {
  id: string;
  environment_id: string;
  format: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  status: string;
  counts: Record<string, Record<string, number>>;
  error_count: number;
  created_by: string;
  created_at: string | null;
}

export interface ImportReportResponse {
  batch_id: string;
  environment_id: string;
  format: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  status: string;
  counts: Record<string, Record<string, number>>;
  errors: ImportIssueOut[];
  warnings: ImportIssueOut[];
  created_by: string;
  created_at: string | null;
}

export interface ZoneBreakdownOut {
  key: string;
  name: string;
  trust_level: string;
  intra_zone_policy: string;
  asset_count: number;
  exposed_count: number;
  active_finding_count: number;
}

export interface LatestRunBriefOut {
  id: string;
  snapshot_id: string;
  headline_score: number;
  total_paths: number;
  result_sha256: string;
  created_by: string;
  created_at: string | null;
}

export interface EnvironmentOverviewResponse {
  environment: EnvironmentSummary;
  counts: Record<string, number>;
  findings_by_severity: Record<string, number>;
  zones_breakdown: ZoneBreakdownOut[];
  latest_snapshot: SnapshotSummary | null;
  latest_run: LatestRunBriefOut | null;
  recent_imports: ImportBatchSummary[];
}

export interface AttackPathTargetSummaryOut {
  asset_key: string;
  asset_name: string;
  asset_type: string;
  zone_key: string | null;
  criticality: number;
  crown_jewel: boolean;
  goal_capability: string;
  path_count: number;
  max_score: number;
  search_truncated: boolean;
  expansions_used: number;
}

export interface AttackPathSweepResponse {
  result_kind: "modeled_attack_paths";
  disclaimer: string;
  engine_version: string;
  ruleset_version: string;
  snapshot_id: string;
  snapshot_sha256: string;
  start_kind: string;
  start_key: string;
  start_level: string;
  target_mode: string;
  goal_level: string;
  headline_score: number;
  total_paths: number;
  search_truncated: boolean;
  limits: {
    max_depth: number;
    k_paths: number;
    max_expansions: number;
  };
  targets_evaluated: AttackPathTargetSummaryOut[];
  paths: ModeledPath[];
  global_assumptions: string[];
  input_sha256: string;
  result_sha256: string;
}

export interface RunBriefOut {
  id: string;
  environment_id: string;
  scenario_id: string | null;
  scenario_name: string;
  snapshot_id: string;
  snapshot_sha256: string;
  action_count: number;
  actions: DefensiveActionInput[];
  effective_headline_score: number;
  effective_path_count: number;
  input_sha256: string;
  result_sha256: string;
  created_by: string;
  created_at: string | null;
}

export interface RunComparisonResponse {
  result_kind: "run_comparison";
  disclaimer: string;
  run_a: RunBriefOut;
  run_b: RunBriefOut;
  same_snapshot: boolean;
  same_scenario: boolean;
  same_input_hash: boolean;
  same_result_hash: boolean;
  warnings: string[];
  comparison: ComparisonSection;
}

export interface ReportPreviewResponse {
  result_kind: string;
  disclaimer: string;
  run_id: string;
  environment_id: string;
  environment_name: string;
  snapshot_id: string;
  snapshot_label: string;
  snapshot_sha256: string;
  scenario_name: string;
  result_sha256: string;
  evidence_count: number;
  limitations: string[];
  markdown: string;
}

export interface AdminUserOut {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  active_session_count: number;
  last_login_at: string | null;
  created_at: string | null;
}

export interface AdminUserCreateRequest {
  email: string;
  display_name: string;
  password: string;
  role: Role;
  is_active?: boolean;
}

export interface AdminUserUpdateRequest {
  display_name?: string;
  role?: Role;
  is_active?: boolean;
}

export interface AdminPasswordResetResponse {
  user_id: string;
  email: string;
  sessions_revoked: number;
}

export interface RetentionSummaryResponse {
  dry_run: boolean;
  as_of: string | null;
  policy_days: Record<string, number>;
  counts: Record<string, number>;
  audit_chain_preserved: boolean;
}
