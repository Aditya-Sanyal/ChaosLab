import type {
  AdminPasswordResetResponse,
  AdminUserCreateRequest,
  AdminUserOut,
  AdminUserUpdateRequest,
  AssetDetailResponse,
  AssetSummary,
  AttackPathSweepResponse,
  AuditListResponse,
  AuditVerifyResponse,
  DefensiveActionInput,
  EnvironmentOverviewResponse,
  EnvironmentSummary,
  FindingDetailResponse,
  FindingOut,
  FindingUpdateRequest,
  ImportBatchSummary,
  ImportReportResponse,
  InlineScenarioInput,
  ReportPreviewResponse,
  RetentionSummaryResponse,
  RunComparisonResponse,
  ScenarioCreateRequest,
  ScenarioRunResponse,
  ScenarioSummary,
  SnapshotDetail,
  SnapshotSummary,
  TopologyGraphResponse,
  UserResponse,
} from "./types";

export class ApiError extends Error {
  status: number;
  detail: string;
  data?: unknown;

  constructor(status: number, detail: string, data?: unknown) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.data = data;
  }
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);

  const isFormData = typeof FormData !== "undefined" && init.body instanceof FormData;
  if (init.body !== undefined && !isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (MUTATING_METHODS.has(method)) {
    headers.set("X-Requested-With", "chaoslab");
  }

  const response = await fetch(`/api${path}`, {
    ...init,
    method,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    let data: unknown;
    try {
      data = await response.json();
      if (data && typeof data === "object" && "detail" in data) {
        const d = (data as { detail?: unknown }).detail;
        if (typeof d === "string" && d.length > 0) {
          detail = d;
        }
      }
    } catch {
      // Non-JSON error body
    }
    throw new ApiError(response.status, detail, data);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login: (email: string, password: string) =>
    apiFetch<UserResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  logout: () => apiFetch<void>("/auth/logout", { method: "POST" }),

  getMe: () => apiFetch<UserResponse>("/auth/me"),

  listEnvironments: () => apiFetch<EnvironmentSummary[]>("/environments"),

  createEnvironment: (name: string, description: string) =>
    apiFetch<EnvironmentSummary>("/environments", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),

  getEnvironmentOverview: (envId: string) =>
    apiFetch<EnvironmentOverviewResponse>(`/environments/${envId}/overview`),

  listAssets: (
    envId: string,
    params: {
      search?: string;
      zone_key?: string;
      asset_type?: string;
      min_criticality?: number;
      origin?: string;
      internet_exposed?: boolean;
      has_findings?: boolean;
    } = {}
  ) => {
    const qs = new URLSearchParams();
    if (params.search) qs.set("search", params.search);
    if (params.zone_key) qs.set("zone_key", params.zone_key);
    if (params.asset_type) qs.set("asset_type", params.asset_type);
    if (params.min_criticality !== undefined) {
      qs.set("min_criticality", String(params.min_criticality));
    }
    if (params.origin) qs.set("origin", params.origin);
    if (params.internet_exposed !== undefined) {
      qs.set("internet_exposed", String(params.internet_exposed));
    }
    if (params.has_findings !== undefined) {
      qs.set("has_findings", String(params.has_findings));
    }
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return apiFetch<AssetSummary[]>(`/environments/${envId}/assets${suffix}`);
  },

  getAssetDetail: (envId: string, assetKey: string) =>
    apiFetch<AssetDetailResponse>(`/environments/${envId}/assets/${encodeURIComponent(assetKey)}`),

  getTopologyGraph: (envId: string) => apiFetch<TopologyGraphResponse>(`/environments/${envId}/graph`),

  listFindings: (
    envId: string,
    params: { severity?: string; status?: string; category?: string; search?: string } = {}
  ) => {
    const qs = new URLSearchParams();
    if (params.severity) qs.set("severity", params.severity);
    if (params.status) qs.set("status", params.status);
    if (params.category) qs.set("category", params.category);
    if (params.search) qs.set("search", params.search);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return apiFetch<FindingOut[]>(`/environments/${envId}/findings${suffix}`);
  },

  getFindingDetail: (envId: string, findingKey: string) =>
    apiFetch<FindingDetailResponse>(
      `/environments/${envId}/findings/${encodeURIComponent(findingKey)}`
    ),

  updateFinding: (envId: string, findingKey: string, payload: FindingUpdateRequest) =>
    apiFetch<FindingDetailResponse>(
      `/environments/${envId}/findings/${encodeURIComponent(findingKey)}`,
      {
        method: "PATCH",
        body: JSON.stringify(payload),
      }
    ),

  getAttackPaths: (
    snapshotId: string,
    params: {
      start_kind?: "zone" | "asset";
      start_key?: string;
      start_level?: "user" | "admin";
      target_mode?: "crown_jewels" | "high_criticality" | "all_assets";
      goal_level?: "user" | "admin";
      k_paths?: number;
      max_depth?: number;
      max_expansions?: number;
    } = {}
  ) => {
    const qs = new URLSearchParams();
    if (params.start_kind) qs.set("start_kind", params.start_kind);
    if (params.start_key) qs.set("start_key", params.start_key);
    if (params.start_level) qs.set("start_level", params.start_level);
    if (params.target_mode) qs.set("target_mode", params.target_mode);
    if (params.goal_level) qs.set("goal_level", params.goal_level);
    if (params.k_paths !== undefined) qs.set("k_paths", String(params.k_paths));
    if (params.max_depth !== undefined) qs.set("max_depth", String(params.max_depth));
    if (params.max_expansions !== undefined) {
      qs.set("max_expansions", String(params.max_expansions));
    }
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return apiFetch<AttackPathSweepResponse>(`/snapshots/${snapshotId}/attack-paths${suffix}`);
  },

  listSnapshots: (envId: string) => apiFetch<SnapshotSummary[]>(`/environments/${envId}/snapshots`),

  getSnapshotDetail: (snapshotId: string) =>
    apiFetch<SnapshotDetail>(`/snapshots/${snapshotId}`),

  createSnapshot: (envId: string, label?: string) =>
    apiFetch<SnapshotSummary>(`/environments/${envId}/snapshots`, {
      method: "POST",
      body: JSON.stringify({ label: label ?? null }),
    }),

  listScenarios: (envId: string) => apiFetch<ScenarioSummary[]>(`/environments/${envId}/scenarios`),

  createScenario: (envId: string, payload: ScenarioCreateRequest) =>
    apiFetch<ScenarioSummary>(`/environments/${envId}/scenarios`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteScenario: (envId: string, scenarioId: string) =>
    apiFetch<void>(`/environments/${envId}/scenarios/${scenarioId}`, {
      method: "DELETE",
    }),

  runScenario: (
    snapshotId: string,
    payload: {
      scenario_id?: string;
      inline_scenario?: InlineScenarioInput;
      actions?: DefensiveActionInput[];
    }
  ) =>
    apiFetch<ScenarioRunResponse>(`/snapshots/${snapshotId}/runs`, {
      method: "POST",
      body: JSON.stringify({
        ...(payload.scenario_id ? { scenario_id: payload.scenario_id } : {}),
        ...(payload.inline_scenario ? { inline_scenario: payload.inline_scenario } : {}),
        actions: payload.actions ?? [],
      }),
    }),

  listRuns: (
    envId: string,
    params: { snapshot_id?: string; scenario_id?: string; limit?: number } = {}
  ) => {
    const qs = new URLSearchParams();
    if (params.snapshot_id) qs.set("snapshot_id", params.snapshot_id);
    if (params.scenario_id) qs.set("scenario_id", params.scenario_id);
    if (params.limit !== undefined) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return apiFetch<ScenarioRunResponse[]>(`/environments/${envId}/runs${suffix}`);
  },

  compareRuns: (runAId: string, runBId: string) => {
    const qs = new URLSearchParams({ run_a_id: runAId, run_b_id: runBId });
    return apiFetch<RunComparisonResponse>(`/runs/compare?${qs.toString()}`);
  },

  getRunReportPreview: (runId: string) =>
    apiFetch<ReportPreviewResponse>(`/runs/${encodeURIComponent(runId)}/report`),

  exportRunReport: async (
    runId: string,
    format: "html" | "markdown"
  ): Promise<{ blob: Blob; filename: string; reportSha256: string | null }> => {
    const response = await fetch(`/api/runs/${encodeURIComponent(runId)}/report/export`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "chaoslab",
      },
      credentials: "include",
      body: JSON.stringify({ format }),
    });
    if (!response.ok) {
      let detail = `Export failed (${response.status})`;
      let data: unknown;
      try {
        data = await response.json();
        if (data && typeof data === "object" && "detail" in data) {
          const d = (data as { detail?: unknown }).detail;
          if (typeof d === "string" && d.length > 0) {
            detail = d;
          }
        }
      } catch {
        // Non-JSON error body
      }
      throw new ApiError(response.status, detail, data);
    }
    const cd = response.headers.get("Content-Disposition") ?? "";
    const match = /filename="([^"]+)"/.exec(cd);
    const fallbackExt = format === "html" ? "html" : "md";
    const filename = match?.[1] ?? `chaoslab-report-${runId.slice(0, 8)}.${fallbackExt}`;
    const reportSha256 = response.headers.get("X-Report-SHA256");
    const blob = await response.blob();
    return { blob, filename, reportSha256 };
  },

  listAudit: (
    params:
      | number
      | {
          action?: string;
          actor?: string;
          subject_type?: string;
          since?: string;
          until?: string;
          search?: string;
          limit?: number;
          offset?: number;
        } = {}
  ) => {
    const normalized = typeof params === "number" ? { limit: params } : params;
    const qs = new URLSearchParams();
    if (normalized.action) qs.set("action", normalized.action);
    if (normalized.actor) qs.set("actor", normalized.actor);
    if (normalized.subject_type) qs.set("subject_type", normalized.subject_type);
    if (normalized.since) qs.set("since", normalized.since);
    if (normalized.until) qs.set("until", normalized.until);
    if (normalized.search) qs.set("search", normalized.search);
    if (normalized.limit !== undefined) qs.set("limit", String(normalized.limit));
    if (normalized.offset !== undefined) qs.set("offset", String(normalized.offset));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return apiFetch<AuditListResponse>(`/audit${suffix}`);
  },

  verifyAudit: () => apiFetch<AuditVerifyResponse>("/audit/verify"),

  listUsers: () => apiFetch<AdminUserOut[]>("/admin/users"),

  createUser: (payload: AdminUserCreateRequest) =>
    apiFetch<AdminUserOut>("/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateUser: (userId: string, payload: AdminUserUpdateRequest) =>
    apiFetch<AdminUserOut>(`/admin/users/${encodeURIComponent(userId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  resetUserPassword: (userId: string, newPassword: string) =>
    apiFetch<AdminPasswordResetResponse>(
      `/admin/users/${encodeURIComponent(userId)}/reset-password`,
      {
        method: "POST",
        body: JSON.stringify({ new_password: newPassword }),
      }
    ),

  getRetentionPolicy: () => apiFetch<RetentionSummaryResponse>("/admin/retention-policy"),

  listImports: (envId: string) =>
    apiFetch<ImportBatchSummary[]>(`/environments/${envId}/imports`),

  validateImport: (envId: string, formData: FormData) =>
    apiFetch<ImportReportResponse>(`/environments/${envId}/imports/validate`, {
      method: "POST",
      body: formData,
    }),

  commitImport: (envId: string, formData: FormData) =>
    apiFetch<ImportReportResponse>(`/environments/${envId}/imports/commit`, {
      method: "POST",
      body: formData,
    }),
};
