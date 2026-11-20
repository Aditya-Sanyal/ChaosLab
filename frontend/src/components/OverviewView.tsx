import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, PlusCircle, ShieldAlert } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { UserResponse } from "../api/types";
import type { NavTab } from "./AppShell";

interface OverviewViewProps {
  envId: string;
  user: UserResponse;
  onNavigate: (tab: NavTab) => void;
  onCreatedEnv: (newEnvId: string) => void;
}

export function OverviewView({ envId, user, onNavigate, onCreatedEnv }: OverviewViewProps) {
  const queryClient = useQueryClient();
  const [showNewForm, setShowNewForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const overviewQuery = useQuery({
    queryKey: ["overview", envId],
    queryFn: () => api.getEnvironmentOverview(envId),
    enabled: Boolean(envId),
  });

  const createMutation = useMutation({
    mutationFn: () => api.createEnvironment(newName, newDesc),
    onSuccess: (created) => {
      setCreateError(null);
      setNewName("");
      setNewDesc("");
      setShowNewForm(false);
      void queryClient.invalidateQueries({ queryKey: ["environments"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
      onCreatedEnv(created.id);
    },
    onError: (err) => {
      setCreateError(err instanceof ApiError ? err.detail : "Failed to create environment.");
    },
  });

  function handleCreateSubmit(e: FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    createMutation.mutate();
  }

  const data = overviewQuery.data;
  if (overviewQuery.isLoading || !data) {
    return (
      <div className="mc-panel p-4 text-xs" style={{ color: "var(--text-muted)" }}>
        Loading environment overview…
      </div>
    );
  }

  const { environment, counts, findings_by_severity, zones_breakdown, latest_snapshot, latest_run, recent_imports } = data;

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Environment Overview
          </div>
          <h1 className="text-sm font-bold mt-0.5">{environment.name}</h1>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            {environment.description || "No environment description recorded."}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate("scenario-lab")}
            className="px-3 py-1.5 text-xs font-bold uppercase tracking-wider rounded inline-flex items-center gap-1.5"
            style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
          >
            <span>Open Scenario Lab</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => onNavigate("imports")}
            className="px-3 py-1.5 text-xs font-semibold mc-elevated"
            style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
          >
            Import Data
          </button>
          {user.role === "admin" && (
            <button
              type="button"
              onClick={() => setShowNewForm((v) => !v)}
              className="px-3 py-1.5 text-xs font-semibold mc-elevated inline-flex items-center gap-1.5"
              style={{ color: "var(--accent)", borderColor: "var(--accent-border)" }}
            >
              <PlusCircle className="w-3.5 h-3.5" />
              New Environment
            </button>
          )}
        </div>
      </div>

      {showNewForm && user.role === "admin" && (
        <form onSubmit={handleCreateSubmit} className="mc-panel p-3 space-y-2.5">
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Create Blank Environment
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            <input
              type="text"
              required
              minLength={2}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Environment name (e.g. Lab Staging Segment)"
              className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            />
            <input
              type="text"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Short description (optional)"
              className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            />
          </div>
          {createError && (
            <div className="text-xs flex items-center gap-1.5" style={{ color: "var(--crit)" }}>
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{createError}</span>
            </div>
          )}
          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-3 py-1 text-xs font-bold uppercase rounded"
              style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
            >
              {createMutation.isPending ? "Creating…" : "Create"}
            </button>
            <button
              type="button"
              onClick={() => setShowNewForm(false)}
              className="px-2.5 py-1 text-xs mc-elevated"
              style={{ color: "var(--text-muted)" }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5">
        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Assets / Zones</div>
          <div className="text-lg font-bold mono mt-1">
            {counts.assets} <span className="text-xs font-normal" style={{ color: "var(--text-muted)" }}>/ {counts.zones}z</span>
          </div>
          <div className="text-xs mono" style={{ color: "var(--crown)" }}>
            ◆ {counts.crown_jewels} crown jewels
          </div>
        </div>

        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Internet Exposed</div>
          <div className="text-lg font-bold mono mt-1" style={{ color: counts.internet_exposed > 0 ? "var(--high)" : "var(--ok)" }}>
            {counts.internet_exposed}
          </div>
          <div className="text-xs mono" style={{ color: "var(--text-dim)" }}>
            {counts.services} services
          </div>
        </div>

        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Active Findings</div>
          <div className="text-lg font-bold mono mt-1" style={{ color: findings_by_severity.critical > 0 ? "var(--crit)" : "var(--text-main)" }}>
            {counts.findings_open}
          </div>
          <div className="text-xs mono" style={{ color: "var(--text-muted)" }}>
            C:{findings_by_severity.critical} H:{findings_by_severity.high} M:{findings_by_severity.medium}
          </div>
        </div>

        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Graph Edges</div>
          <div className="text-lg font-bold mono mt-1">
            {counts.reachability_rules + counts.relationships}
          </div>
          <div className="text-xs mono" style={{ color: "var(--text-dim)" }}>
            {counts.reachability_rules} reach · {counts.relationships} rel
          </div>
        </div>

        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Latest Snapshot</div>
          <div className="text-xs font-bold mono mt-1 truncate">
            {latest_snapshot ? latest_snapshot.label : "None"}
          </div>
          <div className="text-xs mono mt-1" style={{ color: "var(--text-dim)" }}>
            {latest_snapshot ? `sha256 ${latest_snapshot.sha256.slice(0, 12)}…` : "Freeze before simulating"}
          </div>
        </div>

        <div className="mc-panel p-3">
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>Latest Modeled Score</div>
          <div className="text-lg font-bold mono mt-1" style={{ color: "var(--accent)" }}>
            {latest_run ? `${latest_run.headline_score}/100` : "—"}
          </div>
          <div className="text-xs mono" style={{ color: "var(--text-dim)" }}>
            {latest_run ? `${latest_run.total_paths} modeled path(s)` : "No runs recorded"}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-0 flex-1">
        <div className="xl:col-span-7 mc-panel p-3 overflow-auto thin-scroll">
          <div className="flex items-center justify-between mb-2">
            <h2 className="mc-kicker" style={{ color: "var(--text-muted)" }}>
              Trust Zone Breakdown ({zones_breakdown.length})
            </h2>
            <button
              type="button"
              onClick={() => onNavigate("assets")}
              className="text-xs font-semibold"
              style={{ color: "var(--accent)" }}
            >
              Inspect Assets →
            </button>
          </div>
          {zones_breakdown.length === 0 ? (
            <div className="text-xs py-4" style={{ color: "var(--text-dim)" }}>
              No zones in this environment yet. Import a JSON bundle or CSV zones table to begin.
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b mc-kicker" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
                  <th className="py-2 pr-2">Zone</th>
                  <th className="py-2 pr-2">Trust</th>
                  <th className="py-2 pr-2">Intra-Zone</th>
                  <th className="py-2 pr-2">Assets</th>
                  <th className="py-2 pr-2">Exposed</th>
                  <th className="py-2">Findings</th>
                </tr>
              </thead>
              <tbody>
                {zones_breakdown.map((z) => (
                  <tr key={z.key} className="border-b" style={{ borderColor: "var(--border)" }}>
                    <td className="py-2 pr-2">
                      <span className="font-bold mono">{z.key}</span>{" "}
                      <span style={{ color: "var(--text-muted)" }}>· {z.name}</span>
                    </td>
                    <td className="py-2 pr-2 mono">{z.trust_level}</td>
                    <td className="py-2 pr-2 mono" style={{ color: z.intra_zone_policy === "deny" ? "var(--ok)" : "var(--text-muted)" }}>
                      {z.intra_zone_policy}
                    </td>
                    <td className="py-2 pr-2 mono font-bold">{z.asset_count}</td>
                    <td className="py-2 pr-2 mono" style={{ color: z.exposed_count > 0 ? "var(--high)" : "var(--text-dim)" }}>
                      {z.exposed_count}
                    </td>
                    <td className="py-2 mono" style={{ color: z.active_finding_count > 0 ? "var(--crit)" : "var(--text-dim)" }}>
                      {z.active_finding_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="xl:col-span-5 mc-panel p-3 overflow-auto thin-scroll">
          <div className="flex items-center justify-between mb-2">
            <h2 className="mc-kicker" style={{ color: "var(--text-muted)" }}>
              Recent Import Batches ({recent_imports.length})
            </h2>
            <button
              type="button"
              onClick={() => onNavigate("imports")}
              className="text-xs font-semibold"
              style={{ color: "var(--accent)" }}
            >
              Imports &amp; Exports →
            </button>
          </div>
          {recent_imports.length === 0 ? (
            <div className="text-xs py-4" style={{ color: "var(--text-dim)" }}>
              No import batches recorded in this environment yet.
            </div>
          ) : (
            <div className="space-y-2">
              {recent_imports.map((b) => (
                <div key={b.id} className="p-2 mc-elevated text-xs flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="mono font-semibold truncate">{b.filename}</div>
                    <div className="mono" style={{ color: "var(--text-dim)" }}>
                      {b.format} · sha256 {b.sha256.slice(0, 10)}… · {b.created_by}
                    </div>
                  </div>
                  <span
                    className="mono px-1.5 py-0.5 rounded uppercase font-bold shrink-0"
                    style={{
                      background: b.status === "committed" ? "var(--ok-bg)" : b.status === "rejected" ? "var(--crit-bg)" : "var(--accent-soft)",
                      color: b.status === "committed" ? "var(--ok)" : b.status === "rejected" ? "var(--crit)" : "var(--accent)",
                    }}
                  >
                    {b.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
