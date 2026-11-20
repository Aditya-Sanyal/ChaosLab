import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, GitCompare, Play, Plus, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";
import { api, ApiError } from "../api/client";
import type {
  DefensiveActionInput,
  InlineScenarioInput,
  ScenarioCreateRequest,
  ScenarioRunResponse,
  UserResponse,
} from "../api/types";
import { AssetDetailPanel } from "./AssetDetailPanel";
import { ComparisonDiffPanel } from "./ComparisonDiffPanel";
import { DefensiveActionsBar } from "./DefensiveActionsBar";
import { PathExplanationPanel } from "./PathExplanationPanel";
import { ScenarioBuilderPanel } from "./ScenarioBuilderPanel";
import { TopologyGraph } from "./TopologyGraph";

interface ScenarioLabViewProps {
  envId: string;
  snapshotId: string;
  user: UserResponse;
}

export function ScenarioLabView({ envId, snapshotId, user }: ScenarioLabViewProps) {
  const queryClient = useQueryClient();
  const isViewer = user.role === "viewer";

  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("");
  const [activeInlineScenario, setActiveInlineScenario] = useState<InlineScenarioInput | null>(
    null
  );
  const [showBuilder, setShowBuilder] = useState(false);

  const [queuedActions, setQueuedActions] = useState<DefensiveActionInput[]>([]);
  const [activeRun, setActiveRun] = useState<ScenarioRunResponse | null>(null);
  const [viewMode, setViewMode] = useState<"modified" | "baseline">("modified");
  const [selectedPathIndex, setSelectedPathIndex] = useState<number>(0);
  const [selectedAssetKey, setSelectedAssetKey] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const [showHistory, setShowHistory] = useState<boolean>(true);
  const [historyOnlySnapshot, setHistoryOnlySnapshot] = useState<boolean>(false);
  const [verifyFeedback, setVerifyFeedback] = useState<{
    runId: string;
    ok: boolean;
    message: string;
  } | null>(null);
  const [compareRunAId, setCompareRunAId] = useState<string | null>(null);
  const [compareRunBId, setCompareRunBId] = useState<string | null>(null);

  const graphQuery = useQuery({
    queryKey: ["graph", envId],
    queryFn: () => api.getTopologyGraph(envId),
    enabled: Boolean(envId),
  });

  const snapshotDetailQuery = useQuery({
    queryKey: ["snapshot-detail", snapshotId],
    queryFn: () => api.getSnapshotDetail(snapshotId),
    enabled: Boolean(snapshotId),
  });

  const scenariosQuery = useQuery({
    queryKey: ["scenarios", envId],
    queryFn: () => api.listScenarios(envId),
    enabled: Boolean(envId),
  });

  const runsQuery = useQuery({
    queryKey: ["runs", envId, historyOnlySnapshot ? snapshotId : "all"],
    queryFn: () =>
      api.listRuns(
        envId,
        historyOnlySnapshot && snapshotId ? { snapshot_id: snapshotId } : {}
      ),
    enabled: Boolean(envId),
  });

  const assetDetailQuery = useQuery({
    queryKey: ["asset-detail", envId, selectedAssetKey],
    queryFn: () => api.getAssetDetail(envId, selectedAssetKey!),
    enabled: Boolean(envId && selectedAssetKey),
  });

  const compareRunsQuery = useQuery({
    queryKey: ["run-compare", compareRunAId, compareRunBId],
    queryFn: () => api.compareRuns(compareRunAId!, compareRunBId!),
    enabled: Boolean(compareRunAId && compareRunBId),
  });

  const scenarios = scenariosQuery.data ?? [];

  useEffect(() => {
    setSelectedScenarioId("");
    setActiveInlineScenario(null);
    setActiveRun(null);
    setQueuedActions([]);
    setSelectedAssetKey(null);
    setVerifyFeedback(null);
    setCompareRunAId(null);
    setCompareRunBId(null);
  }, [envId]);

  useEffect(() => {
    setActiveRun(null);
    setQueuedActions([]);
    setViewMode("modified");
    setVerifyFeedback(null);
  }, [snapshotId]);

  useEffect(() => {
    if (activeInlineScenario) return;
    if (scenarios.length === 0) {
      setSelectedScenarioId("");
      return;
    }
    if (!selectedScenarioId || !scenarios.some((s) => s.id === selectedScenarioId)) {
      const preferred = scenarios.find((s) => s.name.includes("Orders DB")) ?? scenarios[0];
      setSelectedScenarioId(preferred.id);
    }
  }, [scenarios, selectedScenarioId, activeInlineScenario]);

  const runMutation = useMutation({
    mutationFn: (vars: {
      scenarioId?: string;
      inlineScenario?: InlineScenarioInput;
      actions: DefensiveActionInput[];
      targetSnapshotId?: string;
    }) =>
      api.runScenario(vars.targetSnapshotId ?? snapshotId, {
        scenario_id: vars.scenarioId,
        inline_scenario: vars.inlineScenario,
        actions: vars.actions,
      }),
    onSuccess: (data) => {
      setRunError(null);
      setActiveRun(data);
      setViewMode(data.result.modified ? "modified" : "baseline");
      setSelectedPathIndex(0);
      void queryClient.invalidateQueries({ queryKey: ["runs", envId] });
      void queryClient.invalidateQueries({ queryKey: ["overview", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setRunError(err instanceof ApiError ? err.detail : "Failed to run offline simulation.");
    },
  });

  const createScenarioMutation = useMutation({
    mutationFn: (payload: ScenarioCreateRequest) => api.createScenario(envId, payload),
    onSuccess: (created) => {
      setRunError(null);
      setShowBuilder(false);
      setActiveInlineScenario(null);
      setSelectedScenarioId(created.id);
      setQueuedActions([]);
      void queryClient.invalidateQueries({ queryKey: ["scenarios", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
      if (snapshotId && !isViewer) {
        runMutation.mutate({ scenarioId: created.id, actions: [] });
      }
    },
    onError: (err) => {
      setRunError(err instanceof ApiError ? err.detail : "Failed to save scenario.");
    },
  });

  const deleteScenarioMutation = useMutation({
    mutationFn: (scenarioId: string) => api.deleteScenario(envId, scenarioId),
    onSuccess: () => {
      setRunError(null);
      setSelectedScenarioId("");
      void queryClient.invalidateQueries({ queryKey: ["scenarios", envId] });
      void queryClient.invalidateQueries({ queryKey: ["runs", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setRunError(err instanceof ApiError ? err.detail : "Failed to delete scenario.");
    },
  });

  const verifyMutation = useMutation({
    mutationFn: async (r: ScenarioRunResponse) => {
      const sc = r.result.scenario;
      const inlineFallback: InlineScenarioInput = {
        name: sc.name,
        start_kind: sc.start_kind as "zone" | "asset",
        start_key: sc.start_key,
        start_level: (sc.start_level === "admin" ? "admin" : "user") as "user" | "admin",
        targets: sc.targets.map((t) => ({
          asset_key: t.asset_key,
          level: (t.level === "admin" || t.level === "identity" ? t.level : "user") as
            | "user"
            | "admin"
            | "identity",
        })),
        max_depth: sc.max_depth ?? 6,
        k_paths: sc.k_paths ?? 5,
        max_expansions: sc.max_expansions ?? 20000,
      };
      const useSaved = r.scenario_id && scenarios.some((s) => s.id === r.scenario_id);
      const rerun = await api.runScenario(r.snapshot_id, {
        ...(useSaved ? { scenario_id: r.scenario_id! } : { inline_scenario: inlineFallback }),
        actions: r.actions,
      });
      return { original: r, rerun };
    },
    onSuccess: ({ original, rerun }) => {
      const matched = rerun.result_sha256 === original.result_sha256;
      setVerifyFeedback({
        runId: original.id,
        ok: matched,
        message: matched
          ? `Verified reproducible hash ${rerun.result_sha256.slice(0, 14)}… matches run ${original.id.slice(0, 8)}`
          : `Hash mismatch: ${rerun.result_sha256.slice(0, 12)} vs ${original.result_sha256.slice(0, 12)}`,
      });
      void queryClient.invalidateQueries({ queryKey: ["runs", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setVerifyFeedback({
        runId: "err",
        ok: false,
        message: err instanceof ApiError ? err.detail : "Re-run verification failed.",
      });
    },
  });

  // Auto-load saved run or trigger baseline once when saved scenario & snapshot are ready
  useEffect(() => {
    if (activeInlineScenario || !selectedScenarioId || !snapshotId) return;
    const saved = (runsQuery.data ?? []).find(
      (r) =>
        r.snapshot_id === snapshotId &&
        r.scenario_id === selectedScenarioId &&
        r.actions.length === 0
    );
    if (saved && queuedActions.length === 0) {
      setActiveRun(saved);
      return;
    }
    if (!isViewer && !activeRun && !runMutation.isPending && runsQuery.isSuccess) {
      runMutation.mutate({ scenarioId: selectedScenarioId, actions: queuedActions });
    }
    if (isViewer && !activeRun && runsQuery.data && runsQuery.data.length > 0) {
      const forSnap = runsQuery.data.find((r) => r.snapshot_id === snapshotId) ?? runsQuery.data[0];
      setActiveRun(forSnap);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedScenarioId, snapshotId, runsQuery.isSuccess, isViewer, activeInlineScenario]);

  const activeAnalysis = useMemo(() => {
    if (!activeRun) return null;
    if (viewMode === "modified" && activeRun.result.modified) {
      return activeRun.result.modified;
    }
    return activeRun.result.baseline;
  }, [activeRun, viewMode]);

  const activePath = useMemo(() => {
    if (!activeAnalysis || activeAnalysis.paths.length === 0) return null;
    return activeAnalysis.paths[selectedPathIndex] ?? activeAnalysis.paths[0];
  }, [activeAnalysis, selectedPathIndex]);

  function triggerActiveSimulation(nextActions: DefensiveActionInput[]) {
    if (isViewer || !snapshotId) return;
    if (activeInlineScenario) {
      runMutation.mutate({ inlineScenario: activeInlineScenario, actions: nextActions });
    } else if (selectedScenarioId) {
      runMutation.mutate({ scenarioId: selectedScenarioId, actions: nextActions });
    }
  }

  function handleSelectComparisonPath(pathKey: string, side: "before" | "after") {
    if (!activeRun) return;
    const nextView = side === "after" && activeRun.result.modified ? "modified" : "baseline";
    setViewMode(nextView);
    const analysis =
      nextView === "modified" && activeRun.result.modified
        ? activeRun.result.modified
        : activeRun.result.baseline;
    const idx = analysis.paths.findIndex((p) => p.path_key === pathKey);
    if (idx >= 0) {
      setSelectedPathIndex(idx);
      setSelectedAssetKey(null);
    }
  }

  const snapshotDoc = snapshotDetailQuery.data?.document ?? null;

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel px-3 py-2 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mc-kicker" style={{ color: "var(--accent)" }}>
            Scenario
          </span>
          <select
            aria-label="Scenario selector"
            value={activeInlineScenario ? "__inline__" : selectedScenarioId}
            onChange={(e) => {
              const nextId = e.target.value;
              if (nextId === "__inline__") return;
              setActiveInlineScenario(null);
              setSelectedScenarioId(nextId);
              setQueuedActions([]);
              setSelectedAssetKey(null);
              if (!isViewer && nextId && snapshotId) {
                runMutation.mutate({ scenarioId: nextId, actions: [] });
              }
            }}
            className="px-2.5 py-1 text-xs mc-elevated font-semibold focus:outline-none max-w-md"
            style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
          >
            {activeInlineScenario && (
              <option value="__inline__">
                [Ad-hoc] {activeInlineScenario.name} ({activeInlineScenario.start_kind}:
                {activeInlineScenario.start_key} →{" "}
                {activeInlineScenario.targets.map((t) => t.asset_key).join(", ")})
              </option>
            )}
            {scenarios.length === 0 && !activeInlineScenario && (
              <option value="">No saved scenarios yet — click Build Scenario</option>
            )}
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.start_kind}:{s.start_key} →{" "}
                {s.targets.map((t) => t.asset_key).join(", ")})
              </option>
            ))}
          </select>

          {!isViewer && selectedScenarioId && !activeInlineScenario && (
            <button
              type="button"
              onClick={() => deleteScenarioMutation.mutate(selectedScenarioId)}
              disabled={deleteScenarioMutation.isPending}
              title="Delete saved scenario (past runs remain in history)"
              aria-label="Delete saved scenario"
              className="p-1.5 rounded border disabled:opacity-45"
              style={{
                borderColor: "var(--border)",
                background: "var(--bg-elevated)",
                color: "var(--text-muted)",
              }}
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}

          <button
            type="button"
            onClick={() => setShowBuilder((v) => !v)}
            className="px-2.5 py-1 text-xs font-semibold rounded border inline-flex items-center gap-1"
            style={{
              borderColor: showBuilder ? "var(--accent-border)" : "var(--border-strong)",
              background: showBuilder ? "var(--accent-soft)" : "var(--bg-elevated)",
              color: showBuilder ? "var(--accent)" : "var(--text-main)",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            Build Scenario
          </button>

          <button
            type="button"
            disabled={
              isViewer ||
              runMutation.isPending ||
              (!selectedScenarioId && !activeInlineScenario) ||
              !snapshotId
            }
            onClick={() => triggerActiveSimulation(queuedActions)}
            className="px-3 py-1 text-xs font-bold uppercase tracking-wider rounded inline-flex items-center gap-1.5 disabled:opacity-45"
            style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
          >
            <Play className="w-3.5 h-3.5" />
            {runMutation.isPending ? "Simulating…" : "Run Simulation"}
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs mono" style={{ color: "var(--text-muted)" }}>
          {activeRun?.result.modified && (
            <div className="inline-flex rounded border overflow-hidden" style={{ borderColor: "var(--border-strong)" }}>
              <button
                type="button"
                onClick={() => {
                  setViewMode("modified");
                  setSelectedPathIndex(0);
                }}
                className="px-2 py-0.5 text-[11px]"
                style={{
                  background: viewMode === "modified" ? "var(--accent-soft)" : "var(--bg-elevated)",
                  color: viewMode === "modified" ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                Modified
              </button>
              <button
                type="button"
                onClick={() => {
                  setViewMode("baseline");
                  setSelectedPathIndex(0);
                }}
                className="px-2 py-0.5 text-[11px]"
                style={{
                  background: viewMode === "baseline" ? "var(--accent-soft)" : "var(--bg-elevated)",
                  color: viewMode === "baseline" ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                Baseline
              </button>
            </div>
          )}

          <span>
            {activeRun
              ? `Run ${activeRun.id.slice(0, 8)} · ${activeRun.duration_ms}ms · ${activeRun.created_by}`
              : "No simulation loaded yet"}
          </span>
        </div>
      </div>

      {showBuilder && (
        <ScenarioBuilderPanel
          snapshotDoc={snapshotDoc}
          disabled={isViewer}
          running={runMutation.isPending}
          saving={createScenarioMutation.isPending}
          onRunInline={(inline) => {
            setShowBuilder(false);
            setSelectedScenarioId("");
            setActiveInlineScenario(inline);
            setQueuedActions([]);
            setSelectedAssetKey(null);
            runMutation.mutate({ inlineScenario: inline, actions: [] });
          }}
          onSaveAndRun={(payload) => createScenarioMutation.mutate(payload)}
          onClose={() => setShowBuilder(false)}
        />
      )}

      {runError && (
        <div
          className="p-2.5 text-xs border rounded flex items-center gap-2"
          style={{
            background: "var(--crit-bg)",
            color: "var(--crit)",
            borderColor: "rgba(239, 68, 68, 0.45)",
          }}
        >
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{runError}</span>
        </div>
      )}

      <div className="flex-1 grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-0">
        <div className="xl:col-span-8 flex flex-col min-h-0">
          <TopologyGraph
            graph={graphQuery.data ?? null}
            activePath={activePath}
            selectedAssetKey={selectedAssetKey}
            onSelectAsset={(key) => setSelectedAssetKey(key)}
          />
        </div>

        <aside className="xl:col-span-4 mc-panel p-3 overflow-y-auto thin-scroll max-h-[620px]">
          {selectedAssetKey ? (
            <AssetDetailPanel
              asset={assetDetailQuery.data ?? null}
              loading={assetDetailQuery.isLoading}
              error={
                assetDetailQuery.error instanceof ApiError
                  ? assetDetailQuery.error.detail
                  : assetDetailQuery.isError
                    ? "Failed to load asset details."
                    : null
              }
              onBackToPath={() => setSelectedAssetKey(null)}
            />
          ) : (
            <PathExplanationPanel
              meta={
                activeRun
                  ? {
                      resultKind: activeRun.result_kind,
                      disclaimer: activeRun.disclaimer,
                      engineVersion: activeRun.engine_version,
                      rulesetVersion: activeRun.ruleset_version,
                      snapshotSha256: activeRun.result.snapshot_sha256,
                      resultSha256: activeRun.result_sha256,
                      globalAssumptions: activeRun.result.global_assumptions,
                    }
                  : null
              }
              analysis={activeAnalysis}
              selectedPathIndex={selectedPathIndex}
              onSelectPath={setSelectedPathIndex}
              loading={runMutation.isPending}
            />
          )}
        </aside>
      </div>

      <DefensiveActionsBar
        snapshotDoc={snapshotDoc}
        actions={queuedActions}
        onApplyActions={(next) => {
          setQueuedActions(next);
          triggerActiveSimulation(next);
        }}
        run={activeRun}
        disabled={isViewer}
        running={runMutation.isPending}
      />

      {activeRun?.result.comparison && (
        <ComparisonDiffPanel
          title="Before / After Path Comparison (Within Active Run)"
          subtitle="Click any modeled path row to inspect that path on the topology graph."
          comparison={activeRun.result.comparison}
          onSelectPathKey={handleSelectComparisonPath}
        />
      )}

      <section className="mc-panel p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setShowHistory((v) => !v)}
              className="text-xs font-semibold flex items-center gap-2"
              style={{ color: "var(--text-muted)" }}
            >
              <span className="mc-kicker" style={{ color: "var(--accent)" }}>
                Scenario Run History ({(runsQuery.data ?? []).length})
              </span>
              <span>{showHistory ? "▲ Hide" : "▼ Show"}</span>
            </button>

            <label className="inline-flex items-center gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
              <input
                type="checkbox"
                checked={historyOnlySnapshot}
                onChange={(e) => setHistoryOnlySnapshot(e.target.checked)}
                className="accent-amber-500"
              />
              Current snapshot only
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs mono" style={{ color: "var(--text-dim)" }}>
            {(compareRunAId || compareRunBId) && (
              <button
                type="button"
                onClick={() => {
                  setCompareRunAId(null);
                  setCompareRunBId(null);
                }}
                className="px-2 py-0.5 rounded border"
                style={{ borderColor: "var(--border-strong)", color: "var(--text-muted)" }}
              >
                Clear Compare ({compareRunAId ? compareRunAId.slice(0, 6) : "?"} vs{" "}
                {compareRunBId ? compareRunBId.slice(0, 6) : "?"})
              </button>
            )}
            <span>Pick Set A &amp; Set B to compare runs across strategies or snapshots</span>
          </div>
        </div>

        {verifyFeedback && (
          <div
            className="p-2 rounded border text-xs flex items-center gap-2"
            style={{
              borderColor: verifyFeedback.ok ? "rgba(34, 197, 94, 0.4)" : "rgba(239, 68, 68, 0.45)",
              background: verifyFeedback.ok ? "var(--ok-bg)" : "var(--crit-bg)",
              color: verifyFeedback.ok ? "var(--ok)" : "var(--crit)",
            }}
          >
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span className="mono">{verifyFeedback.message}</span>
          </div>
        )}

        {showHistory && (
          <div className="border-t pt-2 overflow-x-auto" style={{ borderColor: "var(--border)" }}>
            {(runsQuery.data ?? []).length === 0 ? (
              <div className="text-xs" style={{ color: "var(--text-dim)" }}>
                No recorded scenario runs match this filter.
              </div>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr
                    className="mc-kicker border-b"
                    style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}
                  >
                    <th className="py-1.5 pr-3">Run</th>
                    <th className="py-1.5 pr-3">Scenario</th>
                    <th className="py-1.5 pr-3">Snapshot</th>
                    <th className="py-1.5 pr-3">Score</th>
                    <th className="py-1.5 pr-3">Actions</th>
                    <th className="py-1.5 pr-3">Result SHA-256</th>
                    <th className="py-1.5 pr-3">Actor</th>
                    <th className="py-1.5">Tools</th>
                  </tr>
                </thead>
                <tbody>
                  {(runsQuery.data ?? []).slice(0, 20).map((r) => {
                    const baseScore = r.result.baseline.headline_score;
                    const modScore = r.result.modified?.headline_score;
                    const isCurrent = activeRun?.id === r.id;
                    const isA = compareRunAId === r.id;
                    const isB = compareRunBId === r.id;
                    return (
                      <tr
                        key={r.id}
                        className="border-b"
                        style={{
                          borderColor: "var(--border)",
                          background: isCurrent ? "var(--accent-soft)" : "transparent",
                        }}
                      >
                        <td
                          onClick={() => {
                            setActiveRun(r);
                            setViewMode(r.result.modified ? "modified" : "baseline");
                            setSelectedPathIndex(0);
                            setSelectedAssetKey(null);
                          }}
                          className="py-1.5 pr-3 mono font-semibold cursor-pointer underline-offset-2 hover:underline"
                          style={{ color: "var(--accent)" }}
                        >
                          {r.id.slice(0, 8)}
                        </td>
                        <td className="py-1.5 pr-3" style={{ color: "var(--text-main)" }}>
                          {r.result.scenario.name}
                          {!r.scenario_id && (
                            <span className="ml-1 mono text-[10px]" style={{ color: "var(--text-dim)" }}>
                              (inline/unlinked)
                            </span>
                          )}
                        </td>
                        <td className="py-1.5 pr-3 mono" style={{ color: "var(--text-dim)" }}>
                          {r.result.snapshot_sha256.slice(0, 8)}
                        </td>
                        <td className="py-1.5 pr-3 mono font-bold" style={{ color: "var(--accent)" }}>
                          {modScore !== undefined ? `${baseScore} → ${modScore}` : baseScore}/100
                        </td>
                        <td className="py-1.5 pr-3 mono" style={{ color: "var(--text-muted)" }}>
                          {r.actions.length === 0 ? "baseline" : `${r.actions.length} action(s)`}
                        </td>
                        <td className="py-1.5 pr-3 mono" style={{ color: "var(--text-dim)" }}>
                          {r.result_sha256.slice(0, 12)}…
                        </td>
                        <td className="py-1.5 pr-3 mono" style={{ color: "var(--text-muted)" }}>
                          {r.created_by}
                        </td>
                        <td className="py-1.5 flex items-center gap-1.5 mono text-[11px]">
                          {!isViewer && (
                            <button
                              type="button"
                              disabled={verifyMutation.isPending}
                              onClick={() => verifyMutation.mutate(r)}
                              title="Re-run exact snapshot + scenario + actions and verify result_sha256"
                              className="px-1.5 py-0.5 rounded border inline-flex items-center gap-1"
                              style={{
                                borderColor: "var(--border-strong)",
                                background: "var(--bg-elevated)",
                                color: "var(--text-muted)",
                              }}
                            >
                              <RefreshCw className="w-3 h-3" />
                              Verify
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => setCompareRunAId(isA ? null : r.id)}
                            className="px-1.5 py-0.5 rounded border"
                            style={{
                              borderColor: isA ? "var(--accent-border)" : "var(--border)",
                              background: isA ? "var(--accent-soft)" : "var(--bg-elevated)",
                              color: isA ? "var(--accent)" : "var(--text-dim)",
                            }}
                          >
                            Set A
                          </button>
                          <button
                            type="button"
                            onClick={() => setCompareRunBId(isB ? null : r.id)}
                            className="px-1.5 py-0.5 rounded border"
                            style={{
                              borderColor: isB ? "var(--accent-border)" : "var(--border)",
                              background: isB ? "var(--accent-soft)" : "var(--bg-elevated)",
                              color: isB ? "var(--accent)" : "var(--text-dim)",
                            }}
                          >
                            Set B
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {compareRunsQuery.data && (
          <div className="pt-2">
            <ComparisonDiffPanel
              title={`Run-to-Run Comparison: ${compareRunsQuery.data.run_a.id.slice(0, 8)} vs ${compareRunsQuery.data.run_b.id.slice(0, 8)}`}
              comparison={compareRunsQuery.data.comparison}
              warnings={compareRunsQuery.data.warnings}
              beforeLabel={`Run A (${compareRunsQuery.data.run_a.effective_headline_score})`}
              afterLabel={`Run B (${compareRunsQuery.data.run_b.effective_headline_score})`}
              metaBanner={
                <div className="flex flex-wrap items-center gap-2 text-[11px] mono">
                  <span className="px-2 py-0.5 rounded border inline-flex items-center gap-1" style={{ borderColor: "var(--border)" }}>
                    <GitCompare className="w-3 h-3" />
                    same_snapshot:{String(compareRunsQuery.data.same_snapshot)}
                  </span>
                  <span className="px-2 py-0.5 rounded border" style={{ borderColor: "var(--border)" }}>
                    same_scenario:{String(compareRunsQuery.data.same_scenario)}
                  </span>
                  <span
                    className="px-2 py-0.5 rounded border"
                    style={{
                      borderColor: compareRunsQuery.data.same_result_hash
                        ? "rgba(34, 197, 94, 0.4)"
                        : "var(--border)",
                      color: compareRunsQuery.data.same_result_hash
                        ? "var(--ok)"
                        : "var(--text-muted)",
                    }}
                  >
                    same_result_hash:{String(compareRunsQuery.data.same_result_hash)}
                  </span>
                </div>
              }
            />
          </div>
        )}
      </section>
    </div>
  );
}
