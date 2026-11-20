import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Crown, FilterX, Route, ShieldAlert } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { ModeledPath } from "../api/types";
import { AssetDetailPanel } from "./AssetDetailPanel";
import { PathExplanationPanel, type PathResultMeta } from "./PathExplanationPanel";
import { TopologyGraph } from "./TopologyGraph";

interface AttackPathsViewProps {
  envId: string;
  snapshotId: string;
}

function scoreColor(score: number): string {
  if (score >= 8.0) return "var(--crit)";
  if (score >= 5.5) return "var(--high)";
  if (score >= 3.0) return "var(--med)";
  if (score > 0) return "var(--low)";
  return "var(--ok)";
}

export function AttackPathsView({ envId, snapshotId }: AttackPathsViewProps) {
  const [startKind, setStartKind] = useState<"zone" | "asset">("zone");
  const [startKey, setStartKey] = useState<string>("internet");
  const [startLevel, setStartLevel] = useState<"user" | "admin">("user");
  const [targetMode, setTargetMode] = useState<"crown_jewels" | "high_criticality" | "all_assets">(
    "crown_jewels"
  );
  const [goalLevel, setGoalLevel] = useState<"user" | "admin">("user");
  const [kPaths, setKPaths] = useState<number>(5);
  const [maxDepth, setMaxDepth] = useState<number>(6);
  const [maxExpansions, setMaxExpansions] = useState<number>(500);

  const [selectedTargetKey, setSelectedTargetKey] = useState<string | null>(null);
  const [selectedPathIndex, setSelectedPathIndex] = useState<number>(0);
  const [selectedAssetKey, setSelectedAssetKey] = useState<string | null>(null);

  const graphQuery = useQuery({
    queryKey: ["graph", envId],
    queryFn: () => api.getTopologyGraph(envId),
    enabled: Boolean(envId),
  });

  const graph = graphQuery.data ?? null;

  useEffect(() => {
    setSelectedTargetKey(null);
    setSelectedPathIndex(0);
    setSelectedAssetKey(null);
  }, [envId, snapshotId]);

  useEffect(() => {
    if (!graph) return;
    if (startKind === "zone") {
      const validZones = graph.zones.map((z) => z.key);
      if (!validZones.includes(startKey)) {
        setStartKey(validZones.includes("internet") ? "internet" : (validZones[0] ?? "internet"));
      }
    } else {
      const validAssets = graph.assets.map((a) => a.key);
      if (!validAssets.includes(startKey) && validAssets.length > 0) {
        setStartKey(validAssets[0]);
      }
    }
  }, [graph, startKind, startKey]);

  const sweepQuery = useQuery({
    queryKey: [
      "attack-paths",
      snapshotId,
      startKind,
      startKey,
      startLevel,
      targetMode,
      goalLevel,
      kPaths,
      maxDepth,
      maxExpansions,
    ],
    queryFn: () =>
      api.getAttackPaths(snapshotId, {
        start_kind: startKind,
        start_key: startKey,
        start_level: startLevel,
        target_mode: targetMode,
        goal_level: goalLevel,
        k_paths: kPaths,
        max_depth: maxDepth,
        max_expansions: maxExpansions,
      }),
    enabled: Boolean(snapshotId && startKey),
  });

  const assetDetailQuery = useQuery({
    queryKey: ["asset-detail", envId, selectedAssetKey],
    queryFn: () => api.getAssetDetail(envId, selectedAssetKey!),
    enabled: Boolean(envId && selectedAssetKey),
  });

  const sweep = sweepQuery.data ?? null;

  const displayedPaths: ModeledPath[] = useMemo(() => {
    if (!sweep) return [];
    if (!selectedTargetKey) return sweep.paths;
    return sweep.paths.filter((p) => p.target_key === selectedTargetKey);
  }, [sweep, selectedTargetKey]);

  useEffect(() => {
    if (selectedPathIndex >= displayedPaths.length) {
      setSelectedPathIndex(0);
    }
  }, [displayedPaths.length, selectedPathIndex]);

  const activePath = displayedPaths[selectedPathIndex] ?? null;

  const meta: PathResultMeta | null = useMemo(() => {
    if (!sweep) return null;
    return {
      resultKind: sweep.result_kind,
      disclaimer: sweep.disclaimer,
      engineVersion: sweep.engine_version,
      rulesetVersion: sweep.ruleset_version,
      snapshotSha256: sweep.snapshot_sha256,
      resultSha256: sweep.result_sha256,
      globalAssumptions: sweep.global_assumptions,
    };
  }, [sweep]);

  const totalExpansionsUsed = useMemo(() => {
    if (!sweep) return 0;
    return sweep.targets_evaluated.reduce((sum, t) => sum + t.expansions_used, 0);
  }, [sweep]);

  if (!snapshotId) {
    return (
      <div className="mc-panel p-6 text-xs flex items-center gap-2" style={{ color: "var(--text-muted)" }}>
        <Route size={16} style={{ color: "var(--accent)" }} />
        <span>Select or create an environment snapshot in the top bar to explore modeled attack paths.</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="mc-panel p-3 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="mc-kicker" style={{ color: "var(--accent)" }}>
              Multi-Target Attack Path Sweep · Read-Only Snapshot Analysis
            </div>
            <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              Bounded deterministic graph search across crown jewels or high-value targets. Outputs represent modeled paths, not live exploit proof.
            </div>
          </div>

          {sweep && (
            <div className="flex flex-wrap items-center gap-3 text-xs mono">
              <div className="px-2.5 py-1 rounded border" style={{ borderColor: "var(--border)", backgroundColor: "var(--bg-elevated)" }}>
                <span style={{ color: "var(--text-dim)" }}>headline: </span>
                <span className="font-bold" style={{ color: scoreColor(sweep.headline_score) }}>
                  {sweep.headline_score.toFixed(1)}
                </span>
              </div>
              <div className="px-2.5 py-1 rounded border" style={{ borderColor: "var(--border)", backgroundColor: "var(--bg-elevated)" }}>
                <span style={{ color: "var(--text-dim)" }}>paths: </span>
                <span style={{ color: "var(--text-main)" }}>{sweep.total_paths}</span>
              </div>
              <div className="px-2.5 py-1 rounded border" style={{ borderColor: "var(--border)", backgroundColor: "var(--bg-elevated)" }}>
                <span style={{ color: "var(--text-dim)" }}>expansions: </span>
                <span style={{ color: "var(--text-main)" }}>{totalExpansionsUsed}</span>
              </div>
              {sweep.search_truncated && (
                <div
                  className="px-2.5 py-1 rounded border flex items-center gap-1"
                  style={{
                    borderColor: "rgba(251, 146, 60, 0.45)",
                    backgroundColor: "var(--high-bg)",
                    color: "var(--high)",
                  }}
                >
                  <AlertTriangle size={12} />
                  <span>truncated</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-xs">
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Start Kind
            </span>
            <select
              value={startKind}
              onChange={(e) => {
                const nextKind = e.target.value as "zone" | "asset";
                setStartKind(nextKind);
                if (nextKind === "zone") {
                  setStartKey("internet");
                } else if (graph && graph.assets.length > 0) {
                  setStartKey(graph.assets[0].key);
                }
                setSelectedPathIndex(0);
              }}
              aria-label="Start Kind"
              className="w-full px-2 py-1.5 rounded border text-xs"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              <option value="zone">zone</option>
              <option value="asset">asset</option>
            </select>
          </label>

          <label className="space-y-1 col-span-2 sm:col-span-2">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Start Position ({startKind})
            </span>
            <select
              value={startKey}
              onChange={(e) => {
                setStartKey(e.target.value);
                setSelectedPathIndex(0);
              }}
              aria-label="Start Position"
              className="w-full px-2 py-1.5 rounded border text-xs mono"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              {startKind === "zone"
                ? (graph?.zones ?? [{ key: "internet", name: "Internet" }]).map((z) => (
                    <option key={z.key} value={z.key}>
                      {z.key} ({z.name})
                    </option>
                  ))
                : (graph?.assets ?? []).map((a) => (
                    <option key={a.key} value={a.key}>
                      {a.key} ({a.name})
                    </option>
                  ))}
            </select>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Start Priv
            </span>
            <select
              value={startLevel}
              onChange={(e) => setStartLevel(e.target.value as "user" | "admin")}
              aria-label="Start Privilege"
              className="w-full px-2 py-1.5 rounded border text-xs"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Target Scope
            </span>
            <select
              value={targetMode}
              onChange={(e) => {
                setTargetMode(
                  e.target.value as "crown_jewels" | "high_criticality" | "all_assets"
                );
                setSelectedTargetKey(null);
                setSelectedPathIndex(0);
              }}
              aria-label="Target Scope"
              className="w-full px-2 py-1.5 rounded border text-xs"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              <option value="crown_jewels">crown_jewels</option>
              <option value="high_criticality">high_criticality</option>
              <option value="all_assets">all_assets</option>
            </select>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Goal Priv
            </span>
            <select
              value={goalLevel}
              onChange={(e) => setGoalLevel(e.target.value as "user" | "admin")}
              aria-label="Goal Privilege"
              className="w-full px-2 py-1.5 rounded border text-xs"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              K / Depth
            </span>
            <div className="flex gap-1">
              <input
                type="number"
                min={1}
                max={10}
                value={kPaths}
                onChange={(e) => setKPaths(Math.max(1, Math.min(10, Number(e.target.value) || 1)))}
                aria-label="K paths per target"
                title="Top K paths per target"
                className="w-1/2 px-1.5 py-1.5 rounded border text-xs mono"
                style={{
                  backgroundColor: "var(--bg-elevated)",
                  borderColor: "var(--border)",
                  color: "var(--text-main)",
                }}
              />
              <input
                type="number"
                min={1}
                max={12}
                value={maxDepth}
                onChange={(e) =>
                  setMaxDepth(Math.max(1, Math.min(12, Number(e.target.value) || 1)))
                }
                aria-label="Max search depth"
                title="Max hops depth"
                className="w-1/2 px-1.5 py-1.5 rounded border text-xs mono"
                style={{
                  backgroundColor: "var(--bg-elevated)",
                  borderColor: "var(--border)",
                  color: "var(--text-main)",
                }}
              />
            </div>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Max Expansions
            </span>
            <input
              type="number"
              min={10}
              max={5000}
              step={50}
              value={maxExpansions}
              onChange={(e) =>
                setMaxExpansions(Math.max(10, Math.min(5000, Number(e.target.value) || 100)))
              }
              aria-label="Max search expansions"
              className="w-full px-2 py-1.5 rounded border text-xs mono"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            />
          </label>
        </div>
      </div>

      {sweepQuery.isError && (
        <div
          className="mc-panel px-3 py-2 text-xs flex items-center gap-2"
          style={{ borderColor: "rgba(239, 68, 68, 0.5)", color: "var(--crit)" }}
        >
          <ShieldAlert size={15} className="shrink-0" />
          <span>
            {sweepQuery.error instanceof ApiError
              ? sweepQuery.error.detail
              : "Failed to run multi-target attack path sweep."}
          </span>
        </div>
      )}

      {sweep && sweep.targets_evaluated.length > 0 && (
        <div className="mc-panel p-3 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
              Evaluated Targets ({sweep.targets_evaluated.length})
            </span>
            {selectedTargetKey && (
              <button
                type="button"
                onClick={() => {
                  setSelectedTargetKey(null);
                  setSelectedPathIndex(0);
                }}
                className="text-xs px-2 py-0.5 rounded border flex items-center gap-1 cursor-pointer"
                style={{
                  borderColor: "var(--accent-border)",
                  backgroundColor: "var(--accent-soft)",
                  color: "var(--accent)",
                }}
              >
                <FilterX size={12} />
                <span>Show all targets ({sweep.paths.length} paths)</span>
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {sweep.targets_evaluated.map((target) => {
              const active = selectedTargetKey === target.asset_key;
              return (
                <button
                  key={target.asset_key}
                  type="button"
                  onClick={() => {
                    setSelectedTargetKey(active ? null : target.asset_key);
                    setSelectedPathIndex(0);
                    setSelectedAssetKey(null);
                  }}
                  className="text-left p-2.5 rounded border transition-colors cursor-pointer space-y-1"
                  style={{
                    borderColor: active ? "var(--accent-border)" : "var(--border)",
                    backgroundColor: active ? "var(--accent-soft)" : "var(--bg-elevated)",
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-xs truncate flex items-center gap-1" style={{ color: "var(--text-main)" }}>
                      {target.crown_jewel && (
                        <Crown size={12} style={{ color: "var(--high)" }} className="shrink-0" />
                      )}
                      {target.asset_name}
                    </span>
                    <span
                      className="mono text-xs font-bold shrink-0"
                      style={{ color: scoreColor(target.max_score) }}
                    >
                      {target.max_score.toFixed(1)}
                    </span>
                  </div>

                  <div className="mono text-[11px] truncate" style={{ color: "var(--text-dim)" }}>
                    {target.asset_key}
                    {target.zone_key ? ` · ${target.zone_key}` : ""} · crit:{target.criticality}
                  </div>

                  <div className="mono text-[11px] flex items-center justify-between" style={{ color: "var(--text-muted)" }}>
                    <span>
                      {target.path_count} {target.path_count === 1 ? "path" : "paths"}
                    </span>
                    <span>
                      {target.expansions_used} exp
                      {target.search_truncated ? " · trunc" : ""}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-0">
        <div className="xl:col-span-8 flex flex-col gap-3 min-h-0">
          <TopologyGraph
            graph={graph}
            activePath={activePath}
            selectedAssetKey={selectedAssetKey}
            onSelectAsset={(key) => setSelectedAssetKey(key)}
          />

          <div className="mc-panel flex flex-col overflow-hidden">
            <div
              className="px-3 py-2 border-b flex items-center justify-between text-xs"
              style={{ borderColor: "var(--border)" }}
            >
              <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
                Ranked Modeled Paths ({displayedPaths.length})
              </span>
              {selectedTargetKey && (
                <span className="mono text-[11px]" style={{ color: "var(--accent)" }}>
                  filtered to target: {selectedTargetKey}
                </span>
              )}
            </div>

            <div className="max-h-64 overflow-auto thin-scroll">
              <table className="w-full text-left border-collapse text-xs">
                <thead
                  className="sticky top-0 z-10 border-b text-[11px] uppercase tracking-wider"
                  style={{
                    backgroundColor: "var(--bg-elevated)",
                    borderColor: "var(--border)",
                    color: "var(--text-dim)",
                  }}
                >
                  <tr>
                    <th className="py-2 px-3">#</th>
                    <th className="py-2 px-3">Target</th>
                    <th className="py-2 px-3">Score</th>
                    <th className="py-2 px-3">Like / Conf</th>
                    <th className="py-2 px-3">Step Chain</th>
                  </tr>
                </thead>
                <tbody>
                  {sweepQuery.isLoading ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center" style={{ color: "var(--text-muted)" }}>
                        Running bounded attack path sweep…
                      </td>
                    </tr>
                  ) : displayedPaths.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center" style={{ color: "var(--text-muted)" }}>
                        0 modeled paths matched under current sweep parameters.
                      </td>
                    </tr>
                  ) : (
                    displayedPaths.map((p, idx) => {
                      const active = idx === selectedPathIndex && !selectedAssetKey;
                      const chain = p.steps.map((s) => `${s.rule_id}→${s.target_key}`).join(" | ");
                      return (
                        <tr
                          key={p.path_key}
                          onClick={() => {
                            setSelectedPathIndex(idx);
                            setSelectedAssetKey(null);
                          }}
                          className="border-b cursor-pointer transition-colors"
                          style={{
                            borderColor: "var(--border)",
                            backgroundColor: active ? "var(--accent-soft)" : "transparent",
                          }}
                        >
                          <td className="py-2 px-3 mono" style={{ color: "var(--text-dim)" }}>
                            #{idx + 1}
                          </td>
                          <td className="py-2 px-3">
                            <div className="mono font-medium" style={{ color: "var(--text-main)" }}>
                              {p.target_key}
                            </div>
                            <div className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                              {p.goal_capability}
                            </div>
                          </td>
                          <td className="py-2 px-3 mono font-bold" style={{ color: scoreColor(p.modeled_score) }}>
                            {p.modeled_score.toFixed(1)}
                          </td>
                          <td className="py-2 px-3 mono">
                            <span style={{ color: "var(--text-main)" }}>
                              {p.path_likelihood.toFixed(2)}
                            </span>{" "}
                            /{" "}
                            <span style={{ color: p.low_confidence ? "var(--high)" : "var(--text-muted)" }}>
                              {Math.round(p.path_confidence * 100)}%
                            </span>
                            {p.low_confidence && (
                              <span
                                className="ml-1 text-[10px] px-1 rounded border"
                                style={{
                                  borderColor: "rgba(251, 146, 60, 0.45)",
                                  color: "var(--high)",
                                }}
                              >
                                low-conf
                              </span>
                            )}
                          </td>
                          <td className="py-2 px-3 mono text-[11px]" style={{ color: "var(--text-muted)" }}>
                            {chain}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <aside className="xl:col-span-4 mc-panel p-3 overflow-y-auto thin-scroll max-h-[820px]">
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
              meta={meta}
              analysis={
                sweep
                  ? {
                      paths: sweep.paths,
                      search_truncated: sweep.search_truncated,
                    }
                  : null
              }
              pathsOverride={displayedPaths}
              selectedPathIndex={selectedPathIndex}
              onSelectPath={(idx) => setSelectedPathIndex(idx)}
              loading={sweepQuery.isLoading}
            />
          )}
        </aside>
      </div>
    </div>
  );
}
