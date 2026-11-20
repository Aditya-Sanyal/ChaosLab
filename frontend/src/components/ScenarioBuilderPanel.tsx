import { useEffect, useState } from "react";
import { Crown, Play, Plus, Save, X } from "lucide-react";
import type {
  InlineScenarioInput,
  ScenarioCreateRequest,
  SnapshotDocument,
  TargetInput,
} from "../api/types";

interface ScenarioBuilderPanelProps {
  snapshotDoc: SnapshotDocument | null;
  disabled: boolean;
  running: boolean;
  saving: boolean;
  onRunInline: (inline: InlineScenarioInput) => void;
  onSaveAndRun: (payload: ScenarioCreateRequest) => void;
  onClose: () => void;
}

export function ScenarioBuilderPanel({
  snapshotDoc,
  disabled,
  running,
  saving,
  onRunInline,
  onSaveAndRun,
  onClose,
}: ScenarioBuilderPanelProps) {
  const [name, setName] = useState("Custom Attack Scenario");
  const [description, setDescription] = useState("");
  const [startKind, setStartKind] = useState<"zone" | "asset">("zone");
  const [startKey, setStartKey] = useState("internet");
  const [startLevel, setStartLevel] = useState<"user" | "admin">("user");
  const [targets, setTargets] = useState<TargetInput[]>([]);
  const [pickerAssetKey, setPickerAssetKey] = useState("");
  const [pickerLevel, setPickerLevel] = useState<"user" | "admin">("user");
  const [maxDepth, setMaxDepth] = useState(6);
  const [kPaths, setKPaths] = useState(5);
  const [maxExpansions, setMaxExpansions] = useState(20000);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    if (!snapshotDoc) return;
    if (startKind === "zone") {
      const zoneKeys = snapshotDoc.zones.map((z) => z.key);
      if (!zoneKeys.includes(startKey)) {
        setStartKey(zoneKeys.includes("internet") ? "internet" : (zoneKeys[0] ?? ""));
      }
    } else {
      const assetKeys = snapshotDoc.assets.map((a) => a.key);
      if (!assetKeys.includes(startKey)) {
        setStartKey(assetKeys[0] ?? "");
      }
    }
  }, [snapshotDoc, startKind, startKey]);

  useEffect(() => {
    if (!snapshotDoc || snapshotDoc.assets.length === 0) return;
    const validKeys = new Set(snapshotDoc.assets.map((a) => a.key));
    if (!pickerAssetKey || !validKeys.has(pickerAssetKey)) {
      const preferred =
        snapshotDoc.assets.find((a) => a.criticality >= 5) ?? snapshotDoc.assets[0];
      setPickerAssetKey(preferred.key);
    }
    if (targets.length === 0) {
      const initial =
        snapshotDoc.assets.find(
          (a) => a.criticality >= 5 || a.tags.includes("crown_jewel")
        ) ?? snapshotDoc.assets[0];
      setTargets([
        {
          asset_key: initial.key,
          level: initial.type === "identity" ? "identity" : "user",
        },
      ]);
    }
  }, [snapshotDoc, pickerAssetKey, targets.length]);

  const assetsByKey = new Map((snapshotDoc?.assets ?? []).map((a) => [a.key, a]));
  const startAsset = startKind === "asset" ? assetsByKey.get(startKey) : undefined;
  const pickerAsset = assetsByKey.get(pickerAssetKey);

  function addSingleTarget() {
    if (!pickerAsset) return;
    const level: TargetInput["level"] =
      pickerAsset.type === "identity" ? "identity" : pickerLevel;
    if (targets.some((t) => t.asset_key === pickerAsset.key && t.level === level)) {
      return;
    }
    if (targets.length >= 20) {
      setFormError("A scenario supports at most 20 targets.");
      return;
    }
    setFormError(null);
    setTargets([...targets, { asset_key: pickerAsset.key, level }]);
  }

  function addCrownJewels() {
    if (!snapshotDoc) return;
    const jewels = snapshotDoc.assets.filter(
      (a) => a.criticality >= 5 || a.tags.includes("crown_jewel")
    );
    const next = [...targets];
    for (const jewel of jewels) {
      const lvl: TargetInput["level"] = jewel.type === "identity" ? "identity" : "user";
      if (!next.some((t) => t.asset_key === jewel.key && t.level === lvl)) {
        if (next.length < 20) {
          next.push({ asset_key: jewel.key, level: lvl });
        }
      }
    }
    setFormError(null);
    setTargets(next);
  }

  function removeTarget(idx: number) {
    setTargets(targets.filter((_, i) => i !== idx));
  }

  function validateInputs(): InlineScenarioInput | null {
    const trimmed = name.trim();
    if (!trimmed) {
      setFormError("Scenario name is required.");
      return null;
    }
    if (!startKey) {
      setFormError("Select a valid start position from the snapshot.");
      return null;
    }
    if (targets.length === 0) {
      setFormError("Add at least one target asset.");
      return null;
    }
    setFormError(null);
    return {
      name: trimmed,
      start_kind: startKind,
      start_key: startKey,
      start_level: startKind === "asset" && startAsset?.type !== "identity" ? startLevel : "user",
      targets,
      max_depth: maxDepth,
      k_paths: kPaths,
      max_expansions: maxExpansions,
    };
  }

  const busy = disabled || running || saving || !snapshotDoc;

  return (
    <section className="mc-panel p-3.5 space-y-3 border" style={{ borderColor: "var(--accent-border)" }}>
      <div className="flex items-center justify-between gap-2 border-b pb-2" style={{ borderColor: "var(--border)" }}>
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Custom Scenario Builder
          </div>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Define a zone or assumed-breach starting foothold, one or more targets, and deterministic search bounds.
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1 rounded border"
          style={{ borderColor: "var(--border)", color: "var(--text-muted)" }}
          aria-label="Close scenario builder"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5 text-xs">
        <label className="space-y-1 md:col-span-2">
          <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
            Scenario Name
          </span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={busy}
            className="w-full px-2.5 py-1.5 rounded border text-xs"
            style={{
              background: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          />
        </label>

        <label className="space-y-1 md:col-span-2">
          <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
            Description (used if saved)
          </span>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={busy}
            placeholder="Optional scope or adversary assumption notes…"
            className="w-full px-2.5 py-1.5 rounded border text-xs"
            style={{
              background: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          />
        </label>

        <label className="space-y-1">
          <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
            Start Kind
          </span>
          <select
            value={startKind}
            onChange={(e) => setStartKind(e.target.value as "zone" | "asset")}
            disabled={busy}
            aria-label="Builder Start Kind"
            className="w-full px-2 py-1.5 rounded border text-xs"
            style={{
              background: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            <option value="zone">zone (perimeter / segment)</option>
            <option value="asset">asset (assumed breach)</option>
          </select>
        </label>

        <label className="space-y-1 md:col-span-2">
          <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
            Start Key
          </span>
          <select
            value={startKey}
            onChange={(e) => setStartKey(e.target.value)}
            disabled={busy}
            aria-label="Builder Start Key"
            className="w-full px-2 py-1.5 rounded border text-xs mono"
            style={{
              background: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            {startKind === "zone"
              ? (snapshotDoc?.zones ?? []).map((z) => (
                  <option key={z.key} value={z.key}>
                    {z.key} ({z.name} · {z.trust_level})
                  </option>
                ))
              : (snapshotDoc?.assets ?? []).map((a) => (
                  <option key={a.key} value={a.key}>
                    {a.key} ({a.name} · {a.type})
                  </option>
                ))}
          </select>
        </label>

        <label className="space-y-1">
          <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
            Start Privilege
          </span>
          <select
            value={startKind === "asset" && startAsset?.type !== "identity" ? startLevel : "user"}
            onChange={(e) => setStartLevel(e.target.value as "user" | "admin")}
            disabled={busy || startKind === "zone" || startAsset?.type === "identity"}
            aria-label="Builder Start Level"
            className="w-full px-2 py-1.5 rounded border text-xs disabled:opacity-50"
            style={{
              background: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </label>
      </div>

      <div className="mc-elevated p-2.5 space-y-2 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
            Targets ({targets.length}/20)
          </span>
          <button
            type="button"
            onClick={addCrownJewels}
            disabled={busy}
            className="px-2 py-1 rounded border inline-flex items-center gap-1 text-[11px]"
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--bg-panel)",
              color: "var(--high)",
            }}
          >
            <Crown className="w-3 h-3" />
            Add Crown Jewels
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={pickerAssetKey}
            onChange={(e) => setPickerAssetKey(e.target.value)}
            disabled={busy}
            aria-label="Target Asset Picker"
            className="px-2 py-1.5 rounded border text-xs mono min-w-[220px]"
            style={{
              background: "var(--bg-panel)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            {(snapshotDoc?.assets ?? []).map((a) => (
              <option key={a.key} value={a.key}>
                {a.key} ({a.name} · crit {a.criticality})
              </option>
            ))}
          </select>

          <select
            value={pickerAsset?.type === "identity" ? "identity" : pickerLevel}
            onChange={(e) => setPickerLevel(e.target.value as "user" | "admin")}
            disabled={busy || pickerAsset?.type === "identity"}
            aria-label="Target Privilege Picker"
            className="px-2 py-1.5 rounded border text-xs disabled:opacity-55"
            style={{
              background: "var(--bg-panel)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            {pickerAsset?.type === "identity" ? (
              <option value="identity">identity</option>
            ) : (
              <>
                <option value="user">user</option>
                <option value="admin">admin</option>
              </>
            )}
          </select>

          <button
            type="button"
            onClick={addSingleTarget}
            disabled={busy || !pickerAssetKey}
            className="px-2.5 py-1.5 rounded border inline-flex items-center gap-1 font-semibold"
            style={{
              borderColor: "var(--accent-border)",
              background: "var(--accent-soft)",
              color: "var(--accent)",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            Add Target
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {targets.map((t, idx) => (
            <span
              key={`${t.asset_key}:${t.level}`}
              className="mono inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px]"
              style={{
                borderColor: "var(--border-strong)",
                background: "var(--bg-panel)",
                color: "var(--text-main)",
              }}
            >
              <span>
                {t.asset_key}:{t.level}
              </span>
              <button
                type="button"
                onClick={() => removeTarget(idx)}
                disabled={busy}
                aria-label={`Remove target ${t.asset_key}`}
                style={{ color: "var(--text-dim)" }}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2.5">
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Max Depth (1–12)
            </span>
            <input
              type="number"
              min={1}
              max={12}
              value={maxDepth}
              onChange={(e) => setMaxDepth(Math.max(1, Math.min(12, Number(e.target.value) || 1)))}
              disabled={busy}
              className="w-24 px-2 py-1 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              K Paths (1–20)
            </span>
            <input
              type="number"
              min={1}
              max={20}
              value={kPaths}
              onChange={(e) => setKPaths(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
              disabled={busy}
              className="w-24 px-2 py-1 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Max Expansions (10–50000)
            </span>
            <input
              type="number"
              min={10}
              max={50000}
              step={100}
              value={maxExpansions}
              onChange={(e) =>
                setMaxExpansions(Math.max(10, Math.min(50000, Number(e.target.value) || 10)))
              }
              disabled={busy}
              className="w-32 px-2 py-1 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              const parsed = validateInputs();
              if (parsed) onRunInline(parsed);
            }}
            className="px-3 py-1.5 rounded border font-semibold inline-flex items-center gap-1.5 disabled:opacity-45"
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--bg-elevated)",
              color: "var(--text-main)",
            }}
          >
            <Play className="w-3.5 h-3.5" />
            {running ? "Running…" : "Run Ad-Hoc"}
          </button>

          <button
            type="button"
            disabled={busy}
            onClick={() => {
              const parsed = validateInputs();
              if (parsed) {
                onSaveAndRun({
                  ...parsed,
                  description: description.trim(),
                });
              }
            }}
            className="px-3 py-1.5 rounded font-bold inline-flex items-center gap-1.5 disabled:opacity-45"
            style={{
              background: "var(--accent)",
              color: "var(--accent-fg)",
            }}
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? "Saving…" : "Save & Run"}
          </button>
        </div>
      </div>

      {formError && (
        <div className="text-xs" style={{ color: "var(--crit)" }}>
          {formError}
        </div>
      )}
    </section>
  );
}
