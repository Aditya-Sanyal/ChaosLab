import { useEffect, useMemo, useState } from "react";
import { Plus, RotateCcw, X } from "lucide-react";
import type { DefensiveActionInput, ScenarioRunResponse, SnapshotDocument } from "../api/types";

export interface PresetDefensiveAction {
  id: string;
  label: string;
  summary: string;
  action: DefensiveActionInput;
}

export const MERIDIAN_DEFENSIVE_PRESETS: PresetDefensiveAction[] = [
  {
    id: "D1",
    label: "D1 · Remediate F-005 on app-01",
    summary: "Marks unsafe deserialization (F-005) remediated.",
    action: { kind: "remediate_finding", params: { finding_key: "F-005" } },
  },
  {
    id: "D2",
    label: "D2 · Remove zone flow RR-04",
    summary: "Drops reachability rule RR-04 (DMZ → App :8080).",
    action: { kind: "remove_reachability", params: { reachability_key: "RR-04" } },
  },
  {
    id: "D3",
    label: "D3 · Activate WAF CTRL-01",
    summary: "Activates CTRL-01 (×0.50 factor on R-EXP-REMOTE :443).",
    action: { kind: "activate_control", params: { control_key: "CTRL-01" } },
  },
];

const ALL_RULE_IDS = [
  "R-EXP-REMOTE",
  "R-EXP-LOCAL",
  "R-CRED-USE",
  "R-CRED-HARVEST",
  "R-IDENTITY-ACCESS",
];

type ActionKind = DefensiveActionInput["kind"];

interface DefensiveActionsBarProps {
  snapshotDoc: SnapshotDocument | null;
  actions: DefensiveActionInput[];
  onApplyActions: (next: DefensiveActionInput[]) => void;
  run: ScenarioRunResponse | null;
  disabled: boolean;
  running: boolean;
}

function sameAction(a: DefensiveActionInput, b: DefensiveActionInput): boolean {
  return a.kind === b.kind && JSON.stringify(a.params) === JSON.stringify(b.params);
}

function formatActionSummary(action: DefensiveActionInput): string {
  const p = action.params;
  switch (action.kind) {
    case "remediate_finding":
      return p.asset_key
        ? `Remediate ${String(p.finding_key)} on ${String(p.asset_key)}`
        : `Remediate ${String(p.finding_key)}`;
    case "remove_reachability":
      return `Drop flow ${String(p.reachability_key)}`;
    case "remove_relationship":
      return `Drop link ${String(p.relationship_key)}`;
    case "set_zone_isolation":
      return `Zone ${String(p.zone_key)} = ${String(p.intra_zone_policy ?? "deny")}`;
    case "activate_control":
      return `Activate ${String(p.control_key)}`;
    case "add_control":
      return `Add ${String(p.key)} on ${String(p.asset_key)} (×${String(p.factor)})`;
    default:
      return action.kind;
  }
}

export function DefensiveActionsBar({
  snapshotDoc,
  actions,
  onApplyActions,
  run,
  disabled,
  running,
}: DefensiveActionsBarProps) {
  const [kind, setKind] = useState<ActionKind>("remediate_finding");
  const [findingKey, setFindingKey] = useState("");
  const [findingAssetKey, setFindingAssetKey] = useState("");
  const [reachKey, setReachKey] = useState("");
  const [relKey, setRelKey] = useState("");
  const [zoneKey, setZoneKey] = useState("");
  const [zonePolicy, setZonePolicy] = useState<"deny" | "allow">("deny");
  const [ctrlKey, setCtrlKey] = useState("");

  const [newCtrlKey, setNewCtrlKey] = useState("CTRL-CUSTOM-1");
  const [newCtrlName, setNewCtrlName] = useState("Modeled Preventive Control");
  const [newCtrlType, setNewCtrlType] = useState("waf");
  const [newCtrlAssetKey, setNewCtrlAssetKey] = useState("");
  const [newCtrlRules, setNewCtrlRules] = useState<string[]>(["R-EXP-REMOTE"]);
  const [newCtrlPorts, setNewCtrlPorts] = useState("");
  const [newCtrlFactor, setNewCtrlFactor] = useState<string>("0.2");
  const [composerError, setComposerError] = useState<string | null>(null);

  useEffect(() => {
    if (!snapshotDoc) return;
    if (snapshotDoc.findings.length > 0 && !snapshotDoc.findings.some((f) => f.key === findingKey)) {
      setFindingKey(snapshotDoc.findings[0].key);
      setFindingAssetKey("");
    }
    if (
      snapshotDoc.reachability.length > 0 &&
      !snapshotDoc.reachability.some((r) => r.key === reachKey)
    ) {
      setReachKey(snapshotDoc.reachability[0].key);
    }
    if (
      snapshotDoc.relationships.length > 0 &&
      !snapshotDoc.relationships.some((r) => r.key === relKey)
    ) {
      setRelKey(snapshotDoc.relationships[0].key);
    }
    if (snapshotDoc.zones.length > 0 && !snapshotDoc.zones.some((z) => z.key === zoneKey)) {
      setZoneKey(snapshotDoc.zones[0].key);
    }
    if (snapshotDoc.controls.length > 0 && !snapshotDoc.controls.some((c) => c.key === ctrlKey)) {
      setCtrlKey(snapshotDoc.controls[0].key);
    }
    if (
      snapshotDoc.assets.length > 0 &&
      !snapshotDoc.assets.some((a) => a.key === newCtrlAssetKey)
    ) {
      setNewCtrlAssetKey(snapshotDoc.assets[0].key);
    }
  }, [snapshotDoc, findingKey, reachKey, relKey, zoneKey, ctrlKey, newCtrlAssetKey]);

  const availablePresets = useMemo(() => {
    if (!snapshotDoc) return [];
    const findingSet = new Set(snapshotDoc.findings.map((f) => f.key));
    const reachSet = new Set(snapshotDoc.reachability.map((r) => r.key));
    const ctrlSet = new Set(snapshotDoc.controls.map((c) => c.key));
    return MERIDIAN_DEFENSIVE_PRESETS.filter((p) => {
      if (p.action.kind === "remediate_finding") {
        return findingSet.has(String(p.action.params.finding_key));
      }
      if (p.action.kind === "remove_reachability") {
        return reachSet.has(String(p.action.params.reachability_key));
      }
      if (p.action.kind === "activate_control") {
        return ctrlSet.has(String(p.action.params.control_key));
      }
      return false;
    });
  }, [snapshotDoc]);

  const selectedFinding = snapshotDoc?.findings.find((f) => f.key === findingKey);
  const affectedAssetKeys = Array.from(
    new Set((selectedFinding?.affected_assets ?? []).map((fa) => fa.asset_key))
  );

  function togglePreset(preset: PresetDefensiveAction) {
    const exists = actions.some((a) => sameAction(a, preset.action));
    const next = exists
      ? actions.filter((a) => !sameAction(a, preset.action))
      : [...actions, preset.action];
    onApplyActions(next);
  }

  function handleQueueAction() {
    setComposerError(null);
    let candidate: DefensiveActionInput;

    if (kind === "remediate_finding") {
      if (!findingKey) {
        setComposerError("No finding selected.");
        return;
      }
      candidate = {
        kind,
        params: {
          finding_key: findingKey,
          ...(findingAssetKey ? { asset_key: findingAssetKey } : {}),
        },
      };
    } else if (kind === "remove_reachability") {
      if (!reachKey) {
        setComposerError("No reachability rule selected.");
        return;
      }
      candidate = { kind, params: { reachability_key: reachKey } };
    } else if (kind === "remove_relationship") {
      if (!relKey) {
        setComposerError("No relationship selected.");
        return;
      }
      candidate = { kind, params: { relationship_key: relKey } };
    } else if (kind === "set_zone_isolation") {
      if (!zoneKey) {
        setComposerError("No zone selected.");
        return;
      }
      candidate = { kind, params: { zone_key: zoneKey, intra_zone_policy: zonePolicy } };
    } else if (kind === "activate_control") {
      if (!ctrlKey) {
        setComposerError("No control selected.");
        return;
      }
      candidate = { kind, params: { control_key: ctrlKey } };
    } else {
      const k = newCtrlKey.trim();
      if (!k) {
        setComposerError("Control key is required.");
        return;
      }
      if (!newCtrlAssetKey) {
        setComposerError("Select a target asset for the modeled control.");
        return;
      }
      if (newCtrlRules.length === 0) {
        setComposerError("Select at least one rule ID that the control affects.");
        return;
      }
      const factorNum = Number(newCtrlFactor);
      if (Number.isNaN(factorNum) || factorNum < 0 || factorNum > 1) {
        setComposerError("Factor must be a number between 0.0 and 1.0.");
        return;
      }
      const parsedPorts: number[] = [];
      if (newCtrlPorts.trim()) {
        for (const token of newCtrlPorts.split(",")) {
          const p = Number(token.trim());
          if (!Number.isInteger(p) || p < 1 || p > 65535) {
            setComposerError(`Invalid port '${token.trim()}' (must be 1–65535).`);
            return;
          }
          parsedPorts.push(p);
        }
      }
      candidate = {
        kind: "add_control",
        params: {
          key: k,
          name: newCtrlName.trim() || k,
          type: newCtrlType.trim() || "other",
          asset_key: newCtrlAssetKey,
          affects_rules: newCtrlRules,
          ports: parsedPorts,
          factor: factorNum,
        },
      };
    }

    const next = [...actions, candidate];
    onApplyActions(next);
  }

  const comparison = run?.result.comparison;
  const baselineScore =
    comparison?.baseline_headline_score ?? run?.result.baseline.headline_score ?? 0;
  const afterScore = comparison
    ? comparison.modified_headline_score
    : run?.result.baseline.headline_score ?? 0;
  const delta = afterScore - baselineScore;
  const beforePaths = comparison?.baseline_path_count ?? run?.result.baseline.total_paths ?? 0;
  const afterPaths = comparison
    ? comparison.modified_path_count
    : run?.result.baseline.total_paths ?? 0;

  return (
    <section className="mc-panel p-3 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="mc-kicker" style={{ color: "var(--accent)" }}>
            Defensive Action Comparison (What-If Simulation)
          </h2>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            {disabled
              ? "Read-only Viewer role cannot execute new what-if runs."
              : "Compose or toggle proposed mitigations against an in-memory copy of the snapshot."}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {run && (
            <div className="px-3 py-1 mc-elevated text-xs flex items-center gap-2">
              <span style={{ color: "var(--text-dim)" }}>Headline:</span>
              <span className="mono font-bold">{baselineScore}</span>
              <span>→</span>
              <span
                className="mono font-bold"
                style={{
                  color:
                    afterScore === 0
                      ? "var(--ok)"
                      : delta < 0
                        ? "var(--ok)"
                        : delta > 0
                          ? "var(--crit)"
                          : "var(--accent)",
                }}
              >
                {afterScore}
              </span>
              <span
                className="mono"
                style={{
                  color: delta < 0 ? "var(--ok)" : delta > 0 ? "var(--crit)" : "var(--text-muted)",
                }}
              >
                ({delta === 0 ? "no change" : delta > 0 ? `+${delta}` : delta})
              </span>
              <span className="mono" style={{ color: "var(--text-dim)" }}>
                · Paths {beforePaths} → {afterPaths}
              </span>
            </div>
          )}

          <button
            type="button"
            disabled={disabled || running || actions.length === 0}
            onClick={() => onApplyActions([])}
            className="px-2.5 py-1 text-xs mc-elevated inline-flex items-center gap-1 disabled:opacity-40"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <RotateCcw className="w-3 h-3" />
            Reset
          </button>
        </div>
      </div>

      {availablePresets.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {availablePresets.map((preset) => {
            const checked = actions.some((a) => sameAction(a, preset.action));
            return (
              <label
                key={preset.id}
                className={`p-2 border rounded flex items-start gap-2 transition ${
                  disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"
                }`}
                style={{
                  background: checked ? "var(--accent-soft)" : "var(--bg-elevated)",
                  borderColor: checked ? "var(--accent-border)" : "var(--border)",
                }}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={disabled || running}
                  onChange={() => togglePreset(preset)}
                  className="mt-0.5 accent-amber-500"
                />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-semibold">{preset.label}</div>
                  <p className="text-[11px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                    {preset.summary}
                  </p>
                </div>
              </label>
            );
          })}
        </div>
      )}

      <div className="mc-elevated p-2.5 space-y-2 text-xs">
        <div className="flex flex-wrap items-end gap-2">
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Action Type
            </span>
            <select
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as ActionKind);
                setComposerError(null);
              }}
              disabled={disabled || running || !snapshotDoc}
              aria-label="Defensive action type"
              className="px-2 py-1.5 rounded border text-xs"
              style={{
                background: "var(--bg-panel)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            >
              <option value="remediate_finding">Remediate finding</option>
              <option value="remove_reachability">Remove reachability rule</option>
              <option value="remove_relationship">Remove relationship</option>
              <option value="set_zone_isolation">Set zone isolation</option>
              <option value="activate_control">Activate existing control</option>
              <option value="add_control">Add new modeled control</option>
            </select>
          </label>

          {kind === "remediate_finding" && (
            <>
              <label className="space-y-1 flex-1 min-w-[200px]">
                <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                  Finding
                </span>
                <select
                  value={findingKey}
                  onChange={(e) => {
                    setFindingKey(e.target.value);
                    setFindingAssetKey("");
                  }}
                  disabled={disabled || running}
                  aria-label="Finding to remediate"
                  className="w-full px-2 py-1.5 rounded border text-xs mono"
                  style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
                >
                  {(snapshotDoc?.findings ?? []).map((f) => (
                    <option key={f.key} value={f.key}>
                      {f.key}: {f.title} [{f.status}]
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                  Asset Scope
                </span>
                <select
                  value={findingAssetKey}
                  onChange={(e) => setFindingAssetKey(e.target.value)}
                  disabled={disabled || running}
                  aria-label="Finding asset scope"
                  className="px-2 py-1.5 rounded border text-xs mono"
                  style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
                >
                  <option value="">All affected assets</option>
                  {affectedAssetKeys.map((akey) => (
                    <option key={akey} value={akey}>
                      {akey} only
                    </option>
                  ))}
                </select>
              </label>
            </>
          )}

          {kind === "remove_reachability" && (
            <label className="space-y-1 flex-1 min-w-[260px]">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Reachability Rule
              </span>
              <select
                value={reachKey}
                onChange={(e) => setReachKey(e.target.value)}
                disabled={disabled || running}
                aria-label="Reachability rule to remove"
                className="w-full px-2 py-1.5 rounded border text-xs mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              >
                {(snapshotDoc?.reachability ?? []).map((r) => (
                  <option key={r.key} value={r.key}>
                    {r.key}: {r.source_key} → {r.target_key}{" "}
                    {r.ports.length > 0 ? `[${r.ports.join(",")}]` : "[any]"}
                  </option>
                ))}
              </select>
            </label>
          )}

          {kind === "remove_relationship" && (
            <label className="space-y-1 flex-1 min-w-[260px]">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Relationship
              </span>
              <select
                value={relKey}
                onChange={(e) => setRelKey(e.target.value)}
                disabled={disabled || running}
                aria-label="Relationship to remove"
                className="w-full px-2 py-1.5 rounded border text-xs mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              >
                {(snapshotDoc?.relationships ?? []).map((r) => (
                  <option key={r.key} value={r.key}>
                    {r.key}: {r.source_asset_key} —[{r.type}]→ {r.target_asset_key}
                  </option>
                ))}
              </select>
            </label>
          )}

          {kind === "set_zone_isolation" && (
            <>
              <label className="space-y-1 min-w-[200px]">
                <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                  Zone
                </span>
                <select
                  value={zoneKey}
                  onChange={(e) => setZoneKey(e.target.value)}
                  disabled={disabled || running}
                  aria-label="Zone to isolate"
                  className="w-full px-2 py-1.5 rounded border text-xs mono"
                  style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
                >
                  {(snapshotDoc?.zones ?? []).map((z) => (
                    <option key={z.key} value={z.key}>
                      {z.key} ({z.name} · now:{z.intra_zone_policy})
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                  Intra-Zone Policy
                </span>
                <select
                  value={zonePolicy}
                  onChange={(e) => setZonePolicy(e.target.value as "deny" | "allow")}
                  disabled={disabled || running}
                  aria-label="Intra-zone policy"
                  className="px-2 py-1.5 rounded border text-xs"
                  style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
                >
                  <option value="deny">deny (isolate east-west)</option>
                  <option value="allow">allow</option>
                </select>
              </label>
            </>
          )}

          {kind === "activate_control" && (
            <label className="space-y-1 flex-1 min-w-[240px]">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Existing Control
              </span>
              <select
                value={ctrlKey}
                onChange={(e) => setCtrlKey(e.target.value)}
                disabled={disabled || running}
                aria-label="Control to activate"
                className="w-full px-2 py-1.5 rounded border text-xs mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              >
                {(snapshotDoc?.controls ?? []).map((c) => (
                  <option key={c.key} value={c.key}>
                    {c.key}: {c.name} ({c.asset_key} · {c.status} · ×{c.factor})
                  </option>
                ))}
              </select>
            </label>
          )}

          <button
            type="button"
            disabled={disabled || running || !snapshotDoc}
            onClick={handleQueueAction}
            className="px-3 py-1.5 rounded border font-semibold inline-flex items-center gap-1 disabled:opacity-45"
            style={{
              borderColor: "var(--accent-border)",
              background: "var(--accent-soft)",
              color: "var(--accent)",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            Apply Action
          </button>
        </div>

        {kind === "add_control" && (
          <div className="pt-2 border-t grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2" style={{ borderColor: "var(--border)" }}>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Control Key
              </span>
              <input
                type="text"
                value={newCtrlKey}
                onChange={(e) => setNewCtrlKey(e.target.value)}
                disabled={disabled || running}
                className="w-full px-2 py-1 rounded border mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              />
            </label>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Name
              </span>
              <input
                type="text"
                value={newCtrlName}
                onChange={(e) => setNewCtrlName(e.target.value)}
                disabled={disabled || running}
                className="w-full px-2 py-1 rounded border"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              />
            </label>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Type
              </span>
              <select
                value={newCtrlType}
                onChange={(e) => setNewCtrlType(e.target.value)}
                disabled={disabled || running}
                className="w-full px-2 py-1 rounded border"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              >
                <option value="waf">waf</option>
                <option value="mfa">mfa</option>
                <option value="edr">edr</option>
                <option value="segmentation">segmentation</option>
                <option value="patch">patch</option>
                <option value="other">other</option>
              </select>
            </label>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Target Asset
              </span>
              <select
                value={newCtrlAssetKey}
                onChange={(e) => setNewCtrlAssetKey(e.target.value)}
                disabled={disabled || running}
                className="w-full px-2 py-1 rounded border mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              >
                {(snapshotDoc?.assets ?? []).map((a) => (
                  <option key={a.key} value={a.key}>
                    {a.key}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Ports (comma-sep, blank=all)
              </span>
              <input
                type="text"
                value={newCtrlPorts}
                onChange={(e) => setNewCtrlPorts(e.target.value)}
                placeholder="e.g. 443, 8080"
                disabled={disabled || running}
                className="w-full px-2 py-1 rounded border mono"
                style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
              />
            </label>
            <label className="space-y-1">
              <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                Factor (0=block .. 1=none)
              </span>
              <div className="flex gap-1">
                <input
                  type="number"
                  step="0.05"
                  min={0}
                  max={1}
                  value={newCtrlFactor}
                  onChange={(e) => setNewCtrlFactor(e.target.value)}
                  disabled={disabled || running}
                  className="w-20 px-2 py-1 rounded border mono"
                  style={{ background: "var(--bg-panel)", borderColor: "var(--border)" }}
                />
                <button
                  type="button"
                  onClick={() => setNewCtrlFactor("0")}
                  disabled={disabled || running}
                  className="px-1.5 py-1 rounded border text-[10px] mono"
                  style={{ borderColor: "var(--border)", color: "var(--ok)" }}
                >
                  0.0 Block
                </button>
              </div>
            </label>

            <div className="sm:col-span-2 lg:col-span-6 flex flex-wrap items-center gap-3 pt-1">
              <span className="text-[11px]" style={{ color: "var(--text-dim)" }}>
                Affects rules:
              </span>
              {ALL_RULE_IDS.map((ruleId) => {
                const checked = newCtrlRules.includes(ruleId);
                return (
                  <label key={ruleId} className="inline-flex items-center gap-1 mono text-[11px]">
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={disabled || running}
                      onChange={() =>
                        setNewCtrlRules((prev) =>
                          checked ? prev.filter((r) => r !== ruleId) : [...prev, ruleId]
                        )
                      }
                      className="accent-amber-500"
                    />
                    {ruleId}
                  </label>
                );
              })}
            </div>
          </div>
        )}

        {composerError && (
          <div className="text-xs" style={{ color: "var(--crit)" }}>
            {composerError}
          </div>
        )}
      </div>

      {actions.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-[11px] uppercase tracking-wider" style={{ color: "var(--text-dim)" }}>
            Active What-If Stack ({actions.length}):
          </span>
          {actions.map((action, idx) => (
            <span
              key={`${action.kind}-${idx}`}
              className="mono inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px]"
              style={{
                borderColor: "var(--accent-border)",
                background: "var(--accent-soft)",
                color: "var(--accent)",
              }}
            >
              <span>{formatActionSummary(action)}</span>
              <button
                type="button"
                disabled={disabled || running}
                onClick={() => onApplyActions(actions.filter((_, i) => i !== idx))}
                aria-label={`Remove defensive action ${idx + 1}`}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
