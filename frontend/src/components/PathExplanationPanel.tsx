import { AlertTriangle } from "lucide-react";
import type { AnalysisSection, ModeledPath } from "../api/types";

export interface PathResultMeta {
  resultKind: string;
  disclaimer: string;
  engineVersion: string;
  rulesetVersion: string;
  snapshotSha256: string;
  resultSha256: string;
  globalAssumptions: string[];
}

interface PathExplanationPanelProps {
  meta: PathResultMeta | null;
  analysis: Pick<AnalysisSection, "paths" | "search_truncated"> | null;
  pathsOverride?: ModeledPath[];
  selectedPathIndex: number;
  onSelectPath: (index: number) => void;
  loading: boolean;
}

export function PathExplanationPanel({
  meta,
  analysis,
  pathsOverride,
  selectedPathIndex,
  onSelectPath,
  loading,
}: PathExplanationPanelProps) {
  if (loading) {
    return (
      <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
        Running deterministic offline path simulation…
      </div>
    );
  }

  if (!meta || !analysis) {
    return (
      <div className="p-4 text-xs space-y-2" style={{ color: "var(--text-muted)" }}>
        <div className="mc-kicker" style={{ color: "var(--accent)" }}>
          Scenario Result Drawer
        </div>
        <p>Select a scenario and run an offline simulation to inspect modeled paths, prerequisites, evidence, and uncertainty.</p>
      </div>
    );
  }

  const paths = pathsOverride ?? analysis.paths;
  const activeIdx = selectedPathIndex < paths.length ? selectedPathIndex : 0;
  const activePath = paths[activeIdx] ?? null;

  if (!activePath) {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--border)" }}>
          <span className="mc-kicker" style={{ color: "var(--ok)" }}>
            Modeled Result · 0 modeled paths
          </span>
          <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: "var(--ok-bg)", color: "var(--ok)" }}>
            SCORE 0 / 100
          </span>
        </div>

        <div className="p-3 mc-elevated text-xs space-y-2">
          <div className="font-semibold" style={{ color: "var(--ok)" }}>
            No modeled attack paths reach the selected target(s) in this snapshot.
          </div>
          <p style={{ color: "var(--text-muted)" }}>
            Note: No modeled path does not prove zero risk. Unmodeled weaknesses, missing data, or out-of-snapshot changes are not evaluated.
          </p>
        </div>

        <div className="p-2.5 mc-elevated text-xs mono space-y-0.5" style={{ color: "var(--text-dim)" }}>
          <div>snapshot_sha256: {meta.snapshotSha256.slice(0, 16)}…</div>
          <div>result_sha256: {meta.resultSha256.slice(0, 16)}…</div>
        </div>

        <div className="p-2 border rounded text-xs" style={{ borderColor: "var(--border)", background: "var(--bg-app)", color: "var(--text-dim)" }}>
          {meta.disclaimer}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-2.5" style={{ borderColor: "var(--border)" }}>
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Modeled path {activeIdx + 1} of {paths.length} · {meta.resultKind.replace(/_/g, " ")}
          </div>
          <div className="text-xs font-semibold mt-0.5 mono">
            Target: {activePath.goal_capability}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {paths.map((item, idx) => {
            const active = idx === activeIdx;
            return (
              <button
                key={item.path_key}
                type="button"
                onClick={() => onSelectPath(idx)}
                className="text-xs px-2 py-1 border rounded font-semibold mono transition"
                style={{
                  background: active ? "var(--accent-soft)" : "var(--bg-elevated)",
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  borderColor: active ? "var(--accent-border)" : "var(--border)",
                }}
              >
                P{idx + 1} · {item.modeled_score}/100
              </button>
            );
          })}
        </div>
      </div>

      {analysis.search_truncated && (
        <div
          className="p-2 text-xs border rounded flex items-center gap-2"
          style={{
            background: "var(--med-bg)",
            color: "var(--med)",
            borderColor: "rgba(253, 224, 71, 0.45)",
          }}
        >
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Search expansion limit hit; additional modeled paths may exist.</span>
        </div>
      )}

      <div className="grid grid-cols-3 gap-2">
        <div className="p-2 mc-elevated">
          <div className="text-xs" style={{ color: "var(--text-dim)" }}>
            Modeled score
          </div>
          <div className="text-base font-bold mono" style={{ color: "var(--accent)" }}>
            {activePath.modeled_score} / 100
          </div>
          <div className="text-xs" style={{ color: "var(--text-dim)" }}>
            heuristic
          </div>
        </div>
        <div className="p-2 mc-elevated">
          <div className="text-xs" style={{ color: "var(--text-dim)" }}>
            Likelihood
          </div>
          <div className="text-base font-bold mono">{activePath.path_likelihood.toFixed(3)}</div>
          <div className="text-xs mono" style={{ color: "var(--text-dim)" }}>
            w={activePath.weighted_likelihood.toFixed(3)}
          </div>
        </div>
        <div className="p-2 mc-elevated">
          <div className="text-xs" style={{ color: "var(--text-dim)" }}>
            Min confidence
          </div>
          <div
            className="text-base font-bold mono"
            style={{ color: activePath.low_confidence ? "var(--med)" : "var(--ok)" }}
          >
            {activePath.path_confidence.toFixed(2)}
          </div>
          <div className="text-xs" style={{ color: activePath.low_confidence ? "var(--med)" : "var(--text-dim)" }}>
            {activePath.low_confidence ? "LOW CONFIDENCE" : "adequate"}
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Ordered Step Trace ({activePath.steps.length})
        </div>
        {activePath.steps.map((step, idx) => (
          <div key={step.step_key} className="p-2.5 mc-elevated space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className="inline-flex items-center justify-center w-5 h-5 text-xs font-bold mono rounded-full shrink-0"
                  style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
                >
                  {idx + 1}
                </span>
                <span className="mono text-xs font-bold">{step.rule_id}</span>
                <span className="text-xs font-semibold mono truncate">
                  {step.from_position.replace(/^(zone|asset):/, "")} → {step.target_key}
                </span>
              </div>
            </div>

            <div className="text-xs" style={{ color: "var(--text-muted)" }}>
              {step.rule_name} ·{" "}
              <span className="mono">
                {step.reference_labels.join(", ")} (reference label)
              </span>
            </div>

            <div className="grid grid-cols-3 gap-1.5 text-xs mono pt-0.5">
              <div className="px-1.5 py-1 border rounded" style={{ borderColor: "var(--border)" }}>
                <div style={{ color: "var(--text-dim)" }}>Likelihood</div>
                <div className="font-bold">
                  {step.likelihood.toFixed(2)}
                  {step.likelihood !== step.base_likelihood && (
                    <span style={{ color: "var(--ok)" }}> (base {step.base_likelihood.toFixed(2)})</span>
                  )}
                </div>
              </div>
              <div className="px-1.5 py-1 border rounded" style={{ borderColor: "var(--border)" }}>
                <div style={{ color: "var(--text-dim)" }}>Confidence</div>
                <div
                  className="font-bold"
                  style={{ color: step.confidence < 0.5 ? "var(--med)" : "var(--text-main)" }}
                >
                  {step.confidence.toFixed(2)}
                </div>
              </div>
              <div className="px-1.5 py-1 border rounded" style={{ borderColor: "var(--border)" }}>
                <div style={{ color: "var(--text-dim)" }}>Evidence</div>
                <div className="font-bold truncate" title={step.evidence_keys.join(", ")}>
                  {step.evidence_keys.length ? step.evidence_keys.join(", ") : "—"}
                </div>
              </div>
            </div>

            <div className="text-xs" style={{ color: "var(--text-muted)" }}>
              <span style={{ color: "var(--text-dim)" }}>Prereqs:</span>{" "}
              <span className="mono">{step.prerequisites.map((p) => p.key).join(" · ")}</span>
            </div>

            {step.controls_applied.length > 0 && (
              <div className="text-xs mono" style={{ color: "var(--ok)" }}>
                Controls: {step.controls_applied.map((c) => `${c.key} (×${c.factor})`).join(", ")}
              </div>
            )}

            {step.assumptions.length > 0 && (
              <div className="text-xs space-y-0.5" style={{ color: "var(--text-dim)" }}>
                {step.assumptions.map((a) => (
                  <div key={a}>• {a}</div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="p-2.5 mc-elevated text-xs space-y-1">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Global Model Assumptions
        </div>
        <ul className="list-disc pl-4 space-y-0.5" style={{ color: "var(--text-dim)" }}>
          {meta.globalAssumptions.map((a) => (
            <li key={a}>{a}</li>
          ))}
        </ul>
      </div>

      <div className="p-2 mc-elevated text-xs mono space-y-0.5" style={{ color: "var(--text-dim)" }}>
        <div>engine={meta.engineVersion} · ruleset={meta.rulesetVersion}</div>
        <div>snapshot_sha256={meta.snapshotSha256.slice(0, 16)}…</div>
        <div>result_sha256={meta.resultSha256.slice(0, 16)}…</div>
      </div>

      <div
        className="p-2 border rounded text-xs"
        style={{ borderColor: "var(--border)", background: "var(--bg-app)", color: "var(--text-dim)" }}
      >
        {meta.disclaimer}
      </div>
    </div>
  );
}
