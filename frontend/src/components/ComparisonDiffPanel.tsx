import type { CSSProperties, ReactNode } from "react";
import { AlertTriangle, ArrowRight } from "lucide-react";
import type { ComparisonDiffEntry, ComparisonSection } from "../api/types";

interface ComparisonDiffPanelProps {
  title: string;
  subtitle?: string;
  comparison: ComparisonSection;
  warnings?: string[];
  metaBanner?: ReactNode;
  beforeLabel?: string;
  afterLabel?: string;
  onSelectPathKey?: (pathKey: string, side: "before" | "after") => void;
}

const STATUS_STYLE: Record<string, CSSProperties> = {
  removed: {
    color: "var(--ok)",
    background: "var(--ok-bg)",
    borderColor: "rgba(34, 197, 94, 0.4)",
  },
  reduced: {
    color: "var(--ok)",
    background: "var(--ok-bg)",
    borderColor: "rgba(34, 197, 94, 0.4)",
  },
  increased: {
    color: "var(--crit)",
    background: "var(--crit-bg)",
    borderColor: "rgba(239, 68, 68, 0.45)",
  },
  new: {
    color: "var(--high)",
    background: "var(--high-bg)",
    borderColor: "rgba(251, 146, 60, 0.45)",
  },
  unchanged: {
    color: "var(--text-dim)",
    background: "var(--bg-elevated)",
    borderColor: "var(--border)",
  },
};

export function ComparisonDiffPanel({
  title,
  subtitle,
  comparison,
  warnings = [],
  metaBanner,
  beforeLabel = "Before",
  afterLabel = "After",
  onSelectPathKey,
}: ComparisonDiffPanelProps) {
  const reducedCount = comparison.remaining.filter((r) => r.status === "reduced").length;
  const increasedCount = comparison.remaining.filter((r) => r.status === "increased").length;
  const unchangedCount = comparison.remaining.filter((r) => r.status === "unchanged").length;

  const rows: { entry: ComparisonDiffEntry; side: "before" | "after" }[] = [
    ...comparison.removed.map((entry) => ({ entry, side: "before" as const })),
    ...comparison.remaining.map((entry) => ({ entry, side: "after" as const })),
    ...comparison.new.map((entry) => ({ entry, side: "after" as const })),
  ];

  const delta = comparison.score_delta;
  const deltaStr = delta === 0 ? "0" : delta > 0 ? `+${delta}` : String(delta);

  return (
    <section className="mc-panel p-3 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="mc-kicker" style={{ color: "var(--accent)" }}>
            {title}
          </h3>
          {subtitle && (
            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              {subtitle}
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs mono">
          <div className="px-2.5 py-1 mc-elevated flex items-center gap-1.5">
            <span style={{ color: "var(--text-dim)" }}>
              {beforeLabel} → {afterLabel}:
            </span>
            <span className="font-bold">{comparison.baseline_headline_score}</span>
            <ArrowRight className="w-3 h-3" />
            <span
              className="font-bold"
              style={{ color: delta < 0 ? "var(--ok)" : delta > 0 ? "var(--crit)" : "var(--text-main)" }}
            >
              {comparison.modified_headline_score}
            </span>
            <span style={{ color: delta < 0 ? "var(--ok)" : delta > 0 ? "var(--crit)" : "var(--text-dim)" }}>
              ({deltaStr})
            </span>
          </div>

          <div className="px-2.5 py-1 mc-elevated">
            <span style={{ color: "var(--text-dim)" }}>Paths: </span>
            <span>
              {comparison.baseline_path_count} → {comparison.modified_path_count}
            </span>
          </div>

          <div className="px-2.5 py-1 mc-elevated flex items-center gap-2">
            <span style={{ color: "var(--ok)" }}>{comparison.removed.length} removed</span>
            <span style={{ color: "var(--ok)" }}>{reducedCount} reduced</span>
            {increasedCount > 0 && (
              <span style={{ color: "var(--crit)" }}>{increasedCount} increased</span>
            )}
            <span style={{ color: "var(--text-dim)" }}>{unchangedCount} same</span>
            {comparison.new.length > 0 && (
              <span style={{ color: "var(--high)" }}>{comparison.new.length} new</span>
            )}
          </div>
        </div>
      </div>

      {metaBanner}

      {warnings.length > 0 && (
        <div
          className="p-2 rounded border text-xs space-y-1"
          style={{
            borderColor: "rgba(251, 146, 60, 0.45)",
            background: "var(--high-bg)",
            color: "var(--high)",
          }}
        >
          {warnings.map((w, idx) => (
            <div key={idx} className="flex items-start gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {rows.length === 0 ? (
        <div className="text-xs py-2" style={{ color: "var(--text-dim)" }}>
          Both baseline and modified analyses produced 0 modeled paths.
        </div>
      ) : (
        <div className="overflow-x-auto max-h-64 overflow-y-auto thin-scroll border rounded" style={{ borderColor: "var(--border)" }}>
          <table className="w-full text-left border-collapse text-xs">
            <thead
              className="sticky top-0 z-10 border-b text-[11px] uppercase tracking-wider"
              style={{
                background: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-dim)",
              }}
            >
              <tr>
                <th className="py-1.5 px-2.5">Status</th>
                <th className="py-1.5 px-2.5">Target</th>
                <th className="py-1.5 px-2.5">Score Δ</th>
                <th className="py-1.5 px-2.5">Modeled Path &amp; Changed Steps</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ entry, side }) => {
                const badgeStyle = STATUS_STYLE[entry.status] ?? STATUS_STYLE.unchanged;
                const d = entry.score_delta;
                return (
                  <tr
                    key={`${entry.status}:${entry.path_key}`}
                    onClick={() => onSelectPathKey?.(entry.path_key, side)}
                    className={`border-b ${onSelectPathKey ? "cursor-pointer hover:bg-white/5" : ""}`}
                    style={{ borderColor: "var(--border)" }}
                  >
                    <td className="py-2 px-2.5 align-top">
                      <span
                        className="mono inline-flex px-1.5 py-0.5 rounded border text-[11px] uppercase font-semibold"
                        style={badgeStyle}
                      >
                        {entry.status}
                      </span>
                    </td>
                    <td className="py-2 px-2.5 align-top mono font-medium">{entry.target_key}</td>
                    <td className="py-2 px-2.5 align-top mono whitespace-nowrap">
                      <span>{entry.score_before}</span> → <span>{entry.score_after}</span>{" "}
                      <span
                        style={{
                          color: d < 0 ? "var(--ok)" : d > 0 ? "var(--crit)" : "var(--text-dim)",
                        }}
                      >
                        ({d === 0 ? "0" : d > 0 ? `+${d}` : d})
                      </span>
                    </td>
                    <td className="py-2 px-2.5 align-top space-y-1">
                      <div className="mono text-[11px] break-all" style={{ color: "var(--text-main)" }}>
                        {entry.path_key}
                      </div>
                      {entry.changed_steps && entry.changed_steps.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {entry.changed_steps.map((cs) => (
                            <span
                              key={cs.step_key}
                              className="mono text-[10px] px-1.5 py-0.5 rounded border"
                              style={{
                                borderColor: "var(--border-strong)",
                                background: "var(--bg-elevated)",
                                color: "var(--text-muted)",
                              }}
                            >
                              {cs.step_key}: {cs.likelihood_before} → {cs.likelihood_after}
                              {cs.controls_after.length > 0
                                ? ` [${cs.controls_after.join(",")}]`
                                : ""}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
