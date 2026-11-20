import type { CSSProperties } from "react";

const SEV_STYLES: Record<string, CSSProperties> = {
  critical: { color: "var(--crit)", backgroundColor: "var(--crit-bg)", borderColor: "rgba(239, 68, 68, 0.45)" },
  high: { color: "var(--high)", backgroundColor: "var(--high-bg)", borderColor: "rgba(251, 146, 60, 0.45)" },
  medium: { color: "var(--med)", backgroundColor: "var(--med-bg)", borderColor: "rgba(253, 224, 71, 0.45)" },
  low: { color: "var(--low)", backgroundColor: "var(--low-bg)", borderColor: "rgba(56, 189, 248, 0.45)" },
  info: { color: "var(--text-muted)", backgroundColor: "var(--bg-elevated)", borderColor: "var(--border)" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEV_STYLES[severity] ?? SEV_STYLES.info;
  return (
    <span
      className="mono inline-flex items-center px-1.5 py-0.5 text-xs font-bold uppercase border rounded"
      style={style}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const isClean = status === "remediated" || status === "false_positive" || status === "active";
  const style: CSSProperties = isClean
    ? { color: "var(--ok)", backgroundColor: "var(--ok-bg)", borderColor: "rgba(34, 197, 94, 0.4)" }
    : {
        color: "var(--text-muted)",
        backgroundColor: "var(--bg-elevated)",
        borderColor: "var(--border-strong)",
      };
  return (
    <span className="mono inline-flex items-center px-1.5 py-0.5 text-xs border rounded" style={style}>
      {status}
    </span>
  );
}
