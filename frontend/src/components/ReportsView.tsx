import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Download, FileCode2, FileText, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { UserResponse } from "../api/types";

interface ReportsViewProps {
  envId: string;
  user: UserResponse;
}

export function ReportsView({ envId, user }: ReportsViewProps) {
  const queryClient = useQueryClient();
  const canExport = user.role === "analyst" || user.role === "admin";

  const [selectedRunId, setSelectedRunId] = useState<string>("");
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const runsQuery = useQuery({
    queryKey: ["runs", envId, "reports"],
    queryFn: () => api.listRuns(envId, { limit: 50 }),
    enabled: Boolean(envId),
  });

  const runs = runsQuery.data ?? [];

  useEffect(() => {
    setSelectedRunId("");
    setExportMessage(null);
    setExportError(null);
  }, [envId]);

  useEffect(() => {
    if (runs.length === 0) {
      setSelectedRunId("");
      return;
    }
    if (!selectedRunId || !runs.some((r) => r.id === selectedRunId)) {
      setSelectedRunId(runs[0].id);
    }
  }, [runs, selectedRunId]);

  const previewQuery = useQuery({
    queryKey: ["report-preview", selectedRunId],
    queryFn: () => api.getRunReportPreview(selectedRunId),
    enabled: Boolean(selectedRunId),
  });

  const exportMutation = useMutation({
    mutationFn: (fmt: "html" | "markdown") => api.exportRunReport(selectedRunId, fmt),
    onSuccess: ({ blob, filename, reportSha256 }) => {
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      setExportError(null);
      setExportMessage(
        `Exported ${filename}${
          reportSha256 ? ` (sha256:${reportSha256.slice(0, 12)}…)` : ""
        } and logged to Audit Trail.`
      );
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setExportMessage(null);
      setExportError(err instanceof ApiError ? err.detail : "Report export failed.");
    },
  });

  const preview = previewQuery.data ?? null;

  return (
    <div className="h-[calc(100vh-110px)] flex flex-col gap-3">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Scenario Reports &amp; Audited Exports
          </div>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Generated dynamically from immutable snapshots and scenario runs. Reports are never stored server-side; exports are recorded in the audit trail.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!canExport && (
            <span className="text-xs mono" style={{ color: "var(--text-dim)" }}>
              Read-only Viewer role · Export requires Analyst/Admin
            </span>
          )}
          <button
            type="button"
            disabled={!canExport || !selectedRunId || exportMutation.isPending}
            onClick={() => exportMutation.mutate("markdown")}
            className="px-3 py-1.5 rounded border text-xs font-semibold inline-flex items-center gap-1.5 disabled:opacity-45"
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--bg-elevated)",
              color: "var(--text-main)",
            }}
          >
            <Download className="w-3.5 h-3.5" />
            Export Markdown
          </button>

          <button
            type="button"
            disabled={!canExport || !selectedRunId || exportMutation.isPending}
            onClick={() => exportMutation.mutate("html")}
            className="px-3 py-1.5 rounded text-xs font-bold inline-flex items-center gap-1.5 disabled:opacity-45"
            style={{
              background: "var(--accent)",
              color: "var(--accent-fg)",
            }}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            Export Escaped HTML
          </button>
        </div>
      </div>

      {exportMessage && (
        <div
          className="p-2.5 text-xs border rounded flex items-center gap-2"
          style={{
            borderColor: "rgba(34, 197, 94, 0.45)",
            background: "var(--ok-bg)",
            color: "var(--ok)",
          }}
        >
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span className="mono">{exportMessage}</span>
        </div>
      )}

      {exportError && (
        <div
          className="p-2.5 text-xs border rounded flex items-center gap-2"
          style={{
            borderColor: "rgba(239, 68, 68, 0.45)",
            background: "var(--crit-bg)",
            color: "var(--crit)",
          }}
        >
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{exportError}</span>
        </div>
      )}

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-4 mc-panel flex flex-col min-h-0 overflow-hidden">
          <div
            className="px-3 py-2 border-b text-xs flex items-center justify-between"
            style={{ borderColor: "var(--border)" }}
          >
            <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
              Scenario Runs ({runs.length})
            </span>
          </div>
          <div className="flex-1 overflow-y-auto thin-scroll divide-y" style={{ borderColor: "var(--border)" }}>
            {runsQuery.isLoading ? (
              <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
                Loading scenario runs…
              </div>
            ) : runs.length === 0 ? (
              <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
                No recorded scenario runs yet. Run a scenario in Scenario Lab first.
              </div>
            ) : (
              runs.map((r) => {
                const selected = r.id === selectedRunId;
                const baseScore = r.result.baseline.headline_score;
                const modScore = r.result.modified?.headline_score;
                return (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => {
                      setSelectedRunId(r.id);
                      setExportMessage(null);
                      setExportError(null);
                    }}
                    className="w-full text-left p-3 transition-colors space-y-1 cursor-pointer"
                    style={{
                      background: selected ? "var(--accent-soft)" : "transparent",
                    }}
                  >
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-semibold truncate" style={{ color: "var(--text-main)" }}>
                        {r.result.scenario.name}
                      </span>
                      <span className="mono font-bold shrink-0" style={{ color: "var(--accent)" }}>
                        {modScore !== undefined ? `${baseScore} → ${modScore}` : `${baseScore}`}/100
                      </span>
                    </div>
                    <div className="mono text-[11px] flex flex-wrap gap-2" style={{ color: "var(--text-dim)" }}>
                      <span>run:{r.id.slice(0, 8)}</span>
                      <span>snap:{r.result.snapshot_sha256.slice(0, 8)}</span>
                      <span>actions:{r.actions.length}</span>
                    </div>
                    <div className="mono text-[11px]" style={{ color: "var(--text-muted)" }}>
                      {r.created_by}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="lg:col-span-8 mc-panel p-4 flex flex-col min-h-0 overflow-hidden gap-3">
          {!selectedRunId ? (
            <div className="h-full flex flex-col items-center justify-center gap-2 text-xs" style={{ color: "var(--text-dim)" }}>
              <FileText className="w-6 h-6" />
              <span>Select a scenario run to preview and export its offline report.</span>
            </div>
          ) : previewQuery.isLoading ? (
            <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
              Rendering report preview…
            </div>
          ) : previewQuery.isError || !preview ? (
            <div className="p-4 text-xs" style={{ color: "var(--crit)" }}>
              Failed to load report preview.
            </div>
          ) : (
            <>
              <div
                className="p-2.5 rounded border text-xs flex items-start gap-2 shrink-0"
                style={{
                  borderColor: "rgba(34, 197, 94, 0.35)",
                  background: "var(--ok-bg)",
                  color: "var(--ok)",
                }}
              >
                <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
                <span>
                  <strong>{preview.result_kind}</strong>: {preview.disclaimer}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs mono shrink-0">
                <div className="mc-elevated p-2">
                  <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                    Snapshot
                  </div>
                  <div className="truncate" style={{ color: "var(--text-main)" }}>
                    {preview.snapshot_label}
                  </div>
                  <div className="text-[11px]" style={{ color: "var(--text-dim)" }}>
                    {preview.snapshot_sha256.slice(0, 14)}…
                  </div>
                </div>
                <div className="mc-elevated p-2">
                  <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                    Result SHA-256
                  </div>
                  <div className="truncate" style={{ color: "var(--accent)" }}>
                    {preview.result_sha256.slice(0, 22)}…
                  </div>
                </div>
                <div className="mc-elevated p-2">
                  <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                    Evidence Referenced
                  </div>
                  <div style={{ color: "var(--text-main)" }}>{preview.evidence_count} item(s)</div>
                </div>
              </div>

              <div className="flex-1 min-h-0 overflow-auto thin-scroll border rounded p-3" style={{ borderColor: "var(--border)", background: "var(--bg-elevated)" }}>
                <pre
                  className="mono text-xs whitespace-pre-wrap break-words leading-relaxed"
                  style={{ color: "var(--text-main)" }}
                >
                  {preview.markdown}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
