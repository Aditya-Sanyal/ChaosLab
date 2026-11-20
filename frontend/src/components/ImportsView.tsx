import { useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Download, FileUp, ShieldAlert, Upload } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { ImportReportResponse, UserResponse } from "../api/types";

interface ImportsViewProps {
  envId: string;
  user: UserResponse;
}

type ImportFmt = "json" | "csv" | "nmap_xml";

const CSV_ENTITIES = [
  "zones",
  "assets",
  "services",
  "relationships",
  "reachability",
  "findings",
  "controls",
  "evidence",
] as const;

export function ImportsView({ envId, user }: ImportsViewProps) {
  const queryClient = useQueryClient();
  const isViewer = user.role === "viewer";

  const [fmt, setFmt] = useState<ImportFmt>("json");
  const [entityType, setEntityType] = useState<string>("assets");
  const [vantageZone, setVantageZone] = useState<string>("internet");
  const [targetZone, setTargetZone] = useState<string>("dmz");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [report, setReport] = useState<ImportReportResponse | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [validatedHash, setValidatedHash] = useState<string | null>(null);

  const batchesQuery = useQuery({
    queryKey: ["imports", envId],
    queryFn: () => api.listImports(envId),
    enabled: Boolean(envId),
  });

  const graphQuery = useQuery({
    queryKey: ["graph", envId],
    queryFn: () => api.getTopologyGraph(envId),
    enabled: Boolean(envId),
  });

  function buildFormData(file: File): FormData {
    const fd = new FormData();
    fd.append("format", fmt);
    if (fmt === "csv") fd.append("entity_type", entityType);
    if (fmt === "nmap_xml") {
      fd.append("vantage_zone_key", vantageZone);
      fd.append("target_zone_key", targetZone);
    }
    fd.append("file", file);
    return fd;
  }

  const validateMutation = useMutation({
    mutationFn: (file: File) => api.validateImport(envId, buildFormData(file)),
    onSuccess: (res) => {
      setActionError(null);
      setReport(res);
      setValidatedHash(res.status === "validated" ? res.sha256 : null);
      void queryClient.invalidateQueries({ queryKey: ["imports", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setValidatedHash(null);
      setActionError(err instanceof ApiError ? err.detail : "Validation failed.");
    },
  });

  const commitMutation = useMutation({
    mutationFn: (file: File) => api.commitImport(envId, buildFormData(file)),
    onSuccess: (res) => {
      setActionError(null);
      setReport(res);
      setValidatedHash(null);
      void queryClient.invalidateQueries({ queryKey: ["imports", envId] });
      void queryClient.invalidateQueries({ queryKey: ["overview", envId] });
      void queryClient.invalidateQueries({ queryKey: ["assets", envId] });
      void queryClient.invalidateQueries({ queryKey: ["graph", envId] });
      void queryClient.invalidateQueries({ queryKey: ["findings", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      if (err instanceof ApiError && err.data && typeof err.data === "object" && "errors" in err.data) {
        setReport(err.data as ImportReportResponse);
        setActionError(err.detail);
      } else {
        setActionError(err instanceof ApiError ? err.detail : "Commit failed.");
      }
      void queryClient.invalidateQueries({ queryKey: ["imports", envId] });
    },
  });

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0] ?? null;
    setSelectedFile(file);
    setReport(null);
    setValidatedHash(null);
    setActionError(null);
  }

  const zones = graphQuery.data?.zones ?? [];
  const canCommit =
    !isViewer &&
    selectedFile !== null &&
    report !== null &&
    report.status === "validated" &&
    validatedHash === report.sha256 &&
    report.errors.length === 0;

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="mc-kicker" style={{ color: "var(--accent)" }}>
            Inventory Imports &amp; Safe Exports
          </h1>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Upload JSON bundles, CSV tables, or existing Nmap XML (-oX) scans. Max 10 MB / 50,000 rows; secrets and archives rejected.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <a
            href={`/api/environments/${envId}/export/json`}
            download
            className="px-2.5 py-1.5 text-xs font-semibold mc-elevated inline-flex items-center gap-1.5"
            style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
          >
            <Download className="w-3.5 h-3.5" style={{ color: "var(--accent)" }} />
            Export JSON Bundle
          </a>
          <a
            href={`/api/environments/${envId}/export/csv?entity=assets`}
            download
            className="px-2.5 py-1.5 text-xs font-semibold mc-elevated inline-flex items-center gap-1.5"
            style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
          >
            <Download className="w-3.5 h-3.5" style={{ color: "var(--accent)" }} />
            Export Assets CSV
          </a>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-0">
        <section className="xl:col-span-7 mc-panel p-3 space-y-3 overflow-y-auto thin-scroll">
          <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--border)" }}>
            <h2 className="mc-kicker" style={{ color: "var(--text-muted)" }}>
              Step 1 · Validate (Dry-Run) → Step 2 · Commit
            </h2>
            {isViewer && (
              <span className="text-xs mono px-2 py-0.5 rounded" style={{ background: "var(--med-bg)", color: "var(--med)" }}>
                Read-only Viewer role
              </span>
            )}
          </div>

          <div className="grid grid-cols-3 gap-2">
            {(
              [
                { id: "json", label: "JSON Bundle", hint: "Full snapshot-compatible schema" },
                { id: "csv", label: "CSV Table", hint: "Single entity table (; lists)" },
                { id: "nmap_xml", label: "Nmap XML (-oX)", hint: "Offline scan file import" },
              ] as const
            ).map((opt) => {
              const active = fmt === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    setFmt(opt.id);
                    setReport(null);
                    setValidatedHash(null);
                    setActionError(null);
                  }}
                  className="p-2 text-left border rounded transition"
                  style={{
                    background: active ? "var(--accent-soft)" : "var(--bg-elevated)",
                    borderColor: active ? "var(--accent-border)" : "var(--border)",
                  }}
                >
                  <div className="text-xs font-bold" style={{ color: active ? "var(--accent)" : "var(--text-main)" }}>
                    {opt.label}
                  </div>
                  <div className="text-xs mt-0.5" style={{ color: "var(--text-dim)" }}>
                    {opt.hint}
                  </div>
                </button>
              );
            })}
          </div>

          {fmt === "csv" && (
            <div className="p-2.5 mc-elevated flex flex-wrap items-center gap-3 text-xs">
              <label htmlFor="csv-entity-select" className="mc-kicker" style={{ color: "var(--text-muted)" }}>
                CSV Entity Type
              </label>
              <select
                id="csv-entity-select"
                value={entityType}
                onChange={(e) => {
                  setEntityType(e.target.value);
                  setReport(null);
                  setValidatedHash(null);
                }}
                className="px-2.5 py-1 text-xs mc-elevated mono"
                style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
              >
                {CSV_ENTITIES.map((ent) => (
                  <option key={ent} value={ent}>
                    {ent}
                  </option>
                ))}
              </select>
            </div>
          )}

          {fmt === "nmap_xml" && (
            <div className="p-2.5 mc-elevated space-y-2 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div className="space-y-1">
                  <label htmlFor="nmap-vantage" className="block mc-kicker" style={{ color: "var(--text-muted)" }}>
                    Scan Vantage Zone
                  </label>
                  <input
                    id="nmap-vantage"
                    list="env-zones-list"
                    value={vantageZone}
                    onChange={(e) => setVantageZone(e.target.value)}
                    className="w-full px-2.5 py-1 mono text-xs mc-elevated"
                    style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="nmap-target-zone" className="block mc-kicker" style={{ color: "var(--text-muted)" }}>
                    Target Asset Zone
                  </label>
                  <input
                    id="nmap-target-zone"
                    list="env-zones-list"
                    value={targetZone}
                    onChange={(e) => setTargetZone(e.target.value)}
                    className="w-full px-2.5 py-1 mono text-xs mc-elevated"
                    style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
                  />
                </div>
              </div>
              <datalist id="env-zones-list">
                {zones.map((z) => (
                  <option key={z.key} value={z.key}>
                    {z.name}
                  </option>
                ))}
              </datalist>
              <p style={{ color: "var(--text-dim)" }}>
                Parses existing Nmap XML with <span className="mono">defusedxml</span> (entities/external DTDs blocked). Never runs Nmap or contacts hosts.
              </p>
            </div>
          )}

          <div className="p-3 mc-elevated space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label className="inline-flex items-center gap-2 text-xs font-semibold cursor-pointer">
                <FileUp className="w-4 h-4" style={{ color: "var(--accent)" }} />
                <span>Choose UTF-8 file (.json, .csv, .xml)</span>
                <input
                  type="file"
                  accept=".json,.csv,.xml,text/csv,application/json,text/xml,application/xml"
                  onChange={handleFileChange}
                  disabled={isViewer}
                  className="text-xs file:mr-2 file:py-1 file:px-2.5 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-amber-500 file:text-slate-950"
                />
              </label>
              {selectedFile && (
                <span className="mono text-xs" style={{ color: "var(--text-muted)" }}>
                  {(selectedFile.size / 1024).toFixed(1)} KB
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isViewer || !selectedFile || validateMutation.isPending || commitMutation.isPending}
                onClick={() => selectedFile && validateMutation.mutate(selectedFile)}
                className="px-3 py-1.5 text-xs font-bold uppercase tracking-wider rounded border disabled:opacity-45"
                style={{
                  background: "var(--bg-panel)",
                  color: "var(--accent)",
                  borderColor: "var(--accent-border)",
                }}
              >
                {validateMutation.isPending ? "Validating…" : "1. Validate (Dry-Run)"}
              </button>

              <button
                type="button"
                disabled={!canCommit || commitMutation.isPending}
                onClick={() => selectedFile && commitMutation.mutate(selectedFile)}
                className="px-3 py-1.5 text-xs font-bold uppercase tracking-wider rounded inline-flex items-center gap-1.5 disabled:opacity-45"
                style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
              >
                <Upload className="w-3.5 h-3.5" />
                {commitMutation.isPending ? "Committing…" : "2. Commit Upsert"}
              </button>
            </div>
          </div>

          {actionError && (
            <div
              className="p-2.5 text-xs border rounded flex items-center gap-2"
              style={{
                background: "var(--crit-bg)",
                color: "var(--crit)",
                borderColor: "rgba(239, 68, 68, 0.45)",
              }}
            >
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{actionError}</span>
            </div>
          )}

          {report && (
            <div className="p-3 mc-elevated space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs font-bold">
                  {report.status === "rejected" ? (
                    <ShieldAlert className="w-4 h-4" style={{ color: "var(--crit)" }} />
                  ) : (
                    <CheckCircle2 className="w-4 h-4" style={{ color: "var(--ok)" }} />
                  )}
                  <span className="uppercase mono">Status: {report.status}</span>
                </div>
                <span className="mono text-xs" style={{ color: "var(--text-dim)" }}>
                  batch {report.batch_id.slice(0, 8)} · sha256 {report.sha256.slice(0, 12)}…
                </span>
              </div>

              {Object.keys(report.counts).length > 0 && (
                <div className="flex flex-wrap gap-2 text-xs mono">
                  {Object.entries(report.counts).map(([ent, c]) => (
                    <span
                      key={ent}
                      className="px-2 py-0.5 border rounded"
                      style={{ borderColor: "var(--border)", color: "var(--text-main)" }}
                    >
                      {ent}: +{c.created} / ~{c.updated}
                    </span>
                  ))}
                </div>
              )}

              {report.warnings.length > 0 && (
                <div className="space-y-1 text-xs" style={{ color: "var(--med)" }}>
                  <div className="mc-kicker">Warnings ({report.warnings.length})</div>
                  {report.warnings.map((w, idx) => (
                    <div key={`${w.code}-${idx}`} className="mono">
                      [{w.entity}{w.row ? `:${w.row}` : ""}] {w.message}
                    </div>
                  ))}
                </div>
              )}

              {report.errors.length > 0 && (
                <div className="space-y-1.5">
                  <div className="mc-kicker" style={{ color: "var(--crit)" }}>
                    Validation Errors ({report.errors.length})
                  </div>
                  <div className="max-h-56 overflow-y-auto thin-scroll border rounded" style={{ borderColor: "var(--border)" }}>
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b mc-kicker" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
                          <th className="p-2">Entity</th>
                          <th className="p-2">Row</th>
                          <th className="p-2">Field</th>
                          <th className="p-2">Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.errors.map((err, idx) => (
                          <tr key={`${err.code}-${idx}`} className="border-b" style={{ borderColor: "var(--border)" }}>
                            <td className="p-2 mono">{err.entity}</td>
                            <td className="p-2 mono">{err.row ?? "—"}</td>
                            <td className="p-2 mono" style={{ color: "var(--accent)" }}>{err.field ?? "—"}</td>
                            <td className="p-2" style={{ color: "var(--crit)" }}>{err.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>

        <aside className="xl:col-span-5 mc-panel p-3 overflow-auto thin-scroll">
          <h2 className="mc-kicker mb-2" style={{ color: "var(--text-muted)" }}>
            Import Batch Log ({(batchesQuery.data ?? []).length})
          </h2>
          {(batchesQuery.data ?? []).length === 0 ? (
            <div className="text-xs py-4" style={{ color: "var(--text-dim)" }}>
              No import batches recorded yet. Validate a JSON, CSV, or Nmap XML file on the left.
            </div>
          ) : (
            <div className="space-y-2">
              {(batchesQuery.data ?? []).map((b) => (
                <div key={b.id} className="p-2.5 mc-elevated text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono font-bold truncate">{b.filename}</span>
                    <span
                      className="mono px-1.5 py-0.5 rounded uppercase font-bold"
                      style={{
                        background: b.status === "committed" ? "var(--ok-bg)" : b.status === "rejected" ? "var(--crit-bg)" : "var(--accent-soft)",
                        color: b.status === "committed" ? "var(--ok)" : b.status === "rejected" ? "var(--crit)" : "var(--accent)",
                      }}
                    >
                      {b.status}
                    </span>
                  </div>
                  <div className="mono" style={{ color: "var(--text-muted)" }}>
                    {b.format} · {(b.size_bytes / 1024).toFixed(1)} KB · {b.error_count} error(s)
                  </div>
                  <div className="mono" style={{ color: "var(--text-dim)" }}>
                    sha256 {b.sha256.slice(0, 14)}… · {b.created_by}
                  </div>
                </div>
              ))}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
