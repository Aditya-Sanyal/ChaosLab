import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, FileWarning, History, Search, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import type { FindingStatusHistoryEntry, FindingUpdateRequest, UserResponse } from "../api/types";
import { SeverityBadge, StatusBadge } from "./SeverityBadge";

interface FindingsViewProps {
  envId: string;
  user: UserResponse;
}

type FindingStatusValue = "open" | "in_progress" | "accepted_risk" | "remediated" | "false_positive";

const STATUS_OPTIONS: FindingStatusValue[] = [
  "open",
  "in_progress",
  "accepted_risk",
  "remediated",
  "false_positive",
];

function overrideSlotKey(assetKey: string, port: number | null): string {
  return `${assetKey}::${port === null ? "null" : String(port)}`;
}

function formatTs(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function FindingsView({ envId, user }: FindingsViewProps) {
  const queryClient = useQueryClient();
  const canEdit = user.role !== "viewer";

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [knownCategories, setKnownCategories] = useState<string[]>([]);
  const [selectedFindingKey, setSelectedFindingKey] = useState<string | null>(null);

  const [draftStatus, setDraftStatus] = useState<FindingStatusValue>("open");
  const [draftNotes, setDraftNotes] = useState("");
  const [draftComment, setDraftComment] = useState("");
  const [draftOverrides, setDraftOverrides] = useState<Record<string, FindingStatusValue | "">>({});
  const [saveNotice, setSaveNotice] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const findingsQuery = useQuery({
    queryKey: ["findings", envId, severityFilter, statusFilter, categoryFilter, search],
    queryFn: () =>
      api.listFindings(envId, {
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        category: categoryFilter || undefined,
        search: search.trim() || undefined,
      }),
    enabled: Boolean(envId),
  });

  const findings = findingsQuery.data ?? [];

  useEffect(() => {
    setSelectedFindingKey(null);
    setKnownCategories([]);
  }, [envId]);

  useEffect(() => {
    if (findings.length === 0) return;
    setKnownCategories((prev) => {
      const next = new Set(prev);
      for (const item of findings) {
        if (item.category) next.add(item.category);
      }
      return Array.from(next).sort();
    });
  }, [findings]);

  useEffect(() => {
    if (findings.length === 0) {
      setSelectedFindingKey(null);
      return;
    }
    if (!selectedFindingKey || !findings.some((f) => f.key === selectedFindingKey)) {
      setSelectedFindingKey(findings[0].key);
    }
  }, [findings, selectedFindingKey]);

  const detailQuery = useQuery({
    queryKey: ["finding-detail", envId, selectedFindingKey],
    queryFn: () => api.getFindingDetail(envId, selectedFindingKey!),
    enabled: Boolean(envId && selectedFindingKey),
  });

  const detail = detailQuery.data ?? null;

  useEffect(() => {
    setSaveNotice(null);
    setSaveError(null);
  }, [envId, selectedFindingKey]);

  useEffect(() => {
    if (!detail) return;
    setDraftStatus(detail.status as FindingStatusValue);
    setDraftNotes(detail.remediation_notes ?? "");
    setDraftComment("");
    const nextOverrides: Record<string, FindingStatusValue | ""> = {};
    for (const item of detail.affected_assets) {
      nextOverrides[overrideSlotKey(item.asset_key, item.port)] =
        (item.status_override as FindingStatusValue | null) ?? "";
    }
    setDraftOverrides(nextOverrides);
  }, [detail]);

  const dirtyState = useMemo(() => {
    if (!detail) {
      return { isDirty: false, changedOverrides: [] as NonNullable<FindingUpdateRequest["asset_status_overrides"]> };
    }
    const statusChanged = draftStatus !== detail.status;
    const notesChanged = draftNotes !== (detail.remediation_notes ?? "");
    const commentPresent = draftComment.trim().length > 0;
    const changedOverrides: NonNullable<FindingUpdateRequest["asset_status_overrides"]> = [];
    for (const item of detail.affected_assets) {
      const slot = overrideSlotKey(item.asset_key, item.port);
      const currentVal = (item.status_override ?? "") as FindingStatusValue | "";
      const draftVal = draftOverrides[slot] ?? "";
      if (draftVal !== currentVal) {
        changedOverrides.push({
          asset_key: item.asset_key,
          port: item.port,
          status_override: draftVal === "" ? null : draftVal,
        });
      }
    }
    return {
      isDirty: statusChanged || notesChanged || commentPresent || changedOverrides.length > 0,
      changedOverrides,
    };
  }, [detail, draftStatus, draftNotes, draftComment, draftOverrides]);

  const updateMutation = useMutation({
    mutationFn: (payload: FindingUpdateRequest) =>
      api.updateFinding(envId, detail!.key, payload),
    onSuccess: (updated) => {
      setSaveError(null);
      setSaveNotice(`Saved changes for ${updated.key} and recorded audit event.`);
      setDraftComment("");
      queryClient.setQueryData(["finding-detail", envId, updated.key], updated);
      void queryClient.invalidateQueries({ queryKey: ["findings", envId] });
      void queryClient.invalidateQueries({ queryKey: ["overview", envId] });
      void queryClient.invalidateQueries({ queryKey: ["graph", envId] });
      void queryClient.invalidateQueries({ queryKey: ["asset-detail", envId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err: unknown) => {
      setSaveNotice(null);
      setSaveError(err instanceof Error ? err.message : "Failed to update finding.");
    },
  });

  function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!detail || !canEdit || !dirtyState.isDirty) return;
    const payload: FindingUpdateRequest = {};
    if (draftStatus !== detail.status) {
      payload.status = draftStatus;
    }
    if (draftNotes !== (detail.remediation_notes ?? "")) {
      payload.remediation_notes = draftNotes;
    }
    if (draftComment.trim()) {
      payload.comment = draftComment.trim();
    }
    if (dirtyState.changedOverrides.length > 0) {
      payload.asset_status_overrides = dirtyState.changedOverrides;
    }
    updateMutation.mutate(payload);
  }

  const orderedHistory: FindingStatusHistoryEntry[] = useMemo(() => {
    if (!detail?.status_history) return [];
    return [...detail.status_history].reverse();
  }, [detail?.status_history]);

  return (
    <div className="h-[calc(100vh-110px)] flex flex-col gap-3">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Findings &amp; Remediation Workflow
          </div>
          <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Inspect evidence-backed findings, manage per-asset status overrides, and log audited lifecycle transitions.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="relative">
            <Search
              size={13}
              className="absolute left-2.5 top-2"
              style={{ color: "var(--text-dim)" }}
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search key, title, CVE, CWE…"
              aria-label="Search findings"
              className="pl-7 pr-2.5 py-1 rounded border text-xs w-52"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border)",
                color: "var(--text-main)",
              }}
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filter by severity"
            className="px-2 py-1 rounded border text-xs"
            style={{
              backgroundColor: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            <option value="">All severities</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
            className="px-2 py-1 rounded border text-xs"
            style={{
              backgroundColor: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((st) => (
              <option key={st} value={st}>
                {st}
              </option>
            ))}
          </select>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            aria-label="Filter by category"
            className="px-2 py-1 rounded border text-xs"
            style={{
              backgroundColor: "var(--bg-elevated)",
              borderColor: "var(--border)",
              color: "var(--text-main)",
            }}
          >
            <option value="">All categories</option>
            {knownCategories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-7 mc-panel flex flex-col min-h-0 overflow-hidden">
          <div
            className="px-3 py-2 border-b flex items-center justify-between text-xs"
            style={{ borderColor: "var(--border)" }}
          >
            <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
              Findings Inventory ({findings.length})
            </span>
            {findingsQuery.isFetching && (
              <span className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                Refreshing…
              </span>
            )}
          </div>

          <div className="flex-1 overflow-auto thin-scroll">
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
                  <th className="py-2 px-3">Sev</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Finding</th>
                  <th className="py-2 px-3">Category</th>
                  <th className="py-2 px-3">Assets</th>
                  <th className="py-2 px-3">History</th>
                </tr>
              </thead>
              <tbody>
                {findingsQuery.isLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center" style={{ color: "var(--text-muted)" }}>
                      Loading findings…
                    </td>
                  </tr>
                ) : findings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center" style={{ color: "var(--text-muted)" }}>
                      No findings match current filters.
                    </td>
                  </tr>
                ) : (
                  findings.map((f) => {
                    const selected = f.key === selectedFindingKey;
                    const historyCount = f.status_history_count ?? 0;
                    return (
                      <tr
                        key={f.key}
                        onClick={() => setSelectedFindingKey(f.key)}
                        className="border-b cursor-pointer transition-colors"
                        style={{
                          borderColor: "var(--border)",
                          backgroundColor: selected ? "var(--accent-soft)" : "transparent",
                        }}
                      >
                        <td className="py-2.5 px-3 align-top">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="py-2.5 px-3 align-top">
                          <StatusBadge status={f.status} />
                        </td>
                        <td className="py-2.5 px-3 align-top">
                          <div className="mono text-[11px]" style={{ color: "var(--accent)" }}>
                            {f.key}
                          </div>
                          <div className="font-medium mt-0.5" style={{ color: "var(--text-main)" }}>
                            {f.title}
                          </div>
                          <div className="mono text-[11px] mt-0.5 flex flex-wrap gap-2" style={{ color: "var(--text-dim)" }}>
                            {f.cve && <span>{f.cve}</span>}
                            {f.cwe && <span>{f.cwe}</span>}
                            <span>grants:{f.grants}</span>
                            <span>ev:{f.evidence_keys.length}</span>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 align-top mono" style={{ color: "var(--text-muted)" }}>
                          {f.category}
                        </td>
                        <td className="py-2.5 px-3 align-top mono" style={{ color: "var(--text-main)" }}>
                          {f.affected_assets.length}
                        </td>
                        <td className="py-2.5 px-3 align-top mono" style={{ color: "var(--text-dim)" }}>
                          {historyCount > 0 ? `${historyCount}` : "—"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="lg:col-span-5 mc-panel p-4 overflow-y-auto thin-scroll">
          {!selectedFindingKey ? (
            <div className="h-full flex flex-col items-center justify-center text-center gap-2 text-xs" style={{ color: "var(--text-dim)" }}>
              <FileWarning size={22} />
              <span>Select a finding from the list to inspect evidence, overrides, and remediation status.</span>
            </div>
          ) : detailQuery.isLoading ? (
            <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
              Loading finding details…
            </div>
          ) : detailQuery.isError || !detail ? (
            <div className="p-4 text-xs" style={{ color: "var(--crit)" }}>
              Failed to load finding details.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="border-b pb-3 space-y-2" style={{ borderColor: "var(--border)" }}>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="mono text-xs" style={{ color: "var(--accent)" }}>
                      {detail.key}
                    </div>
                    <h2 className="text-sm font-semibold mt-0.5" style={{ color: "var(--text-main)" }}>
                      {detail.title}
                    </h2>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <SeverityBadge severity={detail.severity} />
                    <StatusBadge status={detail.status} />
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 text-[11px] mono" style={{ color: "var(--text-dim)" }}>
                  <span>category:{detail.category}</span>
                  <span>grants:{detail.grants}</span>
                  <span>auth:{detail.requires_auth ? "required" : "none"}</span>
                  {detail.exploitability !== null && (
                    <span>exploitability:{detail.exploitability.toFixed(2)}</span>
                  )}
                  {detail.cve && <span>{detail.cve}</span>}
                  {detail.cwe && <span>{detail.cwe}</span>}
                </div>

                <div className="text-[11px] mono flex flex-wrap gap-2" style={{ color: "var(--text-dim)" }}>
                  <span>origin:{detail.provenance.origin}</span>
                  <span>source:{detail.provenance.source}</span>
                  <span>confidence:{Math.round(detail.provenance.confidence * 100)}%</span>
                  {detail.provenance.observed_at && (
                    <span>observed:{formatTs(detail.provenance.observed_at)}</span>
                  )}
                </div>

                {detail.description && (
                  <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
                    {detail.description}
                  </p>
                )}
              </div>

              <div
                className="mc-elevated px-3 py-2 text-[11px] flex items-start gap-2"
                style={{ color: "var(--text-muted)" }}
              >
                <ShieldAlert size={14} className="shrink-0 mt-0.5" style={{ color: "var(--accent)" }} />
                <span>
                  Updating finding status modifies live inventory for <strong>future</strong> snapshots.
                  Existing frozen snapshots preserve their point-in-time state until a new snapshot is created.
                </span>
              </div>

              <form onSubmit={handleSave} className="space-y-3">
                <div className="mc-elevated p-3 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="mc-kicker" style={{ color: "var(--accent)" }}>
                      Status &amp; Remediation Workflow
                    </span>
                    {!canEdit && (
                      <span className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                        Read-only role ({user.role})
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    <label className="space-y-1">
                      <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                        Global Finding Status
                      </span>
                      <select
                        value={draftStatus}
                        onChange={(e) => setDraftStatus(e.target.value as FindingStatusValue)}
                        disabled={!canEdit || updateMutation.isPending}
                        aria-label="Global Finding Status"
                        className="w-full px-2 py-1.5 rounded border text-xs"
                        style={{
                          backgroundColor: "var(--bg-panel)",
                          borderColor: "var(--border)",
                          color: "var(--text-main)",
                        }}
                      >
                        {STATUS_OPTIONS.map((st) => (
                          <option key={st} value={st}>
                            {st}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="space-y-1">
                      <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                        Audit Transition Comment
                      </span>
                      <input
                        type="text"
                        value={draftComment}
                        onChange={(e) => setDraftComment(e.target.value)}
                        disabled={!canEdit || updateMutation.isPending}
                        placeholder="Reason for status or override update…"
                        aria-label="Audit Transition Comment"
                        className="w-full px-2 py-1.5 rounded border text-xs"
                        style={{
                          backgroundColor: "var(--bg-panel)",
                          borderColor: "var(--border)",
                          color: "var(--text-main)",
                        }}
                      />
                    </label>
                  </div>

                  <label className="block space-y-1 text-xs">
                    <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
                      Remediation Notes
                    </span>
                    <textarea
                      rows={3}
                      value={draftNotes}
                      onChange={(e) => setDraftNotes(e.target.value)}
                      disabled={!canEdit || updateMutation.isPending}
                      aria-label="Remediation Notes"
                      className="w-full px-2 py-1.5 rounded border text-xs"
                      style={{
                        backgroundColor: "var(--bg-panel)",
                        borderColor: "var(--border)",
                        color: "var(--text-main)",
                      }}
                    />
                  </label>
                </div>

                <div className="mc-elevated p-3 space-y-2">
                  <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>
                    Affected Assets &amp; Per-Asset Status Overrides ({detail.affected_assets.length})
                  </div>
                  <div className="space-y-1.5">
                    {detail.affected_assets.map((asset) => {
                      const slot = overrideSlotKey(asset.asset_key, asset.port);
                      const overrideVal = draftOverrides[slot] ?? "";
                      return (
                        <div
                          key={slot}
                          className="p-2 rounded border flex flex-wrap items-center justify-between gap-2 text-xs"
                          style={{
                            borderColor: "var(--border)",
                            backgroundColor: "var(--bg-panel)",
                          }}
                        >
                          <div className="min-w-0">
                            <div className="font-medium" style={{ color: "var(--text-main)" }}>
                              {asset.asset_name}
                            </div>
                            <div className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                              {asset.asset_key}
                              {asset.zone_key ? ` · zone:${asset.zone_key}` : ""}
                              {asset.port !== null ? ` · port:${asset.port}` : ""}
                            </div>
                          </div>

                          <div className="flex items-center gap-2">
                            <span className="text-[11px]" style={{ color: "var(--text-dim)" }}>
                              effective:
                            </span>
                            <StatusBadge status={asset.effective_status} />
                            <select
                              value={overrideVal}
                              onChange={(e) =>
                                setDraftOverrides((prev) => ({
                                  ...prev,
                                  [slot]: e.target.value as FindingStatusValue | "",
                                }))
                              }
                              disabled={!canEdit || updateMutation.isPending}
                              aria-label={`Status override for ${asset.asset_key}`}
                              className="px-2 py-1 rounded border text-[11px] mono"
                              style={{
                                backgroundColor: "var(--bg-elevated)",
                                borderColor: "var(--border)",
                                color: "var(--text-main)",
                              }}
                            >
                              <option value="">Inherit global</option>
                              {STATUS_OPTIONS.map((st) => (
                                <option key={st} value={st}>
                                  {st}
                                </option>
                              ))}
                            </select>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {saveError && (
                  <div
                    className="p-2 rounded border text-xs flex items-center gap-2"
                    style={{
                      borderColor: "rgba(239, 68, 68, 0.45)",
                      backgroundColor: "var(--crit-bg)",
                      color: "var(--crit)",
                    }}
                  >
                    <AlertCircle size={14} className="shrink-0" />
                    <span>{saveError}</span>
                  </div>
                )}

                {saveNotice && (
                  <div
                    className="p-2 rounded border text-xs flex items-center gap-2"
                    style={{
                      borderColor: "rgba(34, 197, 94, 0.4)",
                      backgroundColor: "var(--ok-bg)",
                      color: "var(--ok)",
                    }}
                  >
                    <CheckCircle2 size={14} className="shrink-0" />
                    <span>{saveNotice}</span>
                  </div>
                )}

                {canEdit && (
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px]" style={{ color: "var(--text-dim)" }}>
                      {dirtyState.isDirty ? "Unsaved workflow changes" : "In sync with live inventory"}
                    </span>
                    <button
                      type="submit"
                      disabled={!dirtyState.isDirty || updateMutation.isPending}
                      className="px-3 py-1.5 rounded text-xs font-medium border disabled:opacity-45 cursor-pointer"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        borderColor: "var(--accent-border)",
                        color: "var(--accent)",
                      }}
                    >
                      {updateMutation.isPending ? "Saving…" : "Save Workflow Changes"}
                    </button>
                  </div>
                )}
              </form>

              <div className="mc-elevated p-3 space-y-2">
                <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--text-dim)" }}>
                  <History size={12} />
                  <span>Status Transition History ({orderedHistory.length})</span>
                </div>
                {orderedHistory.length === 0 ? (
                  <div className="text-xs" style={{ color: "var(--text-dim)" }}>
                    No lifecycle transitions recorded yet.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {orderedHistory.map((entry, idx) => (
                      <div
                        key={`${entry.at ?? "na"}-${idx}`}
                        className="p-2 rounded border text-xs space-y-0.5"
                        style={{
                          borderColor: "var(--border)",
                          backgroundColor: "var(--bg-panel)",
                        }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="mono font-medium" style={{ color: "var(--text-main)" }}>
                            {entry.from_status} → {entry.to_status}
                          </span>
                          <span className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                            {formatTs(entry.at)}
                          </span>
                        </div>
                        <div className="text-[11px]" style={{ color: "var(--text-muted)" }}>
                          actor: <span className="mono">{entry.actor}</span>
                          {entry.comment ? ` · “${entry.comment}”` : ""}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="mc-elevated p-3 space-y-2">
                <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>
                  Supporting Evidence ({detail.evidence.length})
                </div>
                {detail.evidence.length === 0 ? (
                  <div className="text-xs" style={{ color: "var(--text-dim)" }}>
                    No evidence records linked to this finding.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {detail.evidence.map((ev) => (
                      <div
                        key={ev.key}
                        className="p-2.5 rounded border space-y-1.5 text-xs"
                        style={{
                          borderColor: "var(--border)",
                          backgroundColor: "var(--bg-panel)",
                        }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-medium" style={{ color: "var(--text-main)" }}>
                            {ev.title}
                          </span>
                          <span className="mono text-[11px]" style={{ color: "var(--accent)" }}>
                            {ev.key} ({ev.kind})
                          </span>
                        </div>
                        <div className="mono text-[11px] flex flex-wrap gap-2" style={{ color: "var(--text-dim)" }}>
                          <span>sha256:{ev.sha256.slice(0, 12)}</span>
                          <span>source:{ev.provenance.source}</span>
                          <span>confidence:{Math.round(ev.provenance.confidence * 100)}%</span>
                        </div>
                        <pre
                          className="mono text-[11px] p-2 rounded overflow-x-auto thin-scroll whitespace-pre-wrap break-all"
                          style={{
                            backgroundColor: "var(--bg-elevated)",
                            color: "var(--text-muted)",
                          }}
                        >
                          {ev.excerpt}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
