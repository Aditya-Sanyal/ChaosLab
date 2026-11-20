import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ChevronDown, ChevronRight, RotateCcw, Search, ShieldAlert } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { AuditVerifyResponse, UserResponse } from "../api/types";

interface AuditViewProps {
  user: UserResponse;
}

const SUBJECT_TYPES = [
  "",
  "user",
  "environment",
  "import_batch",
  "finding",
  "snapshot",
  "scenario",
  "scenario_run",
  "retention",
];

const PAGE_LIMIT = 50;

export function AuditView({ user }: AuditViewProps) {
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [subjectTypeFilter, setSubjectTypeFilter] = useState("");
  const [sinceInput, setSinceInput] = useState("");
  const [untilInput, setUntilInput] = useState("");
  const [offset, setOffset] = useState(0);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const sinceIso = sinceInput ? new Date(sinceInput).toISOString() : undefined;
  const untilIso = untilInput ? new Date(untilInput).toISOString() : undefined;

  const auditQuery = useQuery({
    queryKey: [
      "audit",
      actionFilter,
      actorFilter,
      subjectTypeFilter,
      sinceIso,
      untilIso,
      search,
      offset,
    ],
    queryFn: () =>
      api.listAudit({
        action: actionFilter.trim() || undefined,
        actor: actorFilter.trim() || undefined,
        subject_type: subjectTypeFilter || undefined,
        since: sinceIso,
        until: untilIso,
        search: search.trim() || undefined,
        limit: PAGE_LIMIT,
        offset,
      }),
  });

  async function handleVerify() {
    setVerifying(true);
    setVerifyError(null);
    try {
      const res = await api.verifyAudit();
      setVerifyResult(res);
    } catch (err) {
      setVerifyError(err instanceof ApiError ? err.detail : "Verification failed.");
    } finally {
      setVerifying(false);
    }
  }

  function resetFilters() {
    setSearch("");
    setActionFilter("");
    setActorFilter("");
    setSubjectTypeFilter("");
    setSinceInput("");
    setUntilInput("");
    setOffset(0);
    setExpandedSeq(null);
  }

  const total = auditQuery.data?.total ?? 0;
  const items = auditQuery.data?.items ?? [];

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel p-3 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="mc-kicker" style={{ color: "var(--accent)" }}>
              Append-Only Hash-Chained Audit Trail
            </h2>
            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              Immutable trail across logins, imports, findings updates, snapshots, scenario runs, reports, retention, and admin events ({total} matching events).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={resetFilters}
              className="px-2.5 py-1.5 text-xs mc-elevated inline-flex items-center gap-1"
              style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset
            </button>

            {user.role === "admin" ? (
              <button
                type="button"
                onClick={handleVerify}
                disabled={verifying}
                className="px-3 py-1.5 text-xs font-bold uppercase tracking-wider rounded disabled:opacity-50"
                style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
              >
                {verifying ? "Verifying…" : "Verify Hash Chain"}
              </button>
            ) : (
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>
                Chain verification requires Admin role
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2 text-xs">
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Search
            </span>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2 top-2" style={{ color: "var(--text-dim)" }} />
              <input
                type="text"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setOffset(0);
                }}
                placeholder="action, actor, subject…"
                className="w-full pl-7 pr-2 py-1.5 rounded border"
                style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
              />
            </div>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Exact Action
            </span>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setOffset(0);
              }}
              placeholder="e.g. report.exported"
              className="w-full px-2 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Actor Email
            </span>
            <input
              type="text"
              value={actorFilter}
              onChange={(e) => {
                setActorFilter(e.target.value);
                setOffset(0);
              }}
              placeholder="e.g. admin@"
              className="w-full px-2 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Subject Type
            </span>
            <select
              value={subjectTypeFilter}
              onChange={(e) => {
                setSubjectTypeFilter(e.target.value);
                setOffset(0);
              }}
              aria-label="Filter by subject type"
              className="w-full px-2 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            >
              {SUBJECT_TYPES.map((st) => (
                <option key={st || "all"} value={st}>
                  {st || "All subjects"}
                </option>
              ))}
            </select>
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Since (local)
            </span>
            <input
              type="datetime-local"
              value={sinceInput}
              onChange={(e) => {
                setSinceInput(e.target.value);
                setOffset(0);
              }}
              aria-label="Filter since timestamp"
              className="w-full px-2 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>

          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Until (local)
            </span>
            <input
              type="datetime-local"
              value={untilInput}
              onChange={(e) => {
                setUntilInput(e.target.value);
                setOffset(0);
              }}
              aria-label="Filter until timestamp"
              className="w-full px-2 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
        </div>
      </div>

      {verifyResult && (
        <div
          className="p-2.5 text-xs border rounded flex items-center gap-2"
          style={{
            background: verifyResult.valid ? "var(--ok-bg)" : "var(--crit-bg)",
            color: verifyResult.valid ? "var(--ok)" : "var(--crit)",
            borderColor: verifyResult.valid ? "rgba(34, 197, 94, 0.45)" : "rgba(239, 68, 68, 0.45)",
          }}
        >
          {verifyResult.valid ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <ShieldAlert className="w-4 h-4 shrink-0" />
          )}
          <span className="mono">
            {verifyResult.valid
              ? `Audit hash chain verified intact across ${verifyResult.checked_count} event(s).`
              : `Audit chain broken at seq #${verifyResult.first_broken_seq}!`}
          </span>
        </div>
      )}

      {verifyError && (
        <div className="p-2.5 text-xs border rounded" style={{ background: "var(--crit-bg)", color: "var(--crit)" }}>
          {verifyError}
        </div>
      )}

      <div className="mc-panel overflow-auto thin-scroll flex-1">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b mc-kicker" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
              <th className="p-2.5 w-8"></th>
              <th className="p-2.5">Seq</th>
              <th className="p-2.5">UTC Timestamp</th>
              <th className="p-2.5">Actor</th>
              <th className="p-2.5">Action</th>
              <th className="p-2.5">Subject</th>
              <th className="p-2.5">Chain Hash</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-6 text-center" style={{ color: "var(--text-muted)" }}>
                  No audit events match current filters.
                </td>
              </tr>
            ) : (
              items.map((ev) => {
                const expanded = expandedSeq === ev.seq;
                return (
                  <Fragment key={ev.seq}>
                    <tr
                      onClick={() => setExpandedSeq(expanded ? null : ev.seq)}
                      className="border-b cursor-pointer hover:bg-white/5"
                      style={{ borderColor: "var(--border)" }}
                    >
                      <td className="p-2.5" style={{ color: "var(--text-dim)" }}>
                        {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </td>
                      <td className="p-2.5 mono font-bold">#{ev.seq}</td>
                      <td className="p-2.5 mono" style={{ color: "var(--text-muted)" }}>
                        {ev.at}
                      </td>
                      <td className="p-2.5 mono">{ev.actor_email ?? "system"}</td>
                      <td className="p-2.5 mono font-semibold" style={{ color: "var(--accent)" }}>
                        {ev.action}
                      </td>
                      <td className="p-2.5 mono" style={{ color: "var(--text-muted)" }}>
                        {ev.subject_type}:{ev.subject_id.slice(0, 16)}
                      </td>
                      <td className="p-2.5 mono" style={{ color: "var(--text-dim)" }}>
                        {ev.hash.slice(0, 16)}…
                      </td>
                    </tr>
                    {expanded && (
                      <tr className="border-b" style={{ borderColor: "var(--border)", background: "var(--bg-elevated)" }}>
                        <td colSpan={7} className="p-3 space-y-1.5 text-xs mono">
                          <div className="flex flex-wrap gap-4 text-[11px]" style={{ color: "var(--text-muted)" }}>
                            <span>subject_id: {ev.subject_id}</span>
                            <span>actor_user_id: {ev.actor_user_id ?? "—"}</span>
                            <span>prev_hash: {ev.prev_hash}</span>
                            <span>hash: {ev.hash}</span>
                          </div>
                          <pre
                            className="p-2 rounded border text-[11px] overflow-x-auto thin-scroll"
                            style={{ background: "var(--bg-panel)", borderColor: "var(--border)", color: "var(--text-main)" }}
                          >
                            {JSON.stringify(ev.details, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="mc-panel px-3 py-2 flex items-center justify-between text-xs mono" style={{ color: "var(--text-muted)" }}>
        <span>
          Showing {total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE_LIMIT, total)} of {total}
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}
            className="px-2.5 py-1 rounded border disabled:opacity-40"
            style={{ borderColor: "var(--border-strong)", background: "var(--bg-elevated)" }}
          >
            Prev
          </button>
          <button
            type="button"
            disabled={offset + PAGE_LIMIT >= total}
            onClick={() => setOffset(offset + PAGE_LIMIT)}
            className="px-2.5 py-1 rounded border disabled:opacity-40"
            style={{ borderColor: "var(--border-strong)", background: "var(--bg-elevated)" }}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
