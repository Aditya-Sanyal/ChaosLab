import { ArrowLeft } from "lucide-react";
import type { AssetDetailResponse } from "../api/types";
import { SeverityBadge, StatusBadge } from "./SeverityBadge";

interface AssetDetailPanelProps {
  asset: AssetDetailResponse | null;
  loading: boolean;
  error: string | null;
  onBackToPath?: () => void;
}

export function AssetDetailPanel({
  asset,
  loading,
  error,
  onBackToPath,
}: AssetDetailPanelProps) {
  if (loading) {
    return (
      <div className="p-4 text-xs" style={{ color: "var(--text-muted)" }}>
        Loading asset telemetry &amp; provenance…
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-4 text-xs" style={{ color: "var(--crit)" }}>
        {error}
      </div>
    );
  }
  if (!asset) {
    return (
      <div className="p-4 text-xs" style={{ color: "var(--text-dim)" }}>
        Select an asset to inspect ownership, provenance, relationships, findings, and evidence.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-2 border-b pb-2.5" style={{ borderColor: "var(--border)" }}>
        <div>
          <div className="mc-kicker" style={{ color: "var(--accent)" }}>
            Asset Telemetry &amp; Provenance
          </div>
          <div className="text-sm font-bold mono mt-0.5">
            {asset.key} — {asset.name}
          </div>
        </div>
        {onBackToPath && (
          <button
            type="button"
            onClick={onBackToPath}
            className="px-2.5 py-1 text-xs font-semibold mc-elevated inline-flex items-center gap-1 shrink-0"
            style={{ borderColor: "var(--accent-border)", color: "var(--accent)" }}
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to path
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="p-2 mc-elevated">
          <div style={{ color: "var(--text-dim)" }}>Zone / Type</div>
          <div className="font-semibold mt-0.5">
            {asset.zone_name ?? "Non-zoned"} · <span className="mono">{asset.type}</span>
          </div>
        </div>
        <div className="p-2 mc-elevated">
          <div style={{ color: "var(--text-dim)" }}>Criticality</div>
          <div className="font-semibold mt-0.5 mono">
            {asset.criticality} / 5{" "}
            {asset.crown_jewel && <span style={{ color: "var(--crown)" }}>· ◆ Crown jewel</span>}
          </div>
        </div>
        <div className="p-2 mc-elevated">
          <div style={{ color: "var(--text-dim)" }}>Owner</div>
          <div className="font-semibold mt-0.5">{asset.owner}</div>
        </div>
        <div className="p-2 mc-elevated">
          <div style={{ color: "var(--text-dim)" }}>Network / Exposure</div>
          <div className="font-semibold mt-0.5 mono">
            {asset.ip_addresses.length ? asset.ip_addresses.join(", ") : "—"}
            {asset.internet_exposed && (
              <span className="ml-1.5 px-1 py-0.5 rounded" style={{ background: "var(--high-bg)", color: "var(--high)" }}>
                EXT
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="p-2.5 mc-elevated text-xs space-y-1">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Provenance Record
        </div>
        <div className="mono" style={{ color: "var(--text-muted)" }}>
          origin={asset.provenance.origin} · confidence={asset.provenance.confidence.toFixed(2)}
        </div>
        <div className="mono" style={{ color: "var(--text-muted)" }}>
          source={asset.provenance.source}
        </div>
        <div className="mono" style={{ color: "var(--text-dim)" }}>
          observed_at={asset.provenance.observed_at ?? "—"}
        </div>
        <div className="mono" style={{ color: "var(--text-dim)" }}>
          updated_at={asset.provenance.updated_at ?? "—"} · by={asset.provenance.updated_by ?? "—"}
        </div>
        {asset.provenance.import_batch_id && (
          <div className="mono" style={{ color: "var(--accent)" }}>
            import_batch_id={asset.provenance.import_batch_id}
          </div>
        )}
      </div>

      <div className="space-y-1.5">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Services ({asset.services.length})
        </div>
        <div className="p-2 mc-elevated text-xs mono space-y-0.5" style={{ color: "var(--text-muted)" }}>
          {asset.services.length === 0 ? (
            <span style={{ color: "var(--text-dim)" }}>No exposed services recorded.</span>
          ) : (
            asset.services.map((s) => (
              <div key={s.key}>
                {s.port}/{s.protocol} · {s.name} {s.product ? `(${s.product} ${s.version ?? ""})` : ""}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Relationships ({asset.relationships.length})
        </div>
        <div className="space-y-1">
          {asset.relationships.length === 0 ? (
            <div className="p-2 mc-elevated text-xs" style={{ color: "var(--text-dim)" }}>
              No direct asset relationships.
            </div>
          ) : (
            asset.relationships.map((r) => (
              <div key={r.key} className="p-2 mc-elevated text-xs flex items-center justify-between gap-2">
                <span className="mono">
                  {r.source_asset_key} <span style={{ color: "var(--accent)" }}>{r.type}</span>{" "}
                  {r.target_asset_key}
                </span>
                <span className="mono" style={{ color: "var(--text-dim)" }}>
                  conf {r.provenance.confidence.toFixed(2)}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Findings ({asset.findings.length})
        </div>
        {asset.findings.length === 0 ? (
          <div className="p-2 mc-elevated text-xs" style={{ color: "var(--text-dim)" }}>
            No findings associated with this asset.
          </div>
        ) : (
          <div className="space-y-1.5">
            {asset.findings.map((f) => (
              <div key={f.key} className="p-2 mc-elevated text-xs space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono font-bold">{f.key}</span>
                  <div className="flex items-center gap-1.5">
                    <SeverityBadge severity={f.severity} />
                    <StatusBadge status={f.status} />
                  </div>
                </div>
                <div className="font-medium">{f.title}</div>
                <div style={{ color: "var(--text-muted)" }}>{f.remediation_notes}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="space-y-1.5">
        <div className="mc-kicker" style={{ color: "var(--text-muted)" }}>
          Supporting Evidence ({asset.evidence.length})
        </div>
        {asset.evidence.length === 0 ? (
          <div className="p-2 mc-elevated text-xs" style={{ color: "var(--text-dim)" }}>
            No evidence items linked directly.
          </div>
        ) : (
          <div className="space-y-1.5">
            {asset.evidence.map((ev) => (
              <div key={ev.key} className="p-2 mc-elevated text-xs space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono font-bold" style={{ color: "var(--accent)" }}>
                    {ev.key}
                  </span>
                  <span className="mono" style={{ color: "var(--text-dim)" }}>
                    {ev.kind}
                  </span>
                </div>
                <div className="font-semibold">{ev.title}</div>
                <div className="mono p-1.5 border rounded break-all" style={{ borderColor: "var(--border)", color: "var(--text-muted)", background: "var(--bg-app)" }}>
                  {ev.excerpt}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
