import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { api, ApiError } from "../api/client";
import { AssetDetailPanel } from "./AssetDetailPanel";
import { SeverityBadge } from "./SeverityBadge";

interface AssetsViewProps {
  envId: string;
}

export function AssetsView({ envId }: AssetsViewProps) {
  const [search, setSearch] = useState("");
  const [zoneKey, setZoneKey] = useState("");
  const [assetType, setAssetType] = useState("");
  const [minCriticality, setMinCriticality] = useState<string>("");
  const [exposure, setExposure] = useState<string>("");
  const [hasFindings, setHasFindings] = useState<string>("");
  const [origin, setOrigin] = useState<string>("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const graphQuery = useQuery({
    queryKey: ["graph", envId],
    queryFn: () => api.getTopologyGraph(envId),
    enabled: Boolean(envId),
  });

  const assetsQuery = useQuery({
    queryKey: [
      "assets",
      envId,
      search,
      zoneKey,
      assetType,
      minCriticality,
      exposure,
      hasFindings,
      origin,
    ],
    queryFn: () =>
      api.listAssets(envId, {
        search: search || undefined,
        zone_key: zoneKey || undefined,
        asset_type: assetType || undefined,
        min_criticality: minCriticality ? Number(minCriticality) : undefined,
        internet_exposed:
          exposure === "exposed" ? true : exposure === "internal" ? false : undefined,
        has_findings:
          hasFindings === "yes" ? true : hasFindings === "no" ? false : undefined,
        origin: origin || undefined,
      }),
    enabled: Boolean(envId),
  });

  const detailQuery = useQuery({
    queryKey: ["asset-detail", envId, selectedKey],
    queryFn: () => api.getAssetDetail(envId, selectedKey!),
    enabled: Boolean(envId && selectedKey),
  });

  const assets = assetsQuery.data ?? [];

  useEffect(() => {
    if (assets.length > 0 && (!selectedKey || !assets.some((a) => a.key === selectedKey))) {
      setSelectedKey(assets[0].key);
    }
  }, [assets, selectedKey]);

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2" style={{ color: "var(--text-dim)" }} />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search key, name, owner, IP…"
              className="pl-8 pr-3 py-1.5 text-xs mc-elevated w-64 focus:outline-none"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            />
          </div>

          <select
            aria-label="Filter by zone"
            value={zoneKey}
            onChange={(e) => setZoneKey(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">All Zones</option>
            {graphQuery.data?.zones.map((z) => (
              <option key={z.key} value={z.key}>
                {z.name}
              </option>
            ))}
          </select>

          <select
            aria-label="Filter by type"
            value={assetType}
            onChange={(e) => setAssetType(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">All Types</option>
            <option value="server">server</option>
            <option value="application">application</option>
            <option value="data_store">data_store</option>
            <option value="workstation">workstation</option>
            <option value="network_device">network_device</option>
            <option value="cloud_resource">cloud_resource</option>
            <option value="identity">identity</option>
          </select>

          <select
            aria-label="Filter by min criticality"
            value={minCriticality}
            onChange={(e) => setMinCriticality(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">Any Criticality</option>
            <option value="3">Crit 3+</option>
            <option value="4">Crit 4+</option>
            <option value="5">Crit 5 (Crown)</option>
          </select>

          <select
            aria-label="Filter by exposure"
            value={exposure}
            onChange={(e) => setExposure(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">All Exposure</option>
            <option value="exposed">Internet Exposed</option>
            <option value="internal">Internal Only</option>
          </select>

          <select
            aria-label="Filter by findings"
            value={hasFindings}
            onChange={(e) => setHasFindings(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">All Findings</option>
            <option value="yes">Has Findings</option>
            <option value="no">Clean (0)</option>
          </select>

          <select
            aria-label="Filter by origin"
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
            className="px-2.5 py-1.5 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="">All Origins</option>
            <option value="imported">imported</option>
            <option value="manual">manual</option>
            <option value="inferred">inferred</option>
          </select>

          {(search || zoneKey || assetType || minCriticality || exposure || hasFindings || origin) && (
            <button
              type="button"
              onClick={() => {
                setSearch("");
                setZoneKey("");
                setAssetType("");
                setMinCriticality("");
                setExposure("");
                setHasFindings("");
                setOrigin("");
              }}
              className="px-2.5 py-1.5 text-xs mc-elevated"
              style={{ color: "var(--accent)", borderColor: "var(--accent-border)" }}
            >
              Clear
            </button>
          )}
        </div>

        <div className="text-xs mono" style={{ color: "var(--text-muted)" }}>
          {assets.length} asset(s)
        </div>
      </div>

      <div className="flex-1 grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-0">
        <div className="xl:col-span-7 mc-panel overflow-auto thin-scroll">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b mc-kicker" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
                <th className="p-2.5">Asset</th>
                <th className="p-2.5">Zone</th>
                <th className="p-2.5">Type</th>
                <th className="p-2.5">Crit</th>
                <th className="p-2.5">Findings</th>
                <th className="p-2.5">Origin</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => {
                const selected = a.key === selectedKey;
                return (
                  <tr
                    key={a.key}
                    onClick={() => setSelectedKey(a.key)}
                    className="border-b cursor-pointer transition"
                    style={{
                      borderColor: "var(--border)",
                      background: selected ? "var(--accent-soft)" : "transparent",
                    }}
                  >
                    <td className="p-2.5">
                      <div className="font-bold mono flex items-center gap-1.5">
                        {a.crown_jewel && <span style={{ color: "var(--crown)" }}>◆</span>}
                        <span>{a.key}</span>
                        {a.internet_exposed && (
                          <span className="px-1 py-0.5 rounded" style={{ background: "var(--high-bg)", color: "var(--high)" }}>
                            EXT
                          </span>
                        )}
                      </div>
                      <div style={{ color: "var(--text-muted)" }}>{a.name}</div>
                    </td>
                    <td className="p-2.5 mono" style={{ color: "var(--text-muted)" }}>
                      {a.zone_key ?? "identity"}
                    </td>
                    <td className="p-2.5 mono" style={{ color: "var(--text-muted)" }}>
                      {a.type}
                    </td>
                    <td className="p-2.5 mono font-bold">{a.criticality}/5</td>
                    <td className="p-2.5">
                      {a.finding_count > 0 && a.max_severity ? (
                        <div className="inline-flex items-center gap-1.5">
                          <span className="mono font-bold">{a.finding_count}</span>
                          <SeverityBadge severity={a.max_severity} />
                        </div>
                      ) : (
                        <span style={{ color: "var(--text-dim)" }}>0</span>
                      )}
                    </td>
                    <td className="p-2.5 mono" style={{ color: "var(--text-dim)" }}>
                      {a.provenance.origin}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <aside className="xl:col-span-5 mc-panel p-3 overflow-y-auto thin-scroll max-h-[640px]">
          <AssetDetailPanel
            asset={detailQuery.data ?? null}
            loading={detailQuery.isLoading}
            error={detailQuery.error instanceof ApiError ? detailQuery.error.detail : null}
          />
        </aside>
      </div>
    </div>
  );
}
