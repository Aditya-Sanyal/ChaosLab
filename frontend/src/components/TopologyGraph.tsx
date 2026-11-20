import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { Maximize2, ZoomIn, ZoomOut } from "lucide-react";
import type { AssetSummary, ModeledPath, TopologyGraphResponse } from "../api/types";

interface TopologyGraphProps {
  graph: TopologyGraphResponse | null;
  activePath: ModeledPath | null;
  selectedAssetKey: string | null;
  onSelectAsset: (assetKey: string) => void;
}

const ZONE_SLOT: Record<string, { x: number; y: number }> = {
  internet: { x: 80, y: 200 },
  dmz: { x: 270, y: 140 },
  corp: { x: 270, y: 420 },
  app: { x: 500, y: 120 },
  mgmt: { x: 520, y: 420 },
  data: { x: 740, y: 130 },
  cloud: { x: 960, y: 210 },
};

const SEV_BORDER: Record<string, string> = {
  critical: "#ef4444",
  high: "#fb923c",
  medium: "#fde047",
  low: "#38bdf8",
};

const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function stepNodeId(pos: string): string {
  if (pos.startsWith("zone:")) {
    const zKey = pos.slice(5);
    return zKey === "internet" ? "origin:internet" : `zone:${zKey}`;
  }
  if (pos.startsWith("asset:")) {
    return `asset:${pos.slice(6)}`;
  }
  return `asset:${pos}`;
}

function formatAssetLabel(
  a: AssetSummary,
  showFindings: boolean,
  showExposure: boolean
): string {
  const tags: string[] = [];
  if (a.crown_jewel) tags.push("◆");
  if (showExposure && a.internet_exposed) tags.push("EXT");
  if (showFindings && a.finding_count > 0) tags.push(`${a.finding_count}F`);
  const prefix = tags.length ? `${tags.join(" ")} ` : "";
  const sub = a.type === "identity" ? "identity" : (a.ip_addresses[0] ?? a.type);
  return `${prefix}${a.key}\n${sub}`;
}

export function TopologyGraph({
  graph,
  activePath,
  selectedAssetKey,
  onSelectAsset,
}: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelectAsset);
  onSelectRef.current = onSelectAsset;

  const [zoneFilter, setZoneFilter] = useState<string>("all");
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>("all");
  const [minSeverityFilter, setMinSeverityFilter] = useState<string>("all");
  const [exposureFilter, setExposureFilter] = useState<string>("all");
  const [showFindingsOverlay, setShowFindingsOverlay] = useState<boolean>(true);
  const [showExposureOverlay, setShowExposureOverlay] = useState<boolean>(true);

  const hasFilters =
    zoneFilter !== "all" ||
    assetTypeFilter !== "all" ||
    minSeverityFilter !== "all" ||
    exposureFilter !== "all";

  const baseElements = useMemo<ElementDefinition[]>(() => {
    if (!graph) return [];
    const els: ElementDefinition[] = [];
    const visibleZones = new Set(
      zoneFilter === "all" ? graph.zones.map((z) => z.key) : [zoneFilter]
    );

    const matchesAssetFilter = (a: AssetSummary): boolean => {
      if (zoneFilter !== "all" && a.zone_key !== zoneFilter) return false;
      if (assetTypeFilter !== "all" && a.type !== assetTypeFilter) return false;
      if (exposureFilter === "exposed" && !a.internet_exposed) return false;
      if (minSeverityFilter !== "all") {
        if (a.finding_count === 0) return false;
        const minRank = minSeverityFilter === "any_finding" ? 0 : (SEV_RANK[minSeverityFilter] ?? 0);
        const rank = a.max_severity ? (SEV_RANK[a.max_severity] ?? 0) : -1;
        if (rank < minRank) return false;
      }
      return true;
    };

    const filteredAssets = graph.assets.filter(matchesAssetFilter);
    const hasIdentityNodes = filteredAssets.some((a) => a.zone_key === null);
    if (hasIdentityNodes && zoneFilter === "all") {
      els.push({
        data: {
          id: "zone:__identities__",
          kind: "zone",
          label: "Identities (non-zoned)",
          restricted: false,
        },
      });
    }

    graph.zones.forEach((z) => {
      if (!visibleZones.has(z.key)) return;
      els.push({
        data: {
          id: `zone:${z.key}`,
          kind: "zone",
          label: `${z.name} · intra:${z.intra_zone_policy}`,
          restricted: z.trust_level === "high",
        },
      });
    });

    if (visibleZones.has("internet") && assetTypeFilter === "all" && minSeverityFilter === "all") {
      els.push({
        data: {
          id: "origin:internet",
          parent: "zone:internet",
          kind: "origin",
          label: "Internet\n0.0.0.0/0",
          severity: "none",
        },
        position: { x: ZONE_SLOT.internet.x, y: ZONE_SLOT.internet.y },
      });
    }

    // Group assets by zone slot to stack cleanly without overlap
    const assetsByGroup = new Map<string, AssetSummary[]>();
    for (const a of filteredAssets) {
      const gKey = a.zone_key ?? "__identities__";
      const bucket = assetsByGroup.get(gKey) ?? [];
      bucket.push(a);
      assetsByGroup.set(gKey, bucket);
    }

    const visibleAssetKeys = new Set<string>();
    let fallbackCol = 0;
    for (const [gKey, bucket] of assetsByGroup.entries()) {
      const slot =
        gKey === "__identities__"
          ? { x: 520, y: 270 }
          : ZONE_SLOT[gKey] ?? { x: 180 + fallbackCol++ * 200, y: 240 };

      bucket.forEach((asset, idx) => {
        visibleAssetKeys.add(asset.key);
        const yOffset = (idx - (bucket.length - 1) / 2) * 86;
        els.push({
          data: {
            id: `asset:${asset.key}`,
            assetKey: asset.key,
            parent: `zone:${gKey}`,
            kind: "asset",
            assetType: asset.type,
            label: formatAssetLabel(asset, showFindingsOverlay, showExposureOverlay),
            crown: asset.crown_jewel ? "yes" : "no",
            exposed: showExposureOverlay && asset.internet_exposed ? "yes" : "no",
            severity: showFindingsOverlay ? (asset.max_severity ?? "none") : "none",
          },
          position: { x: slot.x, y: slot.y + yOffset },
        });
      });
    }

    const hasInternetOrigin =
      visibleZones.has("internet") && assetTypeFilter === "all" && minSeverityFilter === "all";

    const resolveEndpoint = (kind: string, key: string): string | null => {
      if (kind === "zone") {
        if (!visibleZones.has(key)) return null;
        if (key === "internet") return hasInternetOrigin ? "origin:internet" : null;
        return `zone:${key}`;
      }
      return visibleAssetKeys.has(key) ? `asset:${key}` : null;
    };

    for (const rr of graph.reachability_edges) {
      const src = resolveEndpoint(rr.source_kind, rr.source_key);
      const tgt = resolveEndpoint(rr.target_kind, rr.target_key);
      if (!src || !tgt) continue;
      const portLabel = rr.ports.length ? `:${rr.ports.join(",")}` : ":*";
      els.push({
        data: {
          id: `rr:${rr.key}`,
          source: src,
          target: tgt,
          edgeKind: rr.inferred_zone_flow ? "inferred" : "explicit",
          label: `${rr.key} ${portLabel}`,
        },
      });
    }

    for (const rel of graph.relationship_edges) {
      if (!visibleAssetKeys.has(rel.source_asset_key) || !visibleAssetKeys.has(rel.target_asset_key)) {
        continue;
      }
      els.push({
        data: {
          id: `rel:${rel.key}`,
          source: `asset:${rel.source_asset_key}`,
          target: `asset:${rel.target_asset_key}`,
          edgeKind: "cred",
          label: rel.type,
        },
      });
    }

    return els;
  }, [
    graph,
    zoneFilter,
    assetTypeFilter,
    minSeverityFilter,
    exposureFilter,
    showFindingsOverlay,
    showExposureOverlay,
  ]);

  // Build / rebuild Cytoscape graph on topology or filter change
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const cy = cytoscape({
      container,
      elements: baseElements,
      layout: { name: "preset", padding: 28 },
      wheelSensitivity: 0.25,
      minZoom: 0.35,
      maxZoom: 2.2,
      style: [
        {
          selector: "node[kind='zone']",
          style: {
            shape: "round-rectangle",
            "background-color": "#0b1526",
            "background-opacity": 0.72,
            "border-color": "#264066",
            "border-width": 1.25,
            "border-style": "solid",
            label: "data(label)",
            "text-valign": "top",
            "text-halign": "center",
            "text-margin-y": -6,
            "font-size": 11,
            "font-weight": 700,
            color: "#93a8c7",
            padding: "24px",
          },
        },
        {
          selector: "node[?restricted]",
          style: {
            "background-color": "#1a111a",
            "border-style": "dashed",
            "border-color": "#5c334a",
          },
        },
        {
          selector: "node[kind='origin']",
          style: {
            shape: "round-rectangle",
            width: 112,
            height: 46,
            "background-color": "#122139",
            "border-color": "#ef4444",
            "border-width": 1.5,
            label: "data(label)",
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": 11,
            "font-family": "ui-monospace, monospace",
            color: "#f1f5f9",
          },
        },
        {
          selector: "node[kind='asset']",
          style: {
            shape: "round-rectangle",
            width: 144,
            height: 50,
            "background-color": "#122139",
            "border-color": "#2d4c7a",
            "border-width": 1.5,
            label: "data(label)",
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": 11,
            "font-family": "ui-monospace, monospace",
            color: "#f1f5f9",
          },
        },
        {
          selector: "node[assetType='identity']",
          style: {
            shape: "ellipse",
            width: 146,
            height: 44,
            "background-color": "#151d36",
            "border-color": "#6366f1",
          },
        },
        {
          selector: "node[severity='critical']",
          style: { "border-color": SEV_BORDER.critical, "border-width": 2 },
        },
        {
          selector: "node[severity='high']",
          style: { "border-color": SEV_BORDER.high, "border-width": 2 },
        },
        {
          selector: "node[severity='medium']",
          style: { "border-color": SEV_BORDER.medium, "border-width": 1.75 },
        },
        {
          selector: "node[crown='yes']",
          style: {
            "border-color": "#fbbf24",
            "border-width": 2.5,
            "border-style": "double",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.9,
            "line-color": "#415d85",
            "target-arrow-color": "#415d85",
            "font-size": 9,
            color: "#6b84a8",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: "edge[edgeKind='inferred']",
          style: {
            "line-style": "dashed",
            "line-dash-pattern": [6, 4],
            "line-color": "#6488b8",
            "target-arrow-color": "#6488b8",
          },
        },
        {
          selector: "edge[edgeKind='cred']",
          style: {
            "line-style": "dotted",
            "line-color": "#7b93b8",
            "target-arrow-color": "#7b93b8",
          },
        },
        {
          selector: ".dimmed",
          style: {
            opacity: 0.28,
          },
        },
        {
          selector: ".path-node",
          style: {
            opacity: 1,
            "border-color": "#f59e0b",
            "border-width": 2.5,
          },
        },
        {
          selector: ".selected-node",
          style: {
            opacity: 1,
            "background-color": "#1c3357",
            "border-color": "#f59e0b",
            "border-width": 3,
          },
        },
        {
          selector: "edge.path-overlay",
          style: {
            width: 3.2,
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 1.15,
            label: "data(label)",
            "font-size": 11,
            "font-weight": 800,
            color: "#1b1102",
            "text-background-color": "#f59e0b",
            "text-background-opacity": 1,
            "text-background-shape": "roundrectangle",
            "text-background-padding": "4px",
            "z-index": 20,
            opacity: 1,
          },
        },
      ],
    });

    cy.on("tap", "node[kind='asset']", (evt) => {
      const assetKey = evt.target.data("assetKey") as string | undefined;
      if (assetKey) {
        onSelectRef.current(assetKey);
      }
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [baseElements]);

  // Apply modeled path overlay & selection without rebuilding layout
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.edges(".path-overlay").remove();
      cy.elements().removeClass("dimmed path-node selected-node");

      if (activePath && activePath.steps.length > 0) {
        cy.nodes("[kind!='zone']").addClass("dimmed");
        cy.edges().addClass("dimmed");

        const pathNodeIds = new Set<string>();
        const overlayEdges: ElementDefinition[] = [];

        activePath.steps.forEach((step, idx) => {
          const fromId = stepNodeId(step.from_position);
          const toId = `asset:${step.target_key}`;
          if (cy.getElementById(fromId).length > 0 && cy.getElementById(toId).length > 0) {
            pathNodeIds.add(fromId);
            pathNodeIds.add(toId);
            overlayEdges.push({
              group: "edges",
              data: {
                id: `path-overlay-${idx}-${step.step_key}`,
                source: fromId,
                target: toId,
                label: String(idx + 1),
              },
              classes: "path-overlay",
            });
          }
        });

        pathNodeIds.forEach((id) => {
          cy.getElementById(id).removeClass("dimmed").addClass("path-node");
        });
        if (overlayEdges.length > 0) {
          cy.add(overlayEdges);
        }
      }

      if (selectedAssetKey) {
        const sel = cy.getElementById(`asset:${selectedAssetKey}`);
        if (sel.length > 0) {
          sel.removeClass("dimmed").addClass("selected-node");
        }
      }
    });
  }, [activePath, selectedAssetKey, baseElements]);

  return (
    <div className="mc-panel flex flex-col min-h-[470px] overflow-hidden">
      <div
        className="px-3 py-2 border-b flex flex-wrap items-center justify-between gap-2"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="mc-kicker">Environment Topology &amp; Modeled Path Overlay</h2>
          {activePath ? (
            <span
              className="mono text-xs px-2 py-0.5 border rounded"
              style={{
                background: "var(--accent-soft)",
                color: "var(--accent)",
                borderColor: "var(--accent-border)",
              }}
            >
              Active Path · score {activePath.modeled_score}/100
            </span>
          ) : (
            <span
              className="mono text-xs px-2 py-0.5 border rounded"
              style={{
                background: "var(--bg-elevated)",
                color: "var(--text-muted)",
                borderColor: "var(--border)",
              }}
            >
              No active path highlight
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            aria-label="Zone filter"
            value={zoneFilter}
            onChange={(e) => setZoneFilter(e.target.value)}
            className="px-2 py-1 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="all">All Zones</option>
            {graph?.zones.map((z) => (
              <option key={z.key} value={z.key}>
                {z.name}
              </option>
            ))}
          </select>

          <select
            aria-label="Asset type filter"
            value={assetTypeFilter}
            onChange={(e) => setAssetTypeFilter(e.target.value)}
            className="px-2 py-1 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="all">All Types</option>
            <option value="server">server</option>
            <option value="application">application</option>
            <option value="data_store">data_store</option>
            <option value="workstation">workstation</option>
            <option value="network_device">network_device</option>
            <option value="cloud_resource">cloud_resource</option>
            <option value="identity">identity</option>
          </select>

          <select
            aria-label="Min severity filter"
            value={minSeverityFilter}
            onChange={(e) => setMinSeverityFilter(e.target.value)}
            className="px-2 py-1 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="all">Any Severity</option>
            <option value="any_finding">Has Findings</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical Only</option>
          </select>

          <select
            aria-label="Exposure filter"
            value={exposureFilter}
            onChange={(e) => setExposureFilter(e.target.value)}
            className="px-2 py-1 text-xs mc-elevated focus:outline-none"
            style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
          >
            <option value="all">All Exposure</option>
            <option value="exposed">Internet Exposed</option>
          </select>

          <label className="inline-flex items-center gap-1 px-1.5 py-1 cursor-pointer" style={{ color: "var(--text-muted)" }}>
            <input
              type="checkbox"
              checked={showFindingsOverlay}
              onChange={(e) => setShowFindingsOverlay(e.target.checked)}
              className="accent-amber-500"
            />
            <span>Findings</span>
          </label>

          <label className="inline-flex items-center gap-1 px-1.5 py-1 cursor-pointer" style={{ color: "var(--text-muted)" }}>
            <input
              type="checkbox"
              checked={showExposureOverlay}
              onChange={(e) => setShowExposureOverlay(e.target.checked)}
              className="accent-amber-500"
            />
            <span>Exposure</span>
          </label>

          {hasFilters && (
            <button
              type="button"
              onClick={() => {
                setZoneFilter("all");
                setAssetTypeFilter("all");
                setMinSeverityFilter("all");
                setExposureFilter("all");
              }}
              className="px-2 py-1 text-xs mc-elevated"
              style={{ color: "var(--accent)", borderColor: "var(--accent-border)" }}
            >
              Reset
            </button>
          )}

          <button
            type="button"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)}
            title="Zoom in"
            className="p-1 mc-elevated"
            style={{ color: "var(--text-muted)" }}
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)}
            title="Zoom out"
            className="p-1 mc-elevated"
            style={{ color: "var(--text-muted)" }}
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => cyRef.current?.fit(undefined, 28)}
            title="Fit graph"
            className="p-1 mc-elevated inline-flex items-center gap-1"
            style={{ color: "var(--text-muted)" }}
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Fit</span>
          </button>
        </div>
      </div>

      <div
        className="px-3 py-1.5 border-b flex flex-wrap items-center gap-4 text-xs"
        style={{ borderColor: "var(--border)", color: "var(--text-muted)", background: "var(--bg-rail)" }}
      >
        <span>── Explicit reach</span>
        <span>- - Inferred zone flow</span>
        <span>··· Credential / identity</span>
        <span style={{ color: "var(--accent)" }}>● Modeled step</span>
        <span style={{ color: "var(--crown)" }}>◆ Crown jewel</span>
        <span style={{ color: "var(--text-dim)" }}>Click any asset node for telemetry</span>
      </div>

      <div ref={containerRef} className="flex-1 min-h-[400px] mc-grid-bg" />
    </div>
  );
}
