import type { ReactNode } from "react";
import {
  Activity,
  Camera,
  Database,
  FileText,
  FileWarning,
  LayoutDashboard,
  LogOut,
  Route,
  ScrollText,
  ShieldCheck,
  UploadCloud,
  Users,
} from "lucide-react";
import type { EnvironmentSummary, SnapshotSummary, UserResponse } from "../api/types";

export type NavTab =
  | "overview"
  | "attack-paths"
  | "scenario-lab"
  | "assets"
  | "findings"
  | "imports"
  | "reports"
  | "audit"
  | "admin";

interface AppShellProps {
  user: UserResponse;
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  environments: EnvironmentSummary[];
  selectedEnvId: string;
  onSelectEnv: (envId: string) => void;
  snapshots: SnapshotSummary[];
  selectedSnapshotId: string;
  onSelectSnapshot: (snapId: string) => void;
  onCreateSnapshot: () => void;
  creatingSnapshot: boolean;
  onLogout: () => void;
  children: ReactNode;
}

export function AppShell({
  user,
  activeTab,
  onSelectTab,
  environments,
  selectedEnvId,
  onSelectEnv,
  snapshots,
  selectedSnapshotId,
  onSelectSnapshot,
  onCreateSnapshot,
  creatingSnapshot,
  onLogout,
  children,
}: AppShellProps) {
  const activeSnap = snapshots.find((s) => s.id === selectedSnapshotId);
  const canCreateSnapshot = user.role === "analyst" || user.role === "admin";
  const canViewAudit = user.role === "analyst" || user.role === "admin";
  const isAdmin = user.role === "admin";

  const navItems: { id: NavTab; label: string; icon: typeof Activity; visible: boolean }[] = [
    { id: "overview", label: "Overview", icon: LayoutDashboard, visible: true },
    { id: "attack-paths", label: "Attack Paths", icon: Route, visible: true },
    { id: "scenario-lab", label: "Scenario Lab", icon: Activity, visible: true },
    { id: "assets", label: "Assets", icon: Database, visible: true },
    { id: "findings", label: "Findings", icon: FileWarning, visible: true },
    { id: "imports", label: "Imports", icon: UploadCloud, visible: true },
    { id: "reports", label: "Reports", icon: FileText, visible: true },
    { id: "audit", label: "Audit Trail", icon: ScrollText, visible: canViewAudit },
    { id: "admin", label: "Admin", icon: Users, visible: isAdmin },
  ];

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--bg-app)" }}>
      <header
        className="border-b px-4 py-2.5 flex flex-wrap items-center justify-between gap-3"
        style={{ background: "var(--bg-rail)", borderColor: "var(--border)" }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 pr-3 border-r" style={{ borderColor: "var(--border)" }}>
            <span
              className="w-7 h-7 inline-flex items-center justify-center text-xs font-bold mono border rounded"
              style={{
                background: "var(--accent-soft)",
                color: "var(--accent)",
                borderColor: "var(--accent-border)",
              }}
            >
              CL
            </span>
            <span className="text-sm font-bold tracking-tight">CHAOS LAB</span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
              Environment
            </span>
            <select
              aria-label="Environment selector"
              value={selectedEnvId}
              disabled={environments.length === 0}
              onChange={(e) => onSelectEnv(e.target.value)}
              className="px-2.5 py-1 text-xs mc-elevated font-semibold focus:outline-none disabled:opacity-50"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            >
              {environments.length === 0 ? (
                <option value="">No environments yet</option>
              ) : (
                environments.map((env) => (
                  <option key={env.id} value={env.id}>
                    {env.name}
                  </option>
                ))
              )}
            </select>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="mc-kicker" style={{ color: "var(--text-dim)" }}>
              Snapshot
            </span>
            <select
              aria-label="Snapshot selector"
              value={selectedSnapshotId}
              disabled={snapshots.length === 0}
              onChange={(e) => onSelectSnapshot(e.target.value)}
              className="px-2.5 py-1 text-xs mono mc-elevated focus:outline-none max-w-xs disabled:opacity-50"
              style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
            >
              {snapshots.length === 0 ? (
                <option value="">No snapshots yet</option>
              ) : (
                snapshots.map((snap) => (
                  <option key={snap.id} value={snap.id}>
                    {snap.label} · sha256 {snap.sha256.slice(0, 8)}
                  </option>
                ))
              )}
            </select>
            {activeSnap && (
              <span className="hidden xl:inline mono text-xs" style={{ color: "var(--text-dim)" }}>
                sha256:{activeSnap.sha256.slice(0, 12)}…
              </span>
            )}
            {canCreateSnapshot && (
              <button
                type="button"
                onClick={onCreateSnapshot}
                disabled={creatingSnapshot || !selectedEnvId}
                title="Freeze working inventory into a new immutable snapshot"
                className="px-2 py-1 text-xs mc-elevated hover:opacity-90 inline-flex items-center gap-1 disabled:opacity-50"
                style={{ color: "var(--accent)", borderColor: "var(--accent-border)" }}
              >
                <Camera className="w-3.5 h-3.5" />
                {creatingSnapshot ? "Freezing…" : "Freeze Snapshot"}
              </button>
            )}
          </div>
        </div>

        <div
          className="flex items-center gap-2 px-2.5 py-1 text-xs font-semibold border rounded"
          style={{
            background: "var(--ok-bg)",
            color: "var(--ok)",
            borderColor: "rgba(34, 197, 94, 0.35)",
          }}
        >
          <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
          <span>OFFLINE SIMULATION · modeled data only · no live systems contacted</span>
        </div>
      </header>

      <div className="flex-1 flex flex-col lg:flex-row min-h-0">
        <aside
          className="border-b lg:border-b-0 lg:border-r lg:w-56 shrink-0 flex flex-col justify-between p-3 gap-4"
          style={{ background: "var(--bg-rail)", borderColor: "var(--border)" }}
        >
          <div className="space-y-4">
            <nav aria-label="Operations modules" className="flex lg:flex-col flex-wrap gap-1">
              {navItems
                .filter((i) => i.visible)
                .map((item) => {
                  const Icon = item.icon;
                  const active = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => onSelectTab(item.id)}
                      className="text-left px-2.5 py-2 text-xs font-semibold flex items-center justify-between gap-2 rounded border transition"
                      style={{
                        background: active ? "var(--accent-soft)" : "transparent",
                        color: active ? "var(--text-main)" : "var(--text-muted)",
                        borderColor: active ? "var(--accent-border)" : "transparent",
                      }}
                    >
                      <span className="inline-flex items-center gap-2">
                        <Icon className="w-3.5 h-3.5" style={{ color: active ? "var(--accent)" : "var(--text-dim)" }} />
                        {item.label}
                      </span>
                      {active && (
                        <span className="mono text-xs" style={{ color: "var(--accent)" }}>
                          ●
                        </span>
                      )}
                    </button>
                  );
                })}
            </nav>
          </div>

          <div className="border-t pt-3 flex items-center justify-between gap-2" style={{ borderColor: "var(--border)" }}>
            <div className="min-w-0">
              <div className="text-xs font-medium truncate">{user.email}</div>
              <div className="text-xs capitalize" style={{ color: "var(--text-dim)" }}>
                Role: {user.role} · RBAC active
              </div>
            </div>
            <button
              type="button"
              onClick={onLogout}
              title="Sign out"
              className="p-1.5 mc-elevated hover:opacity-90"
              style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </aside>

        <main className="flex-1 min-w-0 p-3 flex flex-col gap-3">{children}</main>
      </div>
    </div>
  );
}
