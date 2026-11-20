import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "./api/client";
import type { SnapshotSummary, UserResponse } from "./api/types";
import { AdminView } from "./components/AdminView";
import { AppShell, type NavTab } from "./components/AppShell";
import { AssetsView } from "./components/AssetsView";
import { AttackPathsView } from "./components/AttackPathsView";
import { AuditView } from "./components/AuditView";
import { EmptyEnvironmentsView } from "./components/EmptyEnvironmentsView";
import { FindingsView } from "./components/FindingsView";
import { ImportsView } from "./components/ImportsView";
import { LoginView } from "./components/LoginView";
import { OverviewView } from "./components/OverviewView";
import { ReportsView } from "./components/ReportsView";
import { ScenarioLabView } from "./components/ScenarioLabView";

export function App() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<NavTab>("scenario-lab");
  const [selectedEnvId, setSelectedEnvId] = useState<string>("");
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>("");

  const meQuery = useQuery({
    queryKey: ["me"],
    queryFn: api.getMe,
    retry: false,
  });

  const user: UserResponse | null = meQuery.data ?? null;

  const envsQuery = useQuery({
    queryKey: ["environments"],
    queryFn: api.listEnvironments,
    enabled: Boolean(user),
  });

  const environments = envsQuery.data ?? [];

  useEffect(() => {
    if (environments.length > 0 && (!selectedEnvId || !environments.some((e) => e.id === selectedEnvId))) {
      setSelectedEnvId(environments[0].id);
    }
  }, [environments, selectedEnvId]);

  const snapshotsQuery = useQuery({
    queryKey: ["snapshots", selectedEnvId],
    queryFn: () => api.listSnapshots(selectedEnvId),
    enabled: Boolean(user && selectedEnvId),
  });

  const snapshots = snapshotsQuery.data ?? [];

  useEffect(() => {
    if (snapshots.length > 0 && (!selectedSnapshotId || !snapshots.some((s) => s.id === selectedSnapshotId))) {
      setSelectedSnapshotId(snapshots[0].id);
    }
  }, [snapshots, selectedSnapshotId]);

  const createSnapshotMutation = useMutation({
    mutationFn: () => api.createSnapshot(selectedEnvId),
    onSuccess: (snap) => {
      queryClient.setQueryData<SnapshotSummary[]>(["snapshots", selectedEnvId], (prev) =>
        prev ? [snap, ...prev.filter((s) => s.id !== snap.id)] : [snap]
      );
      setSelectedSnapshotId(snap.id);
      void queryClient.invalidateQueries({ queryKey: ["snapshots", selectedEnvId] });
      void queryClient.invalidateQueries({ queryKey: ["overview", selectedEnvId] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
  });

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      queryClient.clear();
      setActiveTab("scenario-lab");
      await meQuery.refetch();
    }
  }

  if (meQuery.isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-xs mono" style={{ background: "var(--bg-app)", color: "var(--text-muted)" }}>
        Initializing CHAOS LAB operations console…
      </div>
    );
  }

  if (!user || (meQuery.isError && meQuery.error instanceof ApiError && meQuery.error.status === 401)) {
    return (
      <LoginView
        onSuccess={(loggedInUser) => {
          queryClient.setQueryData(["me"], loggedInUser);
        }}
      />
    );
  }

  return (
    <AppShell
      user={user}
      activeTab={activeTab}
      onSelectTab={setActiveTab}
      environments={environments}
      selectedEnvId={selectedEnvId}
      onSelectEnv={(id) => {
        setSelectedEnvId(id);
        setSelectedSnapshotId("");
      }}
      snapshots={snapshots}
      selectedSnapshotId={selectedSnapshotId}
      onSelectSnapshot={setSelectedSnapshotId}
      onCreateSnapshot={() => createSnapshotMutation.mutate()}
      creatingSnapshot={createSnapshotMutation.isPending}
      onLogout={handleLogout}
    >
      {activeTab !== "audit" && activeTab !== "admin" && envsQuery.isLoading && (
        <div className="mc-panel p-6 text-xs" style={{ color: "var(--text-muted)" }}>
          Loading environments…
        </div>
      )}
      {activeTab !== "audit" && activeTab !== "admin" && envsQuery.isError && (
        <div className="mc-panel p-6 text-xs" style={{ color: "var(--crit)" }}>
          Failed to load environments. Refresh or check backend health.
        </div>
      )}
      {activeTab !== "audit" &&
        activeTab !== "admin" &&
        envsQuery.isSuccess &&
        environments.length === 0 && (
          <EmptyEnvironmentsView
            user={user}
            onCreatedEnv={(newId) => {
              setSelectedEnvId(newId);
              setSelectedSnapshotId("");
              setActiveTab("imports");
            }}
          />
        )}
      {activeTab === "overview" && selectedEnvId && (
        <OverviewView
          envId={selectedEnvId}
          user={user}
          onNavigate={setActiveTab}
          onCreatedEnv={(newId) => {
            setSelectedEnvId(newId);
            setSelectedSnapshotId("");
            setActiveTab("imports");
          }}
        />
      )}
      {activeTab === "attack-paths" && selectedEnvId && (
        <AttackPathsView envId={selectedEnvId} snapshotId={selectedSnapshotId} />
      )}
      {activeTab === "scenario-lab" && selectedEnvId && (
        <ScenarioLabView envId={selectedEnvId} snapshotId={selectedSnapshotId} user={user} />
      )}
      {activeTab === "assets" && selectedEnvId && <AssetsView envId={selectedEnvId} />}
      {activeTab === "findings" && selectedEnvId && <FindingsView envId={selectedEnvId} user={user} />}
      {activeTab === "imports" && selectedEnvId && <ImportsView envId={selectedEnvId} user={user} />}
      {activeTab === "reports" && selectedEnvId && <ReportsView envId={selectedEnvId} user={user} />}
      {activeTab === "audit" && <AuditView user={user} />}
      {activeTab === "admin" && <AdminView user={user} />}
    </AppShell>
  );
}

export default App;
