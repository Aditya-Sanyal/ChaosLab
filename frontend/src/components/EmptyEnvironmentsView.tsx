import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Camera, Layers, PlusCircle, ShieldAlert, UploadCloud } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { EnvironmentSummary, UserResponse } from "../api/types";

interface EmptyEnvironmentsViewProps {
  user: UserResponse;
  onCreatedEnv: (newEnvId: string) => void;
}

export function EmptyEnvironmentsView({ user, onCreatedEnv }: EmptyEnvironmentsViewProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () => api.createEnvironment(name.trim(), description.trim()),
    onSuccess: (created) => {
      setErrorMsg(null);
      setName("");
      setDescription("");
      queryClient.setQueryData<EnvironmentSummary[]>(["environments"], (prev) =>
        prev ? [...prev.filter((e) => e.id !== created.id), created] : [created]
      );
      void queryClient.invalidateQueries({ queryKey: ["environments"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
      onCreatedEnv(created.id);
    },
    onError: (err) => {
      setErrorMsg(err instanceof ApiError ? err.detail : "Failed to create environment.");
    },
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (name.trim().length < 2) return;
    createMutation.mutate();
  }

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div className="mc-panel p-5 space-y-4 max-w-4xl">
        <div>
          <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <Layers className="w-3.5 h-3.5" />
            Zero-Demo Workspace Ready
          </div>
          <h1 className="text-base font-bold mt-1">Welcome to CHAOS LAB</h1>
          <p className="text-xs mt-1 leading-relaxed" style={{ color: "var(--text-muted)" }}>
            This instance started cleanly with no demo environments or sample findings. Everything runs strictly
            offline against files you import. Follow the three steps below to set up your first environment.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          <div className="mc-elevated p-3 space-y-1">
            <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
              <PlusCircle className="w-3.5 h-3.5" />
              1. Create Environment
            </div>
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
              Define an isolated workspace scope such as Corp Network, Staging VPC, or Cloud Enclave.
            </p>
          </div>
          <div className="mc-elevated p-3 space-y-1">
            <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
              <UploadCloud className="w-3.5 h-3.5" />
              2. Import Data Offline
            </div>
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
              Dry-run validate and commit JSON bundles, CSV inventory tables, or existing Nmap XML (-oX) files.
            </p>
          </div>
          <div className="mc-elevated p-3 space-y-1">
            <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
              <Camera className="w-3.5 h-3.5" />
              3. Freeze &amp; Model
            </div>
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
              Click Freeze Snapshot to lock a reproducible baseline, then explore Attack Paths and Scenario Lab.
            </p>
          </div>
        </div>

        {user.role === "admin" ? (
          <form
            onSubmit={handleSubmit}
            className="mc-elevated p-4 space-y-3"
            style={{ borderColor: "var(--accent-border)" }}
          >
            <div className="mc-kicker" style={{ color: "var(--accent)" }}>
              Create First Environment
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <div>
                <label className="block text-[11px] font-medium mb-1" style={{ color: "var(--text-muted)" }}>
                  Environment Name *
                </label>
                <input
                  type="text"
                  required
                  minLength={2}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Production Corp Segment"
                  className="w-full px-2.5 py-1.5 text-xs mc-panel focus:outline-none"
                  style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium mb-1" style={{ color: "var(--text-muted)" }}>
                  Description (optional)
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Scope notes or owner team"
                  className="w-full px-2.5 py-1.5 text-xs mc-panel focus:outline-none"
                  style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
                />
              </div>
            </div>

            {errorMsg && (
              <div className="text-xs flex items-center gap-1.5" style={{ color: "var(--crit)" }}>
                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            <div className="flex items-center gap-3">
              <button
                type="submit"
                disabled={createMutation.isPending || name.trim().length < 2}
                className="px-3.5 py-1.5 text-xs font-bold uppercase tracking-wider rounded inline-flex items-center gap-1.5 disabled:opacity-45 cursor-pointer"
                style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
              >
                <PlusCircle className="w-3.5 h-3.5" />
                {createMutation.isPending ? "Creating…" : "Create First Environment"}
              </button>
              <span className="text-[11px]" style={{ color: "var(--text-dim)" }}>
                Redirects directly to Imports after creation.
              </span>
            </div>
          </form>
        ) : (
          <div className="mc-elevated p-3 text-xs flex items-start gap-2" style={{ color: "var(--text-muted)" }}>
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" style={{ color: "var(--accent)" }} />
            <div>
              No workspace environments exist yet. Ask an administrator account (role <span className="mono">admin</span>)
              to create the first environment.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
