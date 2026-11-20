import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, KeyRound, ShieldAlert, Terminal, UserPlus, Users } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { AdminUserOut, Role, UserResponse } from "../api/types";

interface AdminViewProps {
  user: UserResponse;
}

const ROLES: Role[] = ["viewer", "analyst", "admin"];

export function AdminView({ user }: AdminViewProps) {
  const queryClient = useQueryClient();

  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");

  const [pendingRoles, setPendingRoles] = useState<Record<string, Role>>({});
  const [resetTargetId, setResetTargetId] = useState<string | null>(null);
  const [resetPasswordInput, setResetPasswordInput] = useState("");

  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const usersQuery = useQuery({
    queryKey: ["admin-users"],
    queryFn: api.listUsers,
    enabled: user.role === "admin",
  });

  const retentionQuery = useQuery({
    queryKey: ["admin-retention"],
    queryFn: api.getRetentionPolicy,
    enabled: user.role === "admin",
  });

  const createMutation = useMutation({
    mutationFn: () =>
      api.createUser({
        email: email.trim(),
        display_name: displayName.trim(),
        password,
        role,
      }),
    onSuccess: (created) => {
      setErrorMsg(null);
      setNotice(`Created ${created.role} user ${created.email} (logged to Audit Trail).`);
      setEmail("");
      setDisplayName("");
      setPassword("");
      void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setNotice(null);
      setErrorMsg(err instanceof ApiError ? err.detail : "Failed to create user.");
    },
  });

  const updateMutation = useMutation({
    mutationFn: (vars: { userId: string; role?: Role; is_active?: boolean }) =>
      api.updateUser(vars.userId, { role: vars.role, is_active: vars.is_active }),
    onSuccess: (updated) => {
      setErrorMsg(null);
      setNotice(
        `Updated ${updated.email}: role=${updated.role}, active=${String(updated.is_active)}.`
      );
      void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setNotice(null);
      setErrorMsg(err instanceof ApiError ? err.detail : "Failed to update user.");
    },
  });

  const resetPwdMutation = useMutation({
    mutationFn: (vars: { userId: string; newPassword: string }) =>
      api.resetUserPassword(vars.userId, vars.newPassword),
    onSuccess: (res) => {
      setErrorMsg(null);
      setNotice(
        `Reset password for ${res.email}; revoked ${res.sessions_revoked} active session(s).`
      );
      setResetTargetId(null);
      setResetPasswordInput("");
      void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
    onError: (err) => {
      setNotice(null);
      setErrorMsg(err instanceof ApiError ? err.detail : "Failed to reset password.");
    },
  });

  if (user.role !== "admin") {
    return (
      <div className="mc-panel p-6 text-xs" style={{ color: "var(--crit)" }}>
        Admin permissions (`admin:users`, `admin:settings`) are required to view this console.
      </div>
    );
  }

  const users: AdminUserOut[] = usersQuery.data ?? [];
  const retention = retentionQuery.data ?? null;

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0 overflow-y-auto thin-scroll">
      <div className="mc-panel p-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <Users className="w-3.5 h-3.5" />
            Administration &amp; Governance
          </h2>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            Manage local user accounts, RBAC roles, password resets (with immediate session revocation), and data retention posture.
          </p>
        </div>
        <span className="mono text-xs" style={{ color: "var(--text-dim)" }}>
          Last-admin protection active
        </span>
      </div>

      {notice && (
        <div
          className="p-2.5 rounded border text-xs flex items-center gap-2"
          style={{
            borderColor: "rgba(34, 197, 94, 0.45)",
            background: "var(--ok-bg)",
            color: "var(--ok)",
          }}
        >
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{notice}</span>
        </div>
      )}

      {errorMsg && (
        <div
          className="p-2.5 rounded border text-xs flex items-center gap-2"
          style={{
            borderColor: "rgba(239, 68, 68, 0.45)",
            background: "var(--crit-bg)",
            color: "var(--crit)",
          }}
        >
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          createMutation.mutate();
        }}
        className="mc-panel p-3 space-y-2.5"
      >
        <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--text-dim)" }}>
          <UserPlus className="w-3.5 h-3.5" />
          Create Local Account
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 text-xs items-end">
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Email
            </span>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@meridian.example"
              className="w-full px-2.5 py-1.5 rounded border mono"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Display Name
            </span>
            <input
              type="text"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="SecOps Operator"
              className="w-full px-2.5 py-1.5 rounded border"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Role
            </span>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              aria-label="New user role"
              className="w-full px-2.5 py-1.5 rounded border"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="block text-[11px]" style={{ color: "var(--text-dim)" }}>
              Initial Password (≥12 chars, upper+lower+digit/symbol)
            </span>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-2.5 py-1.5 rounded border"
              style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
            />
          </label>
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="px-3 py-1.5 rounded font-bold text-xs disabled:opacity-45"
            style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
          >
            {createMutation.isPending ? "Creating…" : "Create User"}
          </button>
        </div>
      </form>

      <div className="mc-panel overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b mc-kicker" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
              <th className="p-2.5">Account</th>
              <th className="p-2.5">Role</th>
              <th className="p-2.5">Status</th>
              <th className="p-2.5">Sessions</th>
              <th className="p-2.5">Last Login</th>
              <th className="p-2.5">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const selectedRole = pendingRoles[u.id] ?? u.role;
              const roleDirty = selectedRole !== u.role;
              const isResetting = resetTargetId === u.id;
              return (
                <tr key={u.id} className="border-b" style={{ borderColor: "var(--border)" }}>
                  <td className="p-2.5 align-top">
                    <div className="font-medium" style={{ color: "var(--text-main)" }}>
                      {u.display_name}
                    </div>
                    <div className="mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                      {u.email}
                    </div>
                  </td>
                  <td className="p-2.5 align-top">
                    <div className="flex items-center gap-1.5">
                      <select
                        value={selectedRole}
                        onChange={(e) =>
                          setPendingRoles((prev) => ({ ...prev, [u.id]: e.target.value as Role }))
                        }
                        aria-label={`Role for ${u.email}`}
                        className="px-2 py-1 rounded border mono text-xs"
                        style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                      {roleDirty && (
                        <button
                          type="button"
                          disabled={updateMutation.isPending}
                          onClick={() =>
                            updateMutation.mutate({ userId: u.id, role: selectedRole })
                          }
                          className="px-2 py-1 rounded border text-[11px] font-semibold"
                          style={{
                            borderColor: "var(--accent-border)",
                            background: "var(--accent-soft)",
                            color: "var(--accent)",
                          }}
                        >
                          Save
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="p-2.5 align-top">
                    <span
                      className="mono px-1.5 py-0.5 rounded border text-[11px]"
                      style={{
                        borderColor: u.is_active
                          ? "rgba(34, 197, 94, 0.4)"
                          : "rgba(239, 68, 68, 0.45)",
                        background: u.is_active ? "var(--ok-bg)" : "var(--crit-bg)",
                        color: u.is_active ? "var(--ok)" : "var(--crit)",
                      }}
                    >
                      {u.is_active ? "active" : "disabled"}
                    </span>
                  </td>
                  <td className="p-2.5 align-top mono" style={{ color: "var(--text-muted)" }}>
                    {u.active_session_count}
                  </td>
                  <td className="p-2.5 align-top mono text-[11px]" style={{ color: "var(--text-dim)" }}>
                    {u.last_login_at ?? "Never"}
                  </td>
                  <td className="p-2.5 align-top space-y-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <button
                        type="button"
                        disabled={updateMutation.isPending}
                        onClick={() =>
                          updateMutation.mutate({ userId: u.id, is_active: !u.is_active })
                        }
                        className="px-2 py-1 rounded border text-[11px]"
                        style={{
                          borderColor: "var(--border-strong)",
                          background: "var(--bg-elevated)",
                          color: "var(--text-main)",
                        }}
                      >
                        {u.is_active ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setResetTargetId(isResetting ? null : u.id);
                          setResetPasswordInput("");
                        }}
                        className="px-2 py-1 rounded border text-[11px] inline-flex items-center gap-1"
                        style={{
                          borderColor: "var(--border-strong)",
                          background: "var(--bg-elevated)",
                          color: "var(--accent)",
                        }}
                      >
                        <KeyRound className="w-3 h-3" />
                        Reset Password
                      </button>
                    </div>

                    {isResetting && (
                      <div className="flex items-center gap-1.5">
                        <input
                          type="password"
                          value={resetPasswordInput}
                          onChange={(e) => setResetPasswordInput(e.target.value)}
                          placeholder="New strong password…"
                          aria-label={`New password for ${u.email}`}
                          className="px-2 py-1 rounded border text-xs w-44"
                          style={{ background: "var(--bg-elevated)", borderColor: "var(--border)" }}
                        />
                        <button
                          type="button"
                          disabled={!resetPasswordInput || resetPwdMutation.isPending}
                          onClick={() =>
                            resetPwdMutation.mutate({
                              userId: u.id,
                              newPassword: resetPasswordInput,
                            })
                          }
                          className="px-2 py-1 rounded text-[11px] font-bold"
                          style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
                        >
                          Apply
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="mc-panel p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="mc-kicker flex items-center gap-1.5" style={{ color: "var(--accent)" }}>
            <Terminal className="w-3.5 h-3.5" />
            Data Retention Policy &amp; CLI Status
          </div>
          {retention && (
            <span className="mono text-[11px]" style={{ color: "var(--ok)" }}>
              audit_chain_preserved={String(retention.audit_chain_preserved)}
            </span>
          )}
        </div>

        {retention && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs mono">
            <div className="mc-elevated p-2">
              <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                Expired Sessions (&gt;{retention.policy_days.sessions_grace}d)
              </div>
              <div className="font-bold text-sm">{retention.counts.sessions}</div>
            </div>
            <div className="mc-elevated p-2">
              <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                Aged Runs (&gt;{retention.policy_days.scenario_runs}d)
              </div>
              <div className="font-bold text-sm">{retention.counts.scenario_runs}</div>
            </div>
            <div className="mc-elevated p-2">
              <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                Purgeable Snapshots (&gt;{retention.policy_days.snapshots}d)
              </div>
              <div className="font-bold text-sm">{retention.counts.snapshots}</div>
            </div>
            <div className="mc-elevated p-2">
              <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                Protected Snapshots
              </div>
              <div className="font-bold text-sm">{retention.counts.snapshots_protected_by_runs}</div>
            </div>
            <div className="mc-elevated p-2">
              <div className="text-[10px] uppercase" style={{ color: "var(--text-dim)" }}>
                Audit Archive (&gt;{retention.policy_days.audit_archive}d)
              </div>
              <div className="font-bold text-sm">{retention.counts.audit_events_ready_for_archive}</div>
            </div>
          </div>
        )}

        <pre
          className="mono text-[11px] p-2.5 rounded border overflow-x-auto"
          style={{
            background: "var(--bg-elevated)",
            borderColor: "var(--border)",
            color: "var(--text-muted)",
          }}
        >{`# Dry-run evaluation (read-only)\npython -m chaoslab run-retention\n\n# Apply retention purge (sessions, aged runs, unreferenced snapshots)\npython -m chaoslab run-retention --apply\n\n# Verify tamper-evident audit hash chain\npython -m chaoslab verify-audit`}</pre>
      </div>
    </div>
  );
}
