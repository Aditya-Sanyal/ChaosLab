import { useState, type FormEvent } from "react";
import { ShieldAlert, Lock } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { UserResponse } from "../api/types";

interface LoginViewProps {
  onSuccess: (user: UserResponse) => void;
}

const DEMO_ACCOUNTS = [
  { label: "Analyst", email: "analyst@meridian.example", pass: "ChaosAnalyst!2026" },
  { label: "Viewer", email: "viewer@meridian.example", pass: "ChaosViewer!2026" },
  { label: "Admin", email: "admin@meridian.example", pass: "ChaosAdmin!2026" },
] as const;

export function LoginView({ onSuccess }: LoginViewProps) {
  const [email, setEmail] = useState("analyst@meridian.example");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      const user = await api.login(email, password);
      onSuccess(user);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Sign-in failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 mc-grid-bg" style={{ background: "var(--bg-app)" }}>
      <div className="w-full max-w-md mc-panel p-6 space-y-5">
        <div className="flex items-center justify-between gap-2 border-b pb-4" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-2.5">
            <span
              className="w-8 h-8 inline-flex items-center justify-center font-bold mono text-sm border rounded"
              style={{
                background: "var(--accent-soft)",
                color: "var(--accent)",
                borderColor: "var(--accent-border)",
              }}
            >
              CL
            </span>
            <div>
              <h1 className="text-base font-bold tracking-tight">CHAOS LAB</h1>
              <div className="text-xs" style={{ color: "var(--text-dim)" }}>
                Mission Control · Security Operations Console
              </div>
            </div>
          </div>
          <span
            className="text-xs font-semibold px-2 py-1 border rounded inline-flex items-center gap-1.5"
            style={{
              background: "var(--ok-bg)",
              color: "var(--ok)",
              borderColor: "rgba(34, 197, 94, 0.35)",
            }}
          >
            <span className="w-2 h-2 rounded-full" style={{ background: "var(--ok)" }} />
            OFFLINE SIMULATION
          </span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="login-email" className="block mc-kicker" style={{ color: "var(--text-muted)" }}>
              Operator Email
            </label>
            <input
              id="login-email"
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 text-xs mc-elevated focus:outline-none"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="login-password" className="block mc-kicker" style={{ color: "var(--text-muted)" }}>
              Password
            </label>
            <input
              id="login-password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter local password"
              className="w-full px-3 py-2 text-xs mc-elevated focus:outline-none"
              style={{ color: "var(--text-main)", borderColor: "var(--border-strong)" }}
            />
          </div>

          {error && (
            <div
              role="alert"
              className="p-2.5 text-xs border rounded flex items-center gap-2"
              style={{
                background: "var(--crit-bg)",
                color: "var(--crit)",
                borderColor: "rgba(239, 68, 68, 0.45)",
              }}
            >
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={pending}
            className="w-full py-2 px-4 text-xs font-bold uppercase tracking-wider rounded flex items-center justify-center gap-2 transition disabled:opacity-60"
            style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
          >
            <Lock className="w-3.5 h-3.5" />
            {pending ? "Authenticating…" : "Sign In to Operations Console"}
          </button>
        </form>

        <div className="border-t pt-4 space-y-2" style={{ borderColor: "var(--border)" }}>
          <div className="mc-kicker" style={{ color: "var(--text-dim)" }}>
            Synthetic demo quick-fill (local dev accounts)
          </div>
          <div className="grid grid-cols-3 gap-2">
            {DEMO_ACCOUNTS.map((acct) => (
              <button
                key={acct.label}
                type="button"
                onClick={() => {
                  setEmail(acct.email);
                  setPassword(acct.pass);
                  setError(null);
                }}
                className="px-2 py-1.5 text-xs mc-elevated hover:opacity-90 font-semibold transition"
                style={{ color: "var(--text-muted)", borderColor: "var(--border-strong)" }}
              >
                {acct.label}
              </button>
            ))}
          </div>
          <p className="text-xs" style={{ color: "var(--text-dim)" }}>
            Simulations operate strictly on imported or synthetic snapshots. No live systems are contacted.
          </p>
        </div>
      </div>
    </div>
  );
}
