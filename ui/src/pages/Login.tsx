import { useState, type FormEvent } from "react";
import { useNavigate, useLocation } from "react-router-dom";

import { api, tokenStore } from "@/api/client";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const from = (location.state as { from?: string } | null)?.from ?? "/";

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const trimmed = token.trim();
    if (!trimmed) {
      setError("Token required.");
      setBusy(false);
      return;
    }
    tokenStore.set(trimmed);
    try {
      await api.health();
      navigate(from, { replace: true });
    } catch (e) {
      tokenStore.clear();
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-6">
      <form
        onSubmit={onSubmit}
        className="bg-white border rounded-lg shadow-sm p-6 w-full max-w-md space-y-4"
      >
        <div>
          <h1 className="text-lg font-semibold tracking-tight">AgentSploit</h1>
          <p className="text-sm text-slate-500 mt-1">
            Paste the bearer token printed by{" "}
            <code className="font-mono text-xs bg-slate-100 px-1 rounded">
              agentsploit serve
            </code>{" "}
            on startup.
          </p>
        </div>
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
            Token
          </span>
          <input
            type="password"
            autoFocus
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="mt-1 w-full font-mono text-xs border rounded px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-200"
            placeholder="agentsploit-..."
          />
        </label>
        {error && (
          <div className="text-sm text-red-600 bg-red-50 border border-red-100 rounded px-3 py-2">
            {error}
          </div>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full bg-slate-900 text-white text-sm font-medium rounded px-3 py-2 disabled:opacity-50"
        >
          {busy ? "Verifying..." : "Sign in"}
        </button>
        <div className="text-xs text-slate-400">
          The token is stored in browser localStorage. It's not synced anywhere.
        </div>
      </form>
    </div>
  );
}
