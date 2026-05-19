import { useEffect, useState, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { api, AuthError, tokenStore } from "@/api/client";

type Phase = "checking" | "ok" | "no-auth";

/**
 * Probe /api/health on mount to figure out if auth is required.
 *
 * - 200 with a token, or 200 without a token (server in --no-auth mode):
 *   we render children.
 * - 401/403 without a token (or with a bad token): redirect to /login.
 *
 * This avoids a redirect loop when the server is in --no-auth mode but
 * we still have an old token in localStorage from a previous session.
 */
export default function RequireAuth({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>("checking");
  const location = useLocation();

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        await api.health();
        if (live) setPhase("ok");
      } catch (e) {
        if (!live) return;
        if (e instanceof AuthError) {
          tokenStore.clear();
          setPhase("no-auth");
        } else {
          setPhase("ok"); // network/other error - let downstream handle it
        }
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  if (phase === "checking")
    return (
      <div className="min-h-screen flex items-center justify-center text-slate-400 text-sm">
        Connecting...
      </div>
    );
  if (phase === "no-auth")
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  return <>{children}</>;
}
