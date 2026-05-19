import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api, tokenStore } from "@/api/client";
import { useSSE } from "@/hooks/useSSE";

export default function Layout() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: api.health });
  const { connected } = useSSE();

  function navItem(to: string, label: string) {
    const active = pathname === to || (to !== "/" && pathname.startsWith(to));
    return (
      <Link
        to={to}
        className={
          active
            ? "text-slate-900 font-medium"
            : "text-slate-500 hover:text-slate-700"
        }
      >
        {label}
      </Link>
    );
  }

  function signOut() {
    tokenStore.clear();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex flex-col h-full">
      <header className="border-b bg-white px-6 py-3 flex items-baseline gap-6">
        <Link to="/" className="font-bold text-lg tracking-tight">
          AgentSploit
        </Link>
        <nav className="flex gap-4 text-sm">
          {navItem("/", "Sessions")}
          {navItem("/jobs", "Jobs")}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-xs text-slate-500">
          <span
            className={
              "inline-flex items-center gap-1.5 " +
              (connected ? "text-emerald-600" : "text-slate-400")
            }
            title={connected ? "live event stream connected" : "event stream offline"}
          >
            <span
              className={
                "inline-block w-2 h-2 rounded-full " +
                (connected ? "bg-emerald-500" : "bg-slate-300")
              }
            />
            {connected ? "live" : "offline"}
          </span>
          {health ? (
            <>
              v{health.version} - <span className="font-mono">{health.engagement_dir}</span>
            </>
          ) : (
            "loading..."
          )}
          <button
            onClick={signOut}
            className="text-slate-400 hover:text-slate-700"
            title="Forget local token"
          >
            sign out
          </button>
        </div>
      </header>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
