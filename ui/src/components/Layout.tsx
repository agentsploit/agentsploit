import { Link, Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export default function Layout() {
  const { pathname } = useLocation();
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: api.health });

  return (
    <div className="flex flex-col h-full">
      <header className="border-b bg-white px-6 py-3 flex items-baseline gap-6">
        <Link to="/" className="font-bold text-lg tracking-tight">
          AgentSploit
        </Link>
        <nav className="flex gap-4 text-sm">
          <Link
            to="/"
            className={
              pathname === "/" ? "text-slate-900 font-medium" : "text-slate-500 hover:text-slate-700"
            }
          >
            Sessions
          </Link>
        </nav>
        <div className="ml-auto text-xs text-slate-500">
          {health ? (
            <>
              v{health.version} - <span className="font-mono">{health.engagement_dir}</span>
            </>
          ) : (
            "loading..."
          )}
        </div>
      </header>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
