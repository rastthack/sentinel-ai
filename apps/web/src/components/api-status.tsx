"use client";

import { useCallback, useEffect, useState } from "react";

type HealthResponse = {
  service: string;
  status: "ok";
  version: string;
};

type CheckState =
  | { state: "checking" }
  | { state: "online"; health: HealthResponse }
  | { state: "offline" };

async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch("/api/health", { cache: "no-store" });
  if (!response.ok) throw new Error("Health check failed");

  return (await response.json()) as HealthResponse;
}

export function ApiStatus({ compact = false }: { compact?: boolean }) {
  const [check, setCheck] = useState<CheckState>({ state: "checking" });

  const checkHealth = useCallback(async () => {
    setCheck({ state: "checking" });

    try {
      const health = await fetchHealth();
      setCheck({ state: "online", health });
    } catch {
      setCheck({ state: "offline" });
    }
  }, []);

  useEffect(() => {
    let active = true;

    void fetchHealth().then(
      (health) => {
        if (active) setCheck({ state: "online", health });
      },
      () => {
        if (active) setCheck({ state: "offline" });
      },
    );

    return () => {
      active = false;
    };
  }, []);

  const online = check.state === "online";

  if (compact) return <span className="flex items-center gap-2 text-xs text-slate-400" role="status" aria-live="polite"><span className={`size-2 rounded-full ${online ? "bg-emerald-300" : check.state === "checking" ? "bg-amber-300" : "bg-rose-400"}`} />{online ? "Backend connected" : check.state === "checking" ? "Checking backend" : "Backend unavailable"}</span>;
  return (
    <aside className="w-full max-w-md rounded-2xl border border-white/10 bg-[#111a27]/80 p-1 shadow-2xl shadow-black/20 backdrop-blur">
      <div className="rounded-[0.8rem] border border-white/[0.06] bg-[#0c141f] p-6">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs uppercase tracking-[0.16em] text-slate-500">System link</span>
          <span
            className={`size-2 rounded-full ${online ? "bg-emerald-300 shadow-[0_0_12px_#6ee7b7]" : check.state === "checking" ? "animate-pulse bg-amber-300" : "bg-rose-400"}`}
            aria-hidden="true"
          />
        </div>
        <div className="mt-12 flex items-end justify-between gap-4">
          <div>
            <p className="text-sm text-slate-500">FastAPI service</p>
            <p className="mt-1 text-2xl font-semibold text-slate-100" role="status" aria-live="polite">
              {online ? "Connected" : check.state === "checking" ? "Checking…" : "Unavailable"}
            </p>
          </div>
          {check.state === "online" ? (
            <span className="font-mono text-xs text-emerald-300">v{check.health.version}</span>
          ) : check.state === "offline" ? (
            <button className="rounded-lg border border-white/10 px-3 py-2 font-mono text-xs text-slate-300 transition hover:border-emerald-300/40 hover:text-emerald-300" onClick={() => void checkHealth()} type="button">
              Retry
            </button>
          ) : null}
        </div>
        <div className="mt-6 h-px bg-gradient-to-r from-emerald-300/50 via-emerald-300/10 to-transparent" />
        <p className="mt-4 font-mono text-[11px] leading-5 text-slate-600">GET /api/health → API /health</p>
      </div>
    </aside>
  );
}
