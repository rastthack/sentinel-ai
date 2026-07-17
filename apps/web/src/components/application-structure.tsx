"use client";

import { useState } from "react";

type Route = {
  route_id: string;
  method: string;
  path: string;
  authentication_required: boolean | "unknown";
  middlewares: string[];
};

type Mapping = {
  route_id: string;
  model: string;
  operation: string;
};

type Model = {
  name: string;
  primary_key: string[];
};

type OwnershipCandidate = {
  model: string;
  field: string;
  candidate_type: string;
};

type ScanResponse = {
  repository: { name: string };
  summary: {
    route_count: number;
    protected_route_count: number;
    public_route_count: number;
    prisma_model_count: number;
  };
  routes: Route[];
  data_model: {
    models: Model[];
    ownership_candidates: OwnershipCandidate[];
  };
  route_model_mappings: Mapping[];
};

type ScanState =
  | { state: "idle" }
  | { state: "loading" }
  | { state: "error" }
  | { state: "ready"; scan: ScanResponse };

function authenticationLabel(value: Route["authentication_required"]): string {
  if (value === true) return "Protected";
  if (value === false) return "Public";
  return "Unknown";
}

export function ApplicationStructure() {
  const [result, setResult] = useState<ScanState>({ state: "idle" });

  async function runScan(): Promise<void> {
    setResult({ state: "loading" });
    try {
      const response = await fetch("/api/scans/demo", { cache: "no-store" });
      if (!response.ok) throw new Error("Scan request failed");
      setResult({ state: "ready", scan: (await response.json()) as ScanResponse });
    } catch {
      setResult({ state: "error" });
    }
  }

  const scan = result.state === "ready" ? result.scan : null;

  return (
    <section className="border-y border-white/[0.07] bg-slate-950/40">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-10">
        <div className="flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-emerald-300">
              Application Structure Discovery
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">
              Map the bundled TaskFlow AI demo
            </h2>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-500">
              Static, deterministic discovery of Express routes, authentication middleware,
              and Prisma models. The target application is never started.
            </p>
          </div>
          <button
            className="rounded-xl border border-emerald-300/30 bg-emerald-300/10 px-5 py-3 font-mono text-xs uppercase tracking-[0.12em] text-emerald-300 transition hover:bg-emerald-300/15 disabled:cursor-wait disabled:opacity-60"
            disabled={result.state === "loading"}
            onClick={() => void runScan()}
            type="button"
          >
            {result.state === "loading" ? "Scanning source…" : "Scan bundled demo"}
          </button>
        </div>

        {result.state === "error" ? (
          <p className="mt-8 rounded-xl border border-rose-400/20 bg-rose-400/5 p-4 text-sm text-rose-300" role="alert">
            Structure discovery is unavailable. Confirm the Sentinel API is running and retry.
          </p>
        ) : null}

        {scan ? (
          <div className="mt-10 space-y-6">
            <div className="grid gap-px overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.08] sm:grid-cols-4">
              {[
                ["Routes", scan.summary.route_count],
                ["Protected", scan.summary.protected_route_count],
                ["Public", scan.summary.public_route_count],
                ["Models", scan.summary.prisma_model_count],
              ].map(([label, value]) => (
                <div className="bg-[#0c141f] p-5" key={label}>
                  <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">{label}</p>
                  <p className="mt-2 text-2xl font-semibold text-slate-100">{value}</p>
                </div>
              ))}
            </div>

            <div className="overflow-x-auto rounded-xl border border-white/[0.08] bg-[#0c141f]">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-white/[0.08] font-mono text-[10px] uppercase tracking-[0.14em] text-slate-600">
                  <tr>
                    <th className="p-4 font-normal">Method</th>
                    <th className="p-4 font-normal">Route</th>
                    <th className="p-4 font-normal">Authentication</th>
                    <th className="p-4 font-normal">Middleware</th>
                    <th className="p-4 font-normal">Data access</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {scan.routes.map((route) => {
                    const mappings = scan.route_model_mappings.filter(
                      (mapping) => mapping.route_id === route.route_id,
                    );
                    return (
                      <tr key={route.route_id}>
                        <td className="p-4 font-mono text-xs text-emerald-300">{route.method}</td>
                        <td className="p-4 font-mono text-xs text-slate-200">{route.path}</td>
                        <td className="p-4 text-slate-400">
                          {authenticationLabel(route.authentication_required)}
                        </td>
                        <td className="p-4 text-slate-500">{route.middlewares.join(", ") || "—"}</td>
                        <td className="p-4 text-slate-400">
                          {mappings.map((mapping) => `${mapping.model}.${mapping.operation}`).join(", ") || "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-xl border border-white/[0.08] bg-[#0c141f] p-5">
                <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-slate-400">Prisma models</h3>
                <ul className="mt-4 grid gap-2 sm:grid-cols-2">
                  {scan.data_model.models.map((model) => (
                    <li className="rounded-lg border border-white/[0.06] px-3 py-2 text-sm text-slate-300" key={model.name}>
                      {model.name} <span className="text-slate-600">· key {model.primary_key.join(", ")}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="rounded-xl border border-white/[0.08] bg-[#0c141f] p-5">
                <h3 className="font-mono text-xs uppercase tracking-[0.16em] text-slate-400">Ownership candidates</h3>
                <ul className="mt-4 space-y-2">
                  {scan.data_model.ownership_candidates.map((candidate) => (
                    <li className="rounded-lg border border-white/[0.06] px-3 py-2 text-sm text-slate-300" key={`${candidate.model}.${candidate.field}`}>
                      {candidate.model}.{candidate.field} <span className="text-slate-600">· {candidate.candidate_type}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}
