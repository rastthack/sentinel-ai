"use client";

import type { ReactNode } from "react";
import { ApiStatus } from "./api-status";

type Destination = "overview" | "review" | "architecture";

export function navigate(destination: Destination): void {
  window.dispatchEvent(new CustomEvent<Destination>("sentinel:navigate", { detail: destination }));
}

export function AppShell({ children }: { children: ReactNode }) {
  return <main className="min-h-screen"><div className="noise" aria-hidden="true" /><header className="sticky top-0 z-10 border-b border-white/[.08] bg-[#07101a]/95 backdrop-blur"><nav aria-label="Primary navigation" className="mx-auto flex max-w-7xl items-center justify-between gap-5 px-5 py-4 lg:px-8"><div className="flex min-w-0 items-center gap-3"><button aria-label="Return to Sentinel AI dashboard" className="flex shrink-0 cursor-pointer items-center gap-3 rounded text-left focus:outline-none focus:ring-2 focus:ring-emerald-300" onClick={() => navigate("overview")} type="button"><span className="grid size-8 place-items-center rounded border border-emerald-300/40 text-emerald-300">S</span><b className="font-mono text-sm uppercase tracking-[.16em]">Sentinel AI</b></button><small className="hidden select-none text-xs text-slate-500 sm:inline">AI Security Code Review</small></div><div className="hidden gap-1 text-sm text-slate-400 md:flex">{(["overview", "review", "architecture"] as const).map((item) => <button className="cursor-pointer rounded px-2 py-1.5 transition hover:text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-300" key={item} onClick={() => navigate(item)} type="button">{item === "overview" ? "Overview" : item === "review" ? "Security Review" : "Architecture"}</button>)}</div><ApiStatus compact /></nav></header>{children}</main>;
}
