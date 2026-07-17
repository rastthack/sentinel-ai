"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { ApiStatus } from "./api-status";

type Destination = "overview" | "review" | "architecture";

function navigate(destination: Destination): void {
  window.dispatchEvent(new CustomEvent<Destination>("sentinel:navigate", { detail: destination }));
}

export function AppShell({ children }: { children: ReactNode }) {
  return <main className="min-h-screen"><div className="noise" aria-hidden="true" /><header className="sticky top-0 z-10 border-b border-white/[.08] bg-[#07101a]/95 backdrop-blur"><nav aria-label="Primary navigation" className="mx-auto flex max-w-7xl items-center justify-between gap-5 px-5 py-4 lg:px-8"><Link aria-label="Sentinel AI overview" className="flex items-center gap-3 text-left" href="/"><span className="grid size-8 place-items-center rounded border border-emerald-300/40 text-emerald-300">S</span><span><b className="font-mono text-sm uppercase tracking-[.16em]">Sentinel AI</b><small className="ml-3 hidden text-xs text-slate-500 sm:inline">AI Security Code Review</small></span></Link><div className="hidden gap-5 text-sm text-slate-400 md:flex"><Link className="focus:outline-none focus:ring-2 focus:ring-emerald-300" href="/">Overview</Link>{(["review", "architecture"] as const).map((item) => <button className="focus:outline-none focus:ring-2 focus:ring-emerald-300" key={item} onClick={() => navigate(item)} type="button">{item === "review" ? "Security Review" : "Architecture"}</button>)}</div><ApiStatus compact /></nav></header>{children}</main>;
}
