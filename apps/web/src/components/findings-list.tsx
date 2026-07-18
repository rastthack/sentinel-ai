"use client";

import { useMemo, useState } from "react";
import type { Finding, Severity } from "@/lib/scan-types";

export function FindingsList({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const filtered = useMemo(() => findings.filter((finding) => (severity === "all" || finding.severity === severity) && `${finding.rule_id} ${finding.title} ${finding.path}`.toLowerCase().includes(query.toLowerCase())), [findings, query, severity]);
  return <section className="mt-10" aria-labelledby="findings-title">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="font-mono text-xs uppercase tracking-[.16em] text-orange-200">Deterministic findings</p><h2 className="mt-2 text-2xl font-semibold" id="findings-title">Authorization review queue</h2></div><div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row"><input aria-label="Search findings" className="min-w-0 flex-1 rounded border border-white/[.12] bg-[#0c141f] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-300 sm:w-56" onChange={(event) => setQuery(event.target.value)} placeholder="Search findings" value={query} /><select aria-label="Filter severity" className="rounded border border-white/[.12] bg-[#0c141f] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-300" onChange={(event) => setSeverity(event.target.value as Severity | "all")} value={severity}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
    {filtered.length === 0 ? <p className="mt-5 rounded border border-white/[.08] p-5 text-sm text-slate-400">No findings match this review.</p> : <div className="mt-5 overflow-x-auto rounded-xl border border-white/[.08]" role="region" aria-label="Deterministic findings table" tabIndex={0}><table className="min-w-[760px] w-full table-fixed text-left text-sm"><thead className="bg-white/[.03] font-mono text-[10px] uppercase tracking-wider text-slate-500"><tr><th className="w-28 p-3">Severity</th><th className="w-32 p-3">Rule</th><th className="w-[28%] p-3">Finding</th><th className="w-[24%] p-3">Route</th><th className="w-28 p-3">Model</th><th className="w-20 p-3">Risk</th><th className="w-28 p-3">Confidence</th><th className="w-20 p-3">Status</th></tr></thead><tbody>{filtered.map((finding) => <tr className="border-t border-white/[.08] align-top" key={finding.finding_id}><td className="p-3"><SeverityBadge severity={finding.severity} /></td><td className="break-all p-3 font-mono text-xs text-slate-300">{finding.rule_id}</td><td className="p-3"><button aria-label={`Open finding ${finding.finding_id}`} className="break-words text-left text-emerald-200 underline-offset-4 hover:underline focus:outline-none focus:ring-2 focus:ring-emerald-300" onClick={() => onSelect(finding)} type="button"><span className="block font-medium">{finding.title}</span><span className="mt-1 block break-all font-mono text-[10px] text-slate-500">{finding.finding_id}</span></button></td><td className="break-words p-3 font-mono text-xs text-slate-300"><span className="font-semibold text-slate-100">{finding.method}</span> {finding.path}</td><td className="break-words p-3 text-slate-300">{finding.model ?? "Unknown"}</td><td className="p-3 font-semibold text-white">{finding.risk_score}</td><td className="p-3 text-slate-300">{Math.round(finding.confidence * 100)}%</td><td className="p-3"><span className="rounded border border-emerald-300/30 px-2 py-1 text-xs text-emerald-100">Open</span></td></tr>)}</tbody></table></div>}
  </section>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles = {
    critical: "border-rose-300/40 bg-rose-300/10 text-rose-100",
    high: "border-orange-300/40 bg-orange-300/10 text-orange-100",
    medium: "border-amber-300/40 bg-amber-300/10 text-amber-100",
    low: "border-sky-300/40 bg-sky-300/10 text-sky-100",
    informational: "border-slate-300/30 bg-slate-300/10 text-slate-100",
  }[severity];
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold capitalize ${styles}`}>{severity}</span>;
}
