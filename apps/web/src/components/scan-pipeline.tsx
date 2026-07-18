const stages = [
  "Repository",
  "Discovery",
  "Deterministic Analysis",
  "Evidence Package",
  "AI Security Review",
];

export function ScanPipeline() {
  return <section aria-label="Completed scan pipeline" className="mb-6 rounded-xl border border-white/[.08] bg-[#0c141f] p-4"><p className="font-mono text-xs uppercase tracking-wider text-slate-500">Completed scan pipeline</p><ol className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">{stages.map((stage, index) => <li className="flex min-w-0 items-center gap-2 rounded border border-emerald-300/20 bg-emerald-300/[.04] px-3 py-2 text-xs text-slate-200" key={stage}><span aria-label={`${stage} completed`} className="grid size-5 shrink-0 place-items-center rounded-full bg-emerald-300 font-semibold text-slate-950">✓</span><span className="break-words">{stage}</span>{index < stages.length - 1 ? <span aria-hidden="true" className="ml-auto hidden text-emerald-200 lg:block">↓</span> : null}</li>)}</ol></section>;
}
