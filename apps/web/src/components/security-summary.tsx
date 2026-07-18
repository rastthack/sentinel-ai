import type { ScanResponse, Severity } from "@/lib/scan-types";

const severityOrder: Array<{ label: string; value: keyof ScanResponse["summary"]; severity: Severity }> = [
  { label: "Critical", value: "critical_finding_count", severity: "critical" },
  { label: "High", value: "high_finding_count", severity: "high" },
  { label: "Medium", value: "medium_finding_count", severity: "medium" },
  { label: "Low", value: "low_finding_count", severity: "low" },
];

export function SecuritySummary({ scan }: { scan: ScanResponse }) {
  const risk = overallRisk(scan);
  return <section id="review" aria-labelledby="review-title">
    <div className="rounded-2xl border border-white/[.1] bg-[#0c141f]/90 p-5 shadow-2xl shadow-black/10 sm:p-7">
      <div className="flex flex-wrap items-start justify-between gap-5">
        <div className="min-w-0"><p className="font-mono text-xs uppercase tracking-[.16em] text-emerald-300">Deterministic security review</p><h2 className="mt-2 break-words text-3xl font-semibold tracking-tight sm:text-4xl" id="review-title">{scan.repository.name}</h2><p className="mt-2 text-sm text-slate-400">Authorization analysis results. These findings are the security record.</p></div>
        <RiskBadge risk={risk} />
      </div>
      <div className="mt-7 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Metric label="Total findings" value={scan.summary.finding_count} emphasis />
        {severityOrder.map(({ label, value, severity }) => <Metric key={label} label={label} severity={severity} value={scan.summary[value] as number} />)}
      </div>
      <dl className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-white/[.08] bg-white/[.08] sm:grid-cols-3 lg:grid-cols-5">
        <Metric label="Routes analyzed" value={scan.analysis_summary.routes_analyzed} compact />
        <Metric label="Protected routes" value={scan.summary.protected_route_count} compact />
        <Metric label="Public routes" value={scan.summary.public_route_count} compact />
        <Metric label="Prisma models" value={scan.summary.prisma_model_count} compact />
        <Metric label="Mapped routes" value={scan.summary.mapped_route_count} compact />
      </dl>
      <div className="mt-5 flex flex-wrap items-center gap-2"><span className="font-mono text-xs uppercase tracking-wider text-slate-500">Detected stack</span>{scan.technologies.map((technology) => <span className="max-w-full break-words rounded-full border border-white/[.1] px-2.5 py-1 text-xs text-slate-300" key={technology.name}>{technology.name}</span>)}</div>
    </div>
  </section>;
}

function overallRisk(scan: ScanResponse): "critical" | "high" | "medium" | "low" {
  if (scan.summary.critical_finding_count > 0) return "critical";
  if (scan.summary.high_finding_count > 0) return "high";
  if (scan.summary.medium_finding_count > 0) return "medium";
  return "low";
}

function RiskBadge({ risk }: { risk: ReturnType<typeof overallRisk> }) {
  const styles = {
    critical: "border-rose-200/50 bg-rose-300/15 text-rose-100",
    high: "border-orange-200/50 bg-orange-300/15 text-orange-100",
    medium: "border-amber-200/50 bg-amber-300/15 text-amber-100",
    low: "border-emerald-200/50 bg-emerald-300/15 text-emerald-100",
  }[risk];
  return <span className={`rounded-full border px-4 py-2 font-mono text-xs font-semibold uppercase tracking-wider ${styles}`}>Overall risk: {risk}</span>;
}

function Metric({ label, value, severity, emphasis = false, compact = false }: { label: string; value: number; severity?: Severity; emphasis?: boolean; compact?: boolean }) {
  const styles = severity ? severityStyles(severity) : "border-white/[.08] bg-[#0a131e]";
  return <div className={`min-w-0 border p-4 ${styles} ${compact ? "bg-[#0c141f]" : "rounded-xl"}`}>
    <dt className="font-mono text-[10px] uppercase tracking-wider text-slate-400">{label}</dt>
    <dd className={`mt-2 font-semibold text-white ${emphasis ? "text-3xl" : "text-2xl"}`}>{value}</dd>
  </div>;
}

function severityStyles(severity: Severity): string {
  return {
    critical: "border-rose-300/30 bg-rose-300/[.07]",
    high: "border-orange-300/30 bg-orange-300/[.07]",
    medium: "border-amber-300/30 bg-amber-300/[.07]",
    low: "border-sky-300/30 bg-sky-300/[.07]",
    informational: "border-slate-300/20 bg-slate-300/[.04]",
  }[severity];
}
