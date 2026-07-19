import type { ScanResponse } from "@/lib/scan-types";

export function ScanMetadata({ scan }: { scan: ScanResponse }) {
  const framework = technologyName(scan, "framework");
  const orm = technologyName(scan, "orm");
  const metadata = [
    ["Repository", scan.repository.name || "Unknown"],
    ["Framework", framework],
    ["ORM", orm],
    ["Routes detected by supported patterns", String(scan.analysis_summary.routes_analyzed)],
    ["Protected routes", String(scan.summary.protected_route_count)],
    ["Branch", scan.scan_metadata?.branch ?? "Unknown"],
    ["Deterministic scan duration", scan.scan_metadata ? `${scan.scan_metadata.deterministic_scan_duration_ms} ms` : "Unknown"],
    ["Scanner version", scan.scan_metadata?.scanner_version ?? "Unknown"],
  ];
  return <aside aria-labelledby="metadata-title" className="mt-6 rounded-xl border border-white/[.08] bg-[#0c141f] p-5"><p className="font-mono text-xs uppercase tracking-wider text-slate-500" id="metadata-title">Scan Metadata</p><dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{metadata.map(([label, value]) => <div className="min-w-0 rounded border border-white/[.08] bg-black/10 p-3" key={label}><dt className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{label}</dt><dd className="mt-1 break-words text-sm text-slate-200">{value}</dd></div>)}</dl><p className="mt-4 text-xs leading-5 text-slate-500">Sentinel reports only routes matched by its currently supported discovery patterns.</p></aside>;
}

function technologyName(scan: ScanResponse, category: string): string {
  return scan.technologies.find((technology) => technology.category === category)?.name ?? "Unknown";
}
