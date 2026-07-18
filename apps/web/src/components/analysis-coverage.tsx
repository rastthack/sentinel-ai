const supported = [
  "Route and authentication discovery",
  "Prisma model mapping",
  "Ownership validation",
  "BOLA / IDOR detection",
  "Hardcoded secrets",
  "Dangerous CORS",
  "Weak JWT configuration",
  "Missing rate limiting",
  "Open redirect",
  "Path traversal",
  "Command injection",
  "Unsafe file upload",
];

const planned = [
  "SQL Injection",
  "Cross-Site Scripting (XSS)",
  "Server-Side Request Forgery (SSRF)",
  "Broader OWASP API Top 10 coverage",
];

export function AnalysisCoverage() {
  return <aside aria-labelledby="coverage-title" className="mt-6 rounded-xl border border-white/[.08] bg-[#0c141f] p-5"><p className="font-mono text-xs uppercase tracking-wider text-slate-500" id="coverage-title">Current Analysis Coverage</p><div className="mt-4 grid gap-5 lg:grid-cols-[2fr_1fr]"><CoverageList items={supported} title="Supported Today" symbol="✓" columns /><CoverageList items={planned} title="Planned / Experimental" symbol="○" subdued /></div><p className="mt-4 text-xs leading-5 text-slate-500">Coverage is intentionally conservative and currently focused on direct, high-confidence JavaScript/TypeScript patterns. Planned coverage is future work.</p></aside>;
}

function CoverageList({ items, title, symbol, subdued = false, columns = false }: { items: string[]; title: string; symbol: string; subdued?: boolean; columns?: boolean }) {
  return <div><h3 className={`font-mono text-xs uppercase tracking-wider ${subdued ? "text-slate-500" : "text-emerald-200"}`}>{title}</h3><ul className={`mt-3 space-y-2 text-sm text-slate-300 ${columns ? "sm:grid sm:grid-cols-2 sm:gap-x-4 sm:space-y-0" : ""}`}>{items.map((item) => <li className="flex gap-2 py-1" key={item}><span className={subdued ? "text-slate-500" : "text-emerald-300"}>{symbol}</span><span>{item}</span></li>)}</ul></div>;
}
