import { ApiStatus } from "@/components/api-status";
import { ApplicationStructure } from "@/components/application-structure";

const workflow = [
  {
    number: "01",
    title: "Find it",
    copy: "Map the application and identify an authorization weakness.",
  },
  {
    number: "02",
    title: "Prove it",
    copy: "Reproduce cross-user access with controlled identities and HTTP evidence.",
  },
  {
    number: "03",
    title: "Fix it",
    copy: "Propose an ownership-enforcement patch for human review.",
  },
  {
    number: "04",
    title: "Verify it",
    copy: "Apply only to a temporary copy and repeat the original attack.",
  },
] as const;

export default function Home() {
  return (
    <main className="min-h-screen overflow-hidden">
      <div className="noise" aria-hidden="true" />
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-7 lg:px-10">
        <a className="flex items-center gap-3" href="#top" aria-label="Sentinel AI home">
          <span className="grid size-9 place-items-center rounded-lg border border-emerald-300/40 bg-emerald-300/10 text-emerald-300">
            S
          </span>
          <span className="font-mono text-sm font-semibold uppercase tracking-[0.2em] text-slate-100">
            Sentinel AI
          </span>
        </a>
        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-slate-400">
          Foundation / 0.1
        </span>
      </nav>

      <section id="top" className="mx-auto grid max-w-7xl gap-14 px-6 pb-20 pt-16 lg:grid-cols-[1.25fr_0.75fr] lg:px-10 lg:pb-28 lg:pt-24">
        <div>
          <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-emerald-300/20 bg-emerald-300/[0.06] px-3 py-1.5 font-mono text-xs text-emerald-300">
            <span className="size-1.5 rounded-full bg-emerald-300 shadow-[0_0_12px_#6ee7b7]" />
            Evidence, not guesses
          </div>
          <h1 className="max-w-4xl text-balance text-5xl font-semibold leading-[0.98] tracking-[-0.055em] text-white sm:text-7xl lg:text-[5.7rem]">
            Security review that closes the loop.
          </h1>
          <p className="mt-8 max-w-2xl text-lg leading-8 text-slate-400 sm:text-xl">
            Sentinel AI finds broken authorization in AI-generated web apps, proves the impact safely, proposes a focused fix, and verifies the result.
          </p>
          <p className="mt-10 font-mono text-sm uppercase tracking-[0.16em] text-slate-200">
            <span className="text-emerald-300">Find it.</span> Prove it. Fix it. Verify it.
          </p>
        </div>

        <div className="flex items-end lg:justify-end">
          <ApiStatus />
        </div>
      </section>

      <ApplicationStructure />

      <section className="border-y border-white/[0.07] bg-slate-950/40">
        <div className="mx-auto max-w-7xl px-6 py-20 lg:px-10">
          <div className="mb-10 flex items-end justify-between gap-6">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.2em] text-emerald-300">The review loop</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">From finding to verified remediation</h2>
            </div>
            <span className="hidden font-mono text-xs text-slate-600 sm:block">CONTROLLED TARGETS ONLY</span>
          </div>
          <ol className="grid overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.025] md:grid-cols-2 lg:grid-cols-4">
            {workflow.map((step) => (
              <li className="group border-b border-white/[0.08] p-6 last:border-0 md:border-r lg:border-b-0" key={step.number}>
                <span className="font-mono text-xs text-slate-600 transition-colors group-hover:text-emerald-300">{step.number}</span>
                <h3 className="mt-10 text-xl font-semibold text-slate-100">{step.title}</h3>
                <p className="mt-3 text-sm leading-6 text-slate-500">{step.copy}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <footer className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-10 font-mono text-[11px] uppercase tracking-[0.14em] text-slate-600 sm:flex-row sm:items-center sm:justify-between lg:px-10">
        <span>Built for safe, reviewable validation</span>
        <span>No production targets · No autonomous patches</span>
      </footer>
    </main>
  );
}
