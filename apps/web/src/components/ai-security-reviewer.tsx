"use client";

import type { AIReviewerResponse, ReviewerConfidence } from "@/lib/scan-types";

export type ReviewerPanelState =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "ready"; review: AIReviewerResponse };

export function AISecurityReviewer({
  state,
  onRetry,
}: {
  state: ReviewerPanelState;
  onRetry: () => void;
}) {
  return (
    <section
      aria-labelledby="ai-reviewer-title"
      className="mt-10 overflow-hidden rounded-xl border border-violet-300/20 bg-violet-300/[.04] p-5 sm:p-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-[.16em] text-violet-200">Optional reviewer</p>
          <h2 className="mt-2 text-2xl font-semibold" id="ai-reviewer-title">AI Security Reviewer</h2>
        </div>
        {state.kind === "ready" ? <ModeBadge review={state.review} /> : null}
      </div>
      <p className="mt-3 text-sm text-amber-100">AI-generated guidance. Review before applying.</p>
      {state.kind === "loading" ? <p aria-live="polite" className="mt-5 text-sm text-violet-100">Generating security review from the completed deterministic evidence package…</p> : null}
      {state.kind === "unavailable" ? <UnavailableReview onRetry={onRetry} /> : null}
      {state.kind === "ready" ? <ReviewContent review={state.review} /> : null}
    </section>
  );
}

function UnavailableReview({ onRetry }: { onRetry: () => void }) {
  return <div className="mt-5 rounded border border-white/10 bg-black/10 p-4 text-sm text-slate-300" role="status">
    <p>The optional reviewer is currently unavailable. Deterministic findings remain the security record.</p>
    <button className="mt-3 rounded border border-white/20 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-violet-200" onClick={onRetry} type="button">Retry reviewer</button>
  </div>;
}

function ModeBadge({ review }: { review: AIReviewerResponse }) {
  const label = review.model === "sentinel-demo-reviewer" ? "Deterministic Demo" : "Live AI";
  return <span className="rounded-full border border-violet-200/30 px-3 py-1 font-mono text-xs uppercase tracking-wider text-violet-100">{label}</span>;
}

function ReviewContent({ review }: { review: AIReviewerResponse }) {
  return <div className="mt-6 space-y-7 text-sm leading-6 text-slate-300">
    {review.executive_summary ? <ExecutiveSummary review={review} /> : null}
    <div>
      <p className="font-mono text-xs uppercase tracking-wider text-violet-200">Priority Queue</p>
      <div className="mt-3 space-y-3">
        {review.prioritized_findings.map((finding, index) => <details className="overflow-hidden rounded border border-white/10 bg-black/10" key={finding.finding_id} open={index === 0}>
          <summary className="flex cursor-pointer items-center gap-3 p-4 font-semibold text-white focus:outline-none focus:ring-2 focus:ring-inset focus:ring-violet-200">
            <span aria-label={`Queue position ${index + 1}`} className="grid size-7 shrink-0 place-items-center rounded-full bg-violet-300 text-xs font-bold text-slate-950">{index + 1}</span>
            <span className="min-w-0 break-all">{finding.finding_id}</span>
            <span className="ml-auto shrink-0 text-xs font-normal text-slate-400">Priority {finding.priority} · {humanConfidence(finding.confidence)}</span>
          </summary>
          <div className="border-t border-white/10 p-4"><p>{finding.rationale}</p><ReviewerFacts finding={finding} /></div>
        </details>)}
      </div>
    </div>
    <aside className="border-t border-white/10 pt-5 text-xs leading-5 text-slate-500">
      <p className="font-mono uppercase tracking-wider">Limitations</p>
      <ul className="mt-2 list-disc space-y-1 pl-5">{review.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
    </aside>
  </div>;
}

function ExecutiveSummary({ review }: { review: AIReviewerResponse }) {
  const summary = review.executive_summary;
  if (!summary) return null;
  return <div className="rounded-lg border border-violet-200/20 bg-[#0c141f]/70 p-4 sm:p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><p className="font-mono text-xs uppercase tracking-wider text-violet-200">Executive Summary</p><RiskBadge risk={summary.overall_risk} /></div>
    <p className="mt-3 text-base text-slate-100">{summary.summary}</p>
    <ul className="mt-3 list-disc space-y-1 pl-5 text-slate-300">{summary.key_takeaways.map((item) => <li key={item}>{item}</li>)}</ul>
  </div>;
}

function RiskBadge({ risk }: { risk: ReviewerConfidence }) {
  const classes = {
    high: "border-rose-300/40 bg-rose-300/10 text-rose-100",
    medium: "border-amber-300/40 bg-amber-300/10 text-amber-100",
    low: "border-emerald-300/40 bg-emerald-300/10 text-emerald-100",
  }[risk];
  return <span className={`rounded-full border px-3 py-1 font-mono text-xs uppercase tracking-wider ${classes}`}>Overall risk: {risk}</span>;
}

function ReviewerFacts({ finding }: { finding: AIReviewerResponse["prioritized_findings"][number] }) {
  const facts = [["Root Cause", finding.root_cause], ["Attack Scenario", finding.attack_scenario], ["Business Impact", finding.business_impact], ["Secure Recommendation", finding.secure_recommendation]];
  return <div className="mt-5 space-y-4">{facts.map(([label, value]) => <div key={label}><h4 className="font-mono text-xs uppercase tracking-wider text-slate-500">{label}</h4><p className="mt-1 break-words">{value}</p></div>)}<PatchProposals proposals={finding.patch_proposals} /><EvidenceUsed references={finding.evidence_references} /></div>;
}

function PatchProposals({ proposals }: { proposals: AIReviewerResponse["prioritized_findings"][number]["patch_proposals"] }) {
  return <div><h4 className="font-mono text-xs uppercase tracking-wider text-slate-500">Patch Proposal</h4>{proposals.length === 0 ? <p className="mt-1">No patch proposal was generated.</p> : proposals.map((patch) => <div className="mt-2 overflow-hidden rounded border border-amber-200/20 bg-black/20" key={`${patch.language}-${patch.description}`}><p className="p-3 text-slate-200">{patch.description}</p><pre className="overflow-x-auto whitespace-pre-wrap break-words border-y border-white/10 p-3 font-mono text-xs leading-5 text-slate-300"><code>{`Before\n${patch.before}\n\nAfter\n${patch.after}`}</code></pre><p className="p-3 text-xs text-amber-100">{patch.warning}</p></div>)}</div>;
}

function EvidenceUsed({ references }: { references: AIReviewerResponse["prioritized_findings"][number]["evidence_references"] }) {
  return <aside className="rounded border border-cyan-200/15 bg-cyan-200/[.04] p-3"><h4 className="font-mono text-xs uppercase tracking-wider text-cyan-100">Evidence Used</h4><ul className="mt-2 space-y-2 text-xs text-slate-300">{references.map((reference) => <li className="break-words" key={`${reference.source_file}:${reference.line_number}:${reference.description}`}><span className="font-mono text-cyan-100">{reference.source_file}:{reference.line_number}</span><span className="mx-1">—</span>{reference.description}</li>)}</ul></aside>;
}

function humanConfidence(confidence: ReviewerConfidence): string {
  return `${confidence[0]?.toUpperCase()}${confidence.slice(1)} confidence`;
}
