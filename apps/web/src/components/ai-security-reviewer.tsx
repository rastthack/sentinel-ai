"use client";

import type { AIReviewerResponse } from "@/lib/scan-types";

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
  return <section aria-labelledby="ai-reviewer-title" className="mt-10 rounded-xl border border-violet-300/20 bg-violet-300/[.04] p-5 sm:p-6">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p className="font-mono text-xs uppercase tracking-[.16em] text-violet-200">Optional reviewer</p>
        <h2 className="mt-2 text-2xl font-semibold" id="ai-reviewer-title">AI Security Reviewer</h2>
      </div>
      {state.kind === "ready" ? <ModeBadge review={state.review} /> : null}
    </div>
    <p className="mt-3 text-sm text-amber-100">AI-generated guidance. Review before applying.</p>
    {state.kind === "loading" ? <p aria-live="polite" className="mt-5 text-sm text-violet-100">Preparing bounded security review from deterministic evidence…</p> : null}
    {state.kind === "unavailable" ? <div className="mt-5 rounded border border-white/10 bg-black/10 p-4 text-sm text-slate-300" role="status"><p>The optional reviewer is currently unavailable. Deterministic findings remain the security record.</p><button className="mt-3 rounded border border-white/20 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-violet-200" onClick={onRetry} type="button">Retry reviewer</button></div> : null}
    {state.kind === "ready" ? <ReviewContent review={state.review} /> : null}
  </section>;
}

function ModeBadge({ review }: { review: AIReviewerResponse }) {
  const label = review.model === "sentinel-demo-reviewer" ? "Deterministic Demo" : "Live AI";
  return <span className="rounded-full border border-violet-200/30 px-3 py-1 font-mono text-xs uppercase tracking-wider text-violet-100">{label}</span>;
}

function ReviewContent({ review }: { review: AIReviewerResponse }) {
  return <div className="mt-6 space-y-7 text-sm leading-6 text-slate-300">
    {review.executive_summary ? <div><p className="font-mono text-xs uppercase tracking-wider text-violet-200">Executive Summary</p><h3 className="mt-2 text-lg font-semibold text-white">Overall Risk: {review.executive_summary.overall_risk}</h3><p className="mt-2">{review.executive_summary.summary}</p><ul className="mt-3 list-disc space-y-1 pl-5">{review.executive_summary.key_takeaways.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}
    <div><p className="font-mono text-xs uppercase tracking-wider text-violet-200">Priority Queue</p><div className="mt-3 space-y-3">{review.prioritized_findings.map((finding, index) => <details className="rounded border border-white/10 bg-black/10 p-4" key={finding.finding_id} open={index === 0}><summary className="cursor-pointer font-semibold text-white">Priority {finding.priority}: {finding.finding_id} <span className="font-normal text-slate-400">· Confidence: {finding.confidence}</span></summary><p className="mt-4">{finding.rationale}</p><ReviewerFacts finding={finding} /></details>)}</div></div>
    <div><p className="font-mono text-xs uppercase tracking-wider text-violet-200">Limitations</p><ul className="mt-3 list-disc space-y-1 pl-5">{review.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></div>
  </div>;
}

function ReviewerFacts({ finding }: { finding: AIReviewerResponse["prioritized_findings"][number] }) {
  const facts = [["Root Cause", finding.root_cause], ["Attack Scenario", finding.attack_scenario], ["Business Impact", finding.business_impact], ["Secure Recommendation", finding.secure_recommendation]];
  return <div className="mt-5 space-y-4">{facts.map(([label, value]) => <div key={label}><h4 className="font-mono text-xs uppercase tracking-wider text-slate-500">{label}</h4><p className="mt-1">{value}</p></div>)}<div><h4 className="font-mono text-xs uppercase tracking-wider text-slate-500">Patch Proposal</h4>{finding.patch_proposals.length === 0 ? <p className="mt-1">No patch proposal was generated.</p> : finding.patch_proposals.map((patch) => <div className="mt-2 rounded border border-amber-200/20 p-3" key={`${patch.language}-${patch.description}`}><p>{patch.description}</p><p className="mt-2 text-xs text-slate-400">Before: {patch.before}</p><p className="mt-1 text-xs text-slate-400">After: {patch.after}</p><p className="mt-2 text-xs text-amber-100">{patch.warning}</p></div>)}</div><div><h4 className="font-mono text-xs uppercase tracking-wider text-slate-500">Evidence Used</h4><ul className="mt-2 space-y-1">{finding.evidence_references.map((reference) => <li key={`${reference.source_file}:${reference.line_number}:${reference.description}`}>{reference.source_file}:{reference.line_number} — {reference.description}</li>)}</ul></div></div>;
}
