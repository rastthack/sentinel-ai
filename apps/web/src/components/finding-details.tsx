"use client";

import { useState } from "react";

export type Finding = {
  finding_id: string;
  rule_id: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  confidence: number;
  method: string;
  path: string;
  model: string | null;
  description: string;
  evidence: string[];
  recommendation: string;
  risk_score: number;
};

type AIResult = {
  finding_id: string;
  explanation: { summary: string; technical_explanation: string; business_impact: string };
  root_cause: string;
  remediation: { priority: string; strategy: string; steps: string[] };
  patch: { diff: string; review_required: true; safety_notes: string[] };
  verification: { items: Array<{ check: string; required: boolean }> };
  cached: boolean;
};

export type AIAnalysis = {
  status: "disabled" | "complete" | "partial" | "unavailable";
  results: AIResult[];
  errors: Array<{ finding_id: string | null; message: string }>;
};

type FindingTab = "overview" | "evidence" | "ai" | "patch" | "verify";

const tabs: Array<{ id: FindingTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Evidence" },
  { id: "ai", label: "AI detail" },
  { id: "patch", label: "Patch proposal" },
  { id: "verify", label: "Verification" },
];

export function formatDiffLines(diff: string): Array<{ text: string; kind: string }> {
  return diff.split("\n").map((text) => ({
    text,
    kind: text.startsWith("+") && !text.startsWith("+++") ? "addition" : text.startsWith("-") && !text.startsWith("---") ? "removal" : "context",
  }));
}

export function FindingDetails({
  finding,
  ai,
  initialTab = "overview",
}: {
  finding: Finding;
  ai: AIAnalysis;
  initialTab?: FindingTab;
}) {
  const [activeTab, setActiveTab] = useState<FindingTab>(initialTab);
  const result = ai.results.find((item) => item.finding_id === finding.finding_id);

  return (
    <article className="rounded-xl border border-white/[0.08] bg-slate-950/40 p-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-full border border-orange-300/30 bg-orange-300/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-orange-200">{finding.severity}</span>
        <span className="font-mono text-xs text-slate-400">{finding.finding_id}</span>
        <span className="font-mono text-xs text-slate-600">{finding.rule_id}</span>
      </div>
      <p className="mt-4 font-mono text-sm text-slate-200">{finding.method} {finding.path}</p>
      <div aria-label="Finding details" className="mt-5 flex flex-wrap gap-2" role="tablist">
        {tabs.map((tab) => <button aria-controls={`panel-${finding.finding_id}-${tab.id}`} aria-selected={activeTab === tab.id} className="rounded-md border border-white/[0.08] px-3 py-1.5 text-xs text-slate-300" key={tab.id} onClick={() => setActiveTab(tab.id)} role="tab" type="button">{tab.label}</button>)}
      </div>
      <div className="mt-5 text-sm leading-6 text-slate-400" id={`panel-${finding.finding_id}-${activeTab}`} role="tabpanel">
        {activeTab === "overview" ? <><p>{finding.description}</p><p className="mt-3">Recommendation: {finding.recommendation}</p><p className="mt-3">Confidence {Math.round(finding.confidence * 100)}% · Risk {finding.risk_score}/100 · Model {finding.model ?? "unknown"}</p></> : null}
        {activeTab === "evidence" ? <ul className="space-y-2">{finding.evidence.map((item) => <li key={item}>· {item}</li>)}</ul> : null}
        {activeTab === "ai" ? <AIDetail ai={ai} result={result} /> : null}
        {activeTab === "patch" ? <PatchDetail result={result} /> : null}
        {activeTab === "verify" ? <VerificationDetail result={result} /> : null}
      </div>
    </article>
  );
}

function AIDetail({ ai, result }: { ai: AIAnalysis; result: AIResult | undefined }) {
  if (ai.status === "disabled") return <p>AI explanation is disabled. Deterministic findings remain available.</p>;
  if (!result) return <p>{ai.errors.find((error) => error.finding_id === null || error.finding_id === undefined)?.message ?? "AI explanation is unavailable; deterministic findings remain valid."}</p>;
  return <><p>{result.explanation.summary}</p><p className="mt-3">{result.explanation.technical_explanation}</p><p className="mt-3">Impact: {result.explanation.business_impact}</p><p className="mt-3">Root cause: {result.root_cause}</p></>;
}

function PatchDetail({ result }: { result: AIResult | undefined }) {
  if (!result) return <p>No AI patch proposal is available. Patches are never applied automatically.</p>;
  return <><p className="mb-3 text-amber-200">Review required before applying this proposal.</p><pre className="overflow-x-auto rounded-lg border border-white/[0.08] bg-black/30 p-3 font-mono text-xs">{formatDiffLines(result.patch.diff).map((line, index) => <span className={line.kind === "addition" ? "block text-emerald-300" : line.kind === "removal" ? "block text-rose-300" : "block text-slate-400"} key={`${index}-${line.text}`}>{line.text}{"\n"}</span>)}</pre></>;
}

function VerificationDetail({ result }: { result: AIResult | undefined }) {
  if (!result) return <p>No verification checklist is available.</p>;
  return <ul className="space-y-2">{result.verification.items.map((item) => <li key={item.check}>[{item.required ? "required" : "optional"}] {item.check}</li>)}</ul>;
}
