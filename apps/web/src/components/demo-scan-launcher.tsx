"use client";

import { useEffect, useRef, useState } from "react";

import { FindingDetails } from "./finding-details";
import { FindingsList } from "./findings-list";
import { ScanProgress } from "./scan-progress";
import { SecuritySummary } from "./security-summary";
import { ScanPipeline } from "./scan-pipeline";
import { AnalysisCoverage } from "./analysis-coverage";
import { ScanMetadata } from "./scan-metadata";
import { AISecurityReviewer, type ReviewerPanelState } from "./ai-security-reviewer";
import {
  GitHubScanError,
  ReviewerError,
  loadAIReviewerReview,
  loadDemoScan,
  scanGitHubRepository,
} from "../lib/demo-scan-service";
import type { DemoScanTarget } from "../lib/demo-scan-service";
import type { Finding, ScanResponse } from "../lib/scan-types";

type ScanSource =
  | { kind: "demo"; target: DemoScanTarget }
  | { kind: "github"; githubUrl: string };

type RetryTarget =
  | { kind: "demo"; target: DemoScanTarget }
  | { kind: "github" };

type State =
  | { kind: "idle" }
  | { kind: "review-empty" }
  | { kind: "demo-loading"; target: DemoScanTarget }
  | { kind: "github-loading" }
  | { kind: "error"; message: string; retry: RetryTarget }
  | { kind: "ready"; scan: ScanResponse; selected: Finding | null; source: ScanSource; reviewer: ReviewerPanelState };

const githubUrlPrefix = "https://github.com/";

export function DemoScanLauncher() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [githubUrl, setGithubUrl] = useState("");
  const [githubValidationError, setGithubValidationError] = useState<string | null>(null);
  const [scanSubmissionGuard] = useState(createScanSubmissionGuard);
  const reviewRef = useRef<HTMLDivElement>(null);
  const reviewRequestGuard = useRef(createReviewRequestGuard());
  const githubLoading = state.kind === "github-loading";

  useEffect(() => {
    const handleNavigation = (event: Event) => {
      const destination = (event as CustomEvent<"overview" | "review" | "architecture">).detail;
      if (destination === "overview") {
        setState({ kind: "idle" });
        requestAnimationFrame(() => scrollToSection("overview"));
      }
      if (destination === "review") {
        if (state.kind === "ready") reviewRef.current?.scrollIntoView({ behavior: "smooth" });
        else scrollToSection("scan-controls");
      }
      if (destination === "architecture") {
        scrollToSection("architecture");
      }
    };
    window.addEventListener("sentinel:navigate", handleNavigation);
    return () => window.removeEventListener("sentinel:navigate", handleNavigation);
  }, [state.kind]);

  async function startDemoScan(target: DemoScanTarget = "taskflow") {
    if (!scanSubmissionGuard.tryStart()) return;
    setState({ kind: "demo-loading", target });
    try {
      showScan(await loadDemoScan(target), { kind: "demo", target });
    } catch {
      setState({
        kind: "error",
        message: "The controlled demo scan is currently unavailable. Retry when the Sentinel API is ready.",
        retry: { kind: "demo", target },
      });
    } finally {
      scanSubmissionGuard.finish();
    }
  }

  async function startGitHubScan() {
    if (githubLoading) return;
    const validationError = githubUrlValidationError(githubUrl);
    if (validationError) {
      setGithubValidationError(validationError);
      return;
    }
    setGithubValidationError(null);
    if (!scanSubmissionGuard.tryStart()) return;
    setState({ kind: "github-loading" });
    try {
      showScan(await scanGitHubRepository(githubUrl), { kind: "github", githubUrl });
    } catch (error) {
      setState({ kind: "error", message: githubErrorMessage(error), retry: { kind: "github" } });
    } finally {
      scanSubmissionGuard.finish();
    }
  }

  function showScan(scan: ScanResponse, source: ScanSource) {
    setState({
      kind: "ready",
      scan,
      selected: scan.findings[0] ?? null,
      source,
      reviewer: initialReviewerPanelState(),
    });
    void loadReviewer(scan.scan_id);
  }

  async function loadReviewer(scanId: string) {
    if (!reviewRequestGuard.current.tryStart(scanId)) return;
    setState((current) => current.kind === "ready" && current.scan.scan_id === scanId
      ? { ...current, reviewer: { kind: "loading" } }
      : current);
    try {
      const review = await loadAIReviewerReview(scanId);
      setState((current) => current.kind === "ready" && shouldApplyReviewerResult(current.scan.scan_id, scanId)
        ? { ...current, reviewer: { kind: "ready", review } }
        : current);
    } catch (error) {
      setState((current) => current.kind === "ready" && shouldApplyReviewerResult(current.scan.scan_id, scanId)
        ? { ...current, reviewer: error instanceof ReviewerError && error.status === 409 ? { kind: "empty" } : { kind: "unavailable" } }
        : current);
    } finally {
      reviewRequestGuard.current.finish(scanId);
    }
  }

  if (state.kind === "demo-loading" || state.kind === "github-loading") {
    return <div id="overview" className="mx-auto max-w-7xl px-5 py-12 lg:px-8"><ScanProgress onCancel={() => setState({ kind: "idle" })} source={state.kind === "demo-loading" ? state.target : "github"} /></div>;
  }

  if (state.kind === "ready") {
    return <div className="mx-auto max-w-7xl px-5 py-12 lg:px-8" ref={reviewRef}><div className="mb-6 flex flex-wrap items-center justify-between gap-4"><p className="break-all text-sm text-slate-400">{state.source.kind === "github" ? <>Public GitHub repository: <span className="font-mono text-slate-200">{state.source.githubUrl}</span></> : state.source.target === "taskflow" ? "Bundled TaskFlow AI demo" : "Bundled multi-rule demo"}</p><button className="rounded border border-white/15 px-4 py-2 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-300" onClick={() => setState({ kind: "idle" })} type="button">Start another scan</button></div><ScanPipeline /><SecuritySummary scan={state.scan} /><ScanMetadata scan={state.scan} /><AnalysisCoverage /><FindingsList findings={state.scan.findings} onSelect={(selected) => setState((current) => current.kind === "ready" ? { ...current, selected } : current)} />{state.selected ? <FindingDetails ai={state.scan.ai} finding={state.selected} /> : null}<AISecurityReviewer deterministicFindings={state.scan.findings} onRetry={() => void loadReviewer(state.scan.scan_id)} state={state.reviewer} /></div>;
  }

  if (state.kind === "review-empty") {
    return <section className="mx-auto max-w-7xl px-5 py-16 lg:px-8" id="review"><p className="font-mono text-xs uppercase tracking-[.16em] text-emerald-300">Security review</p><h1 className="mt-3 text-4xl font-semibold">No scan is open</h1><p className="mt-4 max-w-xl text-slate-400">Run a controlled demo or scan a public GitHub repository to view deterministic security analysis. Sentinel does not retain scan history.</p><button className="mt-7 rounded-lg bg-emerald-300 px-5 py-3 font-semibold text-slate-950" onClick={() => void startDemoScan("taskflow")} type="button">Run TaskFlow Demo Scan</button></section>;
  }

  return <section className="mx-auto grid max-w-7xl scroll-mt-24 gap-10 px-5 py-16 lg:grid-cols-[1.2fr_.8fr] lg:px-8 lg:py-24" id="overview"><div><p className="font-mono text-xs uppercase tracking-[.2em] text-emerald-300">AI-Assisted Deterministic Security Review</p><h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-tight text-white sm:text-6xl">Evidence-Backed AI Security Reviews</h1><p className="mt-6 max-w-2xl text-lg leading-8 text-slate-400">Scan a public GitHub repository using deterministic security rules, then receive bounded, category-aware AI guidance based only on verified evidence.</p><ul className="mt-6 space-y-3 text-sm text-slate-300"><li>✓ <span className="ml-2">Deterministic vulnerability detection</span></li><li>✓ <span className="ml-2">Evidence-backed AI explanations</span></li><li>✓ <span className="ml-2">Human-verifiable remediation guidance</span></li></ul><a className="mt-8 inline-flex cursor-pointer rounded-lg bg-emerald-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-200 focus:outline-none focus:ring-2 focus:ring-emerald-100" href="#github-url">Scan Public Repository</a><div className="mt-5 grid max-w-2xl scroll-mt-24 gap-3 sm:grid-cols-2" id="scan-controls"><DemoAction description="Authorization-focused controlled demo" detail="A controlled BOLA and ownership-validation example. Fixture code is never executed." label="Run TaskFlow Demo" onClick={() => void startDemoScan("taskflow")} /><DemoAction description="Multi-rule controlled demo" detail="Controlled secrets, JWT, CORS, redirects, command execution, filesystem, rate limiting, and file upload checks. Fixture code is never executed." label="Run Multi-Rule Demo" onClick={() => void startDemoScan("multirule")} /></div><p className="mt-3 max-w-2xl text-xs leading-5 text-slate-500">Both demos are controlled local static-analysis targets. Sentinel never installs dependencies or runs fixture code.</p><form className="mt-8 max-w-xl rounded-xl border border-emerald-300/20 bg-[#0c141f] p-5 shadow-lg shadow-black/10" onSubmit={(event) => { event.preventDefault(); void startGitHubScan(); }}><p className="font-mono text-xs uppercase tracking-wider text-emerald-200">Scan Public Repository</p><label className="mt-3 block text-sm font-semibold text-slate-100" htmlFor="github-url">Public GitHub repository URL</label><p className="mt-2 text-sm text-slate-400">Only public GitHub HTTPS repository URLs are supported.</p><div className="mt-4 flex flex-col gap-3 sm:flex-row"><input aria-describedby="github-url-help" aria-invalid={githubValidationError ? "true" : undefined} className="min-w-0 flex-1 rounded border border-white/15 bg-[#07101a] px-3 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-300 disabled:cursor-not-allowed disabled:opacity-60" disabled={githubLoading} id="github-url" name="github-url" onChange={(event) => setGithubUrl(event.target.value)} placeholder="https://github.com/owner/repository" type="url" value={githubUrl} /><button className="cursor-pointer rounded bg-emerald-300 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-emerald-200 focus:outline-none focus:ring-2 focus:ring-emerald-100 disabled:cursor-not-allowed disabled:opacity-60" disabled={githubLoading} type="submit">Scan repository</button></div><p className="mt-3 text-sm text-slate-500" id="github-url-help">Sentinel clones and statically analyzes the repository. It never installs dependencies or executes repository code.</p><p className="mt-2 text-xs leading-5 text-slate-500">Large repositories may exceed the bounded download limit.</p>{githubLoading ? <p aria-live="polite" className="mt-3 text-sm text-emerald-200">Cloning and scanning repository…</p> : null}{githubValidationError ? <p className="mt-3 text-sm text-rose-200" role="alert">{githubValidationError}</p> : null}</form>{state.kind === "error" ? <div className="mt-5 rounded border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-100" role="alert">{state.message}<button className="ml-4 cursor-pointer rounded underline underline-offset-4 focus:outline-none focus:ring-2 focus:ring-rose-200" onClick={() => { if (state.retry.kind === "github") void startGitHubScan(); else void startDemoScan(state.retry.target); }} type="button">Retry</button></div> : null}</div><aside className="rounded-xl border border-white/[.08] bg-[#0c141f] p-6"><p className="font-mono text-xs uppercase tracking-wider text-slate-500">Currently supported deterministic checks</p><div className="mt-5 flex flex-wrap gap-2">{["Authorization", "Secrets", "CORS", "JWT", "Rate Limiting", "Redirect", "Path Traversal", "Command Execution", "File Upload"].map((item) => <span className="rounded-full border border-emerald-300/20 bg-emerald-300/[.04] px-2.5 py-1 text-xs text-emerald-100" key={item}>{item}</span>)}</div><p className="mt-6 text-sm leading-6 text-slate-500">Coverage is intentionally bounded and is not a comprehensive security assessment.</p></aside></section>;
}

export function scrollToSection(id: "overview" | "scan-controls" | "architecture"): void {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function DemoAction({ description, detail, label, onClick }: { description: string; detail: string; label: string; onClick: () => void }) {
  return <div className="rounded-xl border border-white/[.08] bg-[#0c141f] p-4"><p className="font-mono text-[10px] uppercase tracking-wider text-emerald-200">{description}</p><p className="mt-2 min-h-10 text-xs leading-5 text-slate-400">{detail}</p><button className="mt-4 w-full rounded-lg bg-emerald-300 px-4 py-3 text-sm font-semibold text-slate-950 focus:outline-none focus:ring-2 focus:ring-emerald-100" onClick={onClick} type="button">{label}</button></div>;
}

export function githubUrlValidationError(value: string): string | null {
  if (!value.trim()) return "Enter a public GitHub repository URL.";
  if (!value.startsWith(githubUrlPrefix)) return "Enter a public GitHub repository URL.";
  return null;
}

export function githubErrorMessage(error: unknown): string {
  if (error instanceof GitHubScanError) {
    if (error.status === 422) return "Enter a valid public GitHub repository URL.";
    if (error.status === 413) return "This repository is too large to scan safely.";
    if (error.status === 502) return "The repository could not be accessed. Confirm that it is public and available.";
    if (error.status === 504) return "The repository took too long to download.";
    if (error.status === 500) return "The repository could not be scanned.";
    return "The repository could not be scanned.";
  }
  return "The repository could not be scanned.";
}

type ScanSubmissionGuard = {
  tryStart: () => boolean;
  finish: () => void;
};

export function createScanSubmissionGuard(): ScanSubmissionGuard {
  let active = false;
  return {
    tryStart: () => {
      if (active) return false;
      active = true;
      return true;
    },
    finish: () => {
      active = false;
    },
  };
}

export function createGitHubSubmissionGuard(): ScanSubmissionGuard {
  return createScanSubmissionGuard();
}

type ReviewRequestGuard = {
  tryStart: (scanId: string) => boolean;
  finish: (scanId: string) => void;
};

export function createReviewRequestGuard(): ReviewRequestGuard {
  const activeScanIds = new Set<string>();
  return {
    tryStart: (scanId) => {
      if (activeScanIds.has(scanId)) return false;
      activeScanIds.add(scanId);
      return true;
    },
    finish: (scanId) => {
      activeScanIds.delete(scanId);
    },
  };
}

export function initialReviewerPanelState(): ReviewerPanelState {
  return { kind: "loading" };
}

export function shouldApplyReviewerResult(activeScanId: string, reviewScanId: string): boolean {
  return activeScanId === reviewScanId;
}
