import { describe, expect, it, vi } from "vitest";
import {
  DemoScanError,
  GitHubScanError,
  ReviewerError,
  loadAIReviewerReview,
  loadDemoScan,
  scanGitHubRepository,
} from "./demo-scan-service";

const payload = { scan_id: "scan-123", repository: { name: "vulnerable-taskflow" }, summary: {}, technologies: [], analysis_summary: {}, findings: [{ finding_id: "AUTH-BOLA-D1D193AD3E" }], ai: { status: "disabled", results: [], errors: [] } };
const multiRulePayload = { scan_id: "scan-multirule", repository: { name: "vulnerable-multirule" }, summary: {}, technologies: [], analysis_summary: {}, findings: [{ finding_id: "SECRET-TOKEN-123", category: "secrets" }, { finding_id: "COMMAND-UNTRUSTED-123", category: "command_execution" }], ai: { status: "disabled", results: [], errors: [] } };

const reviewPayload = {
  status: "complete",
  mode: "security_review",
  model: "sentinel-demo-reviewer",
  executive_summary: null,
  prioritized_findings: [],
  limitations: [],
  generated_at: "2026-07-18T00:00:00Z",
};

describe("loadDemoScan", () => {
  it("requests the TaskFlow endpoint and preserves the deterministic finding", async () => { const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 })); const result = await loadDemoScan("taskflow", fetcher); expect(fetcher).toHaveBeenCalledWith("/api/scans/demo", { cache: "no-store" }); expect(result.findings).toHaveLength(1); expect(result.findings[0]?.finding_id).toBe("AUTH-BOLA-D1D193AD3E"); });
  it("requests the dedicated multi-rule endpoint and preserves mixed categories", async () => { const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(multiRulePayload), { status: 200 })); const result = await loadDemoScan("multirule", fetcher); expect(fetcher).toHaveBeenCalledWith("/api/scans/demo/multirule", { cache: "no-store" }); expect(result.repository.name).toBe("vulnerable-multirule"); expect(result.findings.map((finding) => finding.category)).toEqual(["secrets", "command_execution"]); });
  it("returns a sanitized error for a failed or invalid response", async () => { await expect(loadDemoScan("taskflow", vi.fn().mockResolvedValue(new Response("{}", { status: 503 })))).rejects.toBeInstanceOf(DemoScanError); await expect(loadDemoScan("multirule", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })))).rejects.toBeInstanceOf(DemoScanError); });
});

describe("scanGitHubRepository", () => {
  it("submits the public GitHub URL as the expected JSON request", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));

    await expect(scanGitHubRepository("https://github.com/owner/repository", fetcher)).resolves.toEqual(payload);

    expect(fetcher).toHaveBeenCalledWith("/api/scans/github", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ github_url: "https://github.com/owner/repository" }),
      cache: "no-store",
    });
  });

  it("retains status and only API detail messages for failed requests", async () => {
    const response = new Response(JSON.stringify({ detail: { message: "Public API message" } }), { status: 413 });

    await expect(scanGitHubRepository("https://github.com/owner/repository", vi.fn().mockResolvedValue(response))).rejects.toEqual(
      new GitHubScanError(413, "Public API message"),
    );
  });

  it("uses a generic message for malformed responses and transport failures", async () => {
    await expect(scanGitHubRepository("https://github.com/owner/repository", vi.fn().mockResolvedValue(new Response("not json", { status: 502 })))).rejects.toEqual(
      new GitHubScanError(502, "The repository could not be scanned."),
    );
    await expect(scanGitHubRepository("https://github.com/owner/repository", vi.fn().mockRejectedValue(new Error("private filesystem detail")))).rejects.toEqual(
      new GitHubScanError(500, "The repository could not be scanned."),
    );
  });
});

describe("loadAIReviewerReview", () => {
  it("requests the bounded review endpoint for the completed scan", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(reviewPayload), { status: 200 }));

    await expect(loadAIReviewerReview("scan-123", fetcher)).resolves.toEqual(reviewPayload);

    expect(fetcher).toHaveBeenCalledWith("/api/scans/scan-123/review", {
      method: "POST",
      cache: "no-store",
    });
  });

  it("does not expose malformed or internal reviewer failures", async () => {
    await expect(loadAIReviewerReview("scan-123", vi.fn().mockResolvedValue(new Response("/private/error", { status: 502 })))).rejects.toEqual(
      new ReviewerError(502),
    );
  });

  it("retries only the review endpoint and never starts a replacement scan", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(reviewPayload), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(reviewPayload), { status: 200 }));

    await loadAIReviewerReview("scan-123", fetcher);
    await loadAIReviewerReview("scan-123", fetcher);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.every(([url]) => url === "/api/scans/scan-123/review")).toBe(true);
  });
});
