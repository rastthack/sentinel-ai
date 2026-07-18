import { describe, expect, it, vi } from "vitest";
import {
  DemoScanError,
  GitHubScanError,
  loadDemoScan,
  scanGitHubRepository,
} from "./demo-scan-service";

const payload = { repository: { name: "vulnerable-taskflow" }, summary: {}, technologies: [], analysis_summary: {}, findings: [{ finding_id: "AUTH-BOLA-D1D193AD3E" }], ai: { status: "disabled", results: [], errors: [] } };

describe("loadDemoScan", () => {
  it("requests the demo endpoint and preserves the deterministic finding", async () => { const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 })); const result = await loadDemoScan(fetcher); expect(fetcher).toHaveBeenCalledWith("/api/scans/demo", { cache: "no-store" }); expect(result.findings).toHaveLength(1); expect(result.findings[0]?.finding_id).toBe("AUTH-BOLA-D1D193AD3E"); });
  it("returns a sanitized error for a failed or invalid response", async () => { await expect(loadDemoScan(vi.fn().mockResolvedValue(new Response("{}", { status: 503 })))).rejects.toBeInstanceOf(DemoScanError); await expect(loadDemoScan(vi.fn().mockResolvedValue(new Response("{}", { status: 200 })))).rejects.toBeInstanceOf(DemoScanError); });
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
