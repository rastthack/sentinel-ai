import { describe, expect, it, vi } from "vitest";
import { DemoScanError, loadDemoScan } from "./demo-scan-service";

const payload = { repository: { name: "vulnerable-taskflow" }, summary: {}, technologies: [], analysis_summary: {}, findings: [{ finding_id: "AUTH-BOLA-D1D193AD3E" }], ai: { status: "disabled", results: [], errors: [] } };

describe("loadDemoScan", () => {
  it("requests the demo endpoint and preserves the deterministic finding", async () => { const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 })); const result = await loadDemoScan(fetcher); expect(fetcher).toHaveBeenCalledWith("/api/scans/demo", { cache: "no-store" }); expect(result.findings).toHaveLength(1); expect(result.findings[0]?.finding_id).toBe("AUTH-BOLA-D1D193AD3E"); });
  it("returns a sanitized error for a failed or invalid response", async () => { await expect(loadDemoScan(vi.fn().mockResolvedValue(new Response("{}", { status: 503 })))).rejects.toBeInstanceOf(DemoScanError); await expect(loadDemoScan(vi.fn().mockResolvedValue(new Response("{}", { status: 200 })))).rejects.toBeInstanceOf(DemoScanError); });
});
