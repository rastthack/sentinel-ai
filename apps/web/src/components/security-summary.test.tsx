import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SecuritySummary } from "./security-summary";
import type { ScanResponse } from "@/lib/scan-types";

const scan: ScanResponse = {
  scan_id: "scan-123",
  repository: { name: "taskflow-ai" },
  summary: {
    route_count: 4,
    protected_route_count: 3,
    public_route_count: 1,
    prisma_model_count: 2,
    mapped_route_count: 4,
    finding_count: 1,
    critical_finding_count: 0,
    high_finding_count: 1,
    medium_finding_count: 0,
    low_finding_count: 0,
  },
  technologies: [{ name: "Express", category: "framework" }],
  analysis_summary: { routes_analyzed: 4 },
  findings: [],
  ai: { status: "disabled", results: [], errors: [] },
};

describe("SecuritySummary", () => {
  it("renders the prominent overall risk badge and core deterministic metrics", () => {
    const html = renderToStaticMarkup(<SecuritySummary scan={scan} />);

    for (const label of ["Repository Summary", "taskflow-ai", "Summary of deterministic security analysis for the scanned repository.", "Overall risk: high", "Total findings", "Critical", "High", "Medium", "Low", "Routes detected", "Protected routes", "Public routes", "Prisma models", "Mapped routes", "Routes detected by supported patterns only"]) {
      expect(html).toContain(label);
    }
  });

  it("derives category totals from the deterministic findings", () => {
    const html = renderToStaticMarkup(<SecuritySummary scan={{ ...scan, findings: [{
      finding_id: "SECRET-HARDCODED-1", rule_id: "SECRET-HARDCODED", title: "Hardcoded secret", category: "secrets", severity: "high", confidence: 0.9,
      model: null, operation: null, ownership_candidate: null, source_file: "src/config.ts", line_number: 1, description: "A secret was detected.", evidence: [], recommendation: "Remove it.", risk_score: 80, risk_components: [], cwe: [], owasp: [],
    }] }} />);

    expect(html).toContain("Findings by category");
    expect(html).toContain("Secrets: 1");
  });
});
