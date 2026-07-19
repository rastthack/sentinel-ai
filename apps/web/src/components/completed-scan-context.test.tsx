import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { AnalysisCoverage } from "./analysis-coverage";
import { FindingsList } from "./findings-list";
import { ScanMetadata } from "./scan-metadata";
import { ScanPipeline } from "./scan-pipeline";
import type { ScanResponse } from "@/lib/scan-types";

const scan: ScanResponse = {
  scan_id: "scan-123",
  repository: { name: "repository-with-a-very-long-name" },
  summary: {
    route_count: 3,
    protected_route_count: 2,
    public_route_count: 1,
    prisma_model_count: 1,
    mapped_route_count: 2,
    finding_count: 0,
    critical_finding_count: 0,
    high_finding_count: 0,
    medium_finding_count: 0,
    low_finding_count: 0,
  },
  technologies: [{ name: "Express", category: "framework" }],
  analysis_summary: { routes_analyzed: 3 },
  findings: [],
  ai: { status: "disabled", results: [], errors: [] },
};

describe("completed scan context", () => {
  it("renders the completed workflow and existing-or-unknown metadata only", () => {
    const pipeline = renderToStaticMarkup(<ScanPipeline />);
    const metadata = renderToStaticMarkup(<ScanMetadata scan={scan} />);

    for (const stage of ["Repository", "Discovery", "Deterministic Analysis", "Evidence Package", "AI Security Review"]) {
      expect(pipeline).toContain(stage);
    }
    for (const field of ["Scan Metadata", "repository-with-a-very-long-name", "Express", "ORM", "Unknown", "Routes detected by supported patterns", "Protected routes"]) {
      expect(metadata).toContain(field);
    }
  });

  it("renders supported coverage separately from planned work and explains zero findings", () => {
    const coverage = renderToStaticMarkup(<AnalysisCoverage />);
    const findings = renderToStaticMarkup(<FindingsList findings={[]} onSelect={vi.fn()} />);

    for (const item of ["Current Analysis Coverage", "Supported Today", "Route and authentication discovery", "BOLA / IDOR detection", "Planned / Experimental", "SQL Injection", "Hardcoded secrets", "Command injection", "Unsafe file upload"]) {
      expect(coverage).toContain(item);
    }
    expect(findings).toContain("Scan completed successfully");
    expect(findings).toContain("No issues matching Sentinel AI&#x27;s currently supported deterministic rules were detected.");
    expect(findings).toContain("does not imply that the repository is free of vulnerabilities");
  });
});
