import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { FindingDetails } from "./finding-details";
import { filterFindings, FindingsList } from "./findings-list";
import type { AIAnalysis, Finding } from "@/lib/scan-types";

const disabledAI: AIAnalysis = { status: "disabled", results: [], errors: [] };

const findings: Finding[] = [
  finding("SECRET-HARDCODED", "Hardcoded API secret", "secrets", "high", "src/config.ts", 12),
  finding("CORS-WILDCARD", "Permissive CORS policy", "cors", "medium", "src/server.ts", 20),
  finding("CMD-EXEC", "Command execution risk", "command_execution", "high", "src/tools.ts", 8),
  finding("UPLOAD-UNSAFE", "Unsafe file upload", "file_upload", "medium", "src/upload.ts", 4),
];

function finding(ruleId: string, title: string, category: Finding["category"], severity: Finding["severity"], sourceFile: string, lineNumber: number): Finding {
  return {
    finding_id: `${ruleId}-D1D193AD3E`, rule_id: ruleId, title, category, severity, confidence: 0.92,
    model: null, operation: null, ownership_candidate: null, source_file: sourceFile, line_number: lineNumber,
    description: "<script>untrusted repository text</script>", evidence: ["Literal value: <redacted>"], recommendation: "Review the finding.", risk_score: 70,
    risk_components: [], cwe: [], owasp: [],
  };
}

describe("multi-rule findings UI", () => {
  it("renders mixed deterministic categories safely without authorization-only metadata", () => {
    const html = renderToStaticMarkup(<FindingsList findings={findings} onSelect={vi.fn()} />);
    for (const category of ["Secrets", "CORS", "Command Execution", "File Upload"]) expect(html).toContain(category);
    expect(html).toContain("Filter category");
    expect(html).toContain("Repository configuration");
    expect(html).toContain("Application middleware");
    expect(html).toContain("Source file");

    const detail = renderToStaticMarkup(<FindingDetails ai={disabledAI} finding={findings[0]!} />);
    expect(detail).toContain("Secrets");
    expect(detail).toContain("&lt;script&gt;untrusted repository text&lt;/script&gt;");
    expect(detail).not.toContain("<script>untrusted repository text</script>");
    expect(detail).not.toContain("Ownership candidate");
  });

  it("filters by category, severity, title, rule, source file, and route", () => {
    expect(filterFindings(findings, "", "all", "secrets")).toEqual([findings[0]]);
    expect(filterFindings(findings, "", "high", "all")).toHaveLength(2);
    expect(filterFindings(findings, "cors-wildcard", "all", "all")).toEqual([findings[1]]);
    expect(filterFindings(findings, "upload", "all", "all")).toEqual([findings[3]]);
    expect(filterFindings(findings, "src/tools.ts", "all", "all")).toEqual([findings[2]]);
  });
});
