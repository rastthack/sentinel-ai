import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { AISecurityReviewer } from "./ai-security-reviewer";
import type { AIReviewerResponse, Finding } from "@/lib/scan-types";

const deterministicFindings: Finding[] = [{
  finding_id: "AUTH-BOLA-D1D193AD3E",
  rule_id: "AUTH-BOLA",
  title: "Potential BOLA / IDOR",
  severity: "high",
  confidence: 0.98,
  method: "GET",
  path: "/api/projects/:id",
  model: "Project",
  operation: "read_one",
  ownership_candidate: "ownerId",
  source_file: "src/routes/projects.ts",
  line_number: 42,
  description: "Missing ownership predicate.",
  evidence: ["Deterministic evidence."],
  recommendation: "Scope the lookup.",
  risk_score: 85,
  risk_components: [],
  cwe: ["CWE-639"],
  owasp: ["API1:2023"],
}];

const review: AIReviewerResponse = {
  status: "complete",
  mode: "security_review",
  model: "sentinel-demo-reviewer",
  executive_summary: {
    overall_risk: "high",
    summary: "One deterministic finding needs attention.",
    key_takeaways: ["Scope lookups to the authenticated owner."],
  },
  prioritized_findings: [{
    finding_id: "AUTH-BOLA-D1D193AD3E",
    priority: 85,
    confidence: "high",
    rationale: "The deterministic route evidence supports this priority.",
    root_cause: "The lookup lacks an ownership predicate.",
    attack_scenario: "An attacker substitutes an identifier.",
    business_impact: "Private project data can be exposed.",
    secure_recommendation: "Include the authenticated user in the lookup.",
    evidence_references: [{
      finding_id: "AUTH-BOLA-D1D193AD3E",
      source_file: "src/routes/projects.ts",
      line_number: 42,
      description: "Lookup uses an unscoped identifier.",
    }],
    patch_proposals: [{
      language: "TypeScript",
      description: "Scope the lookup.",
      before: "<img src=x onerror=alert(1)>",
      after: "findFirst({ where: { id, ownerId } })",
      warning: "Review before applying.",
      is_authoritative: false,
    }],
  }],
  limitations: ["Deterministic findings remain authoritative."],
  generated_at: "2026-07-18T00:00:00Z",
};

describe("AISecurityReviewer", () => {
  it("renders the required deterministic-demo review content in collapsible findings", () => {
    const html = renderToStaticMarkup(<AISecurityReviewer deterministicFindings={deterministicFindings} onRetry={vi.fn()} state={{ kind: "ready", review }} />);

    for (const label of ["Evidence-backed AI Review", "AI Security Reviewer", "AI-generated guidance. Review before applying.", "Deterministic Demo", "Executive Summary", "Overall risk: high", "Priority Queue", "Root Cause", "Attack Scenario", "Business Impact", "Secure Recommendation", "Patch Proposal", "Evidence Used", "High confidence", "Evidence confidence", "98% · Very High", "Limitations"]) {
      expect(html).toContain(label);
    }
    expect(html).toContain("<details");
    expect(html).toContain("#1");
    expect(html).toContain("AUTH-BOLA-D1D193AD3E");
    expect(html).toContain("<pre");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
  });

  it("renders clear loading and unavailable states", () => {
    expect(renderToStaticMarkup(<AISecurityReviewer deterministicFindings={deterministicFindings} onRetry={vi.fn()} state={{ kind: "loading" }} />)).toContain("Generating security review");
    const unavailable = renderToStaticMarkup(<AISecurityReviewer deterministicFindings={deterministicFindings} onRetry={vi.fn()} state={{ kind: "unavailable" }} />);
    expect(unavailable).toContain("currently unavailable");
    expect(unavailable).toContain("Retry reviewer");
  });
});
