import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FindingDetails, formatDiffLines } from "./finding-details";

const finding = {
  finding_id: "AUTH-BOLA-test",
  rule_id: "AUTH-BOLA",
  severity: "high" as const,
  confidence: 0.95,
  method: "GET",
  path: "/api/projects/:id",
  model: "Project",
  description: "A project lookup lacks ownership enforcement.",
  evidence: ["Identifier reaches a direct project selector."],
  recommendation: "Scope the selector to the authenticated owner.",
  risk_score: 82,
};

const completeAI = {
  status: "complete" as const,
  errors: [],
  results: [{
    finding_id: finding.finding_id,
    explanation: { summary: "Summary", technical_explanation: "Technical details", business_impact: "Cross-user read" },
    root_cause: "Missing owner filter",
    remediation: { priority: "high", strategy: "ownership_filter", steps: ["Add owner filter"] },
    patch: { diff: "--- a/src/routes/projects.ts\n+++ b/src/routes/projects.ts\n@@ -1 +1 @@\n- old\n+ ownerId", review_required: true as const, safety_notes: ["Review"] },
    verification: { items: [{ check: "Verify cross-user access is rejected", required: true }] },
    cached: false,
  }],
};

describe("FindingDetails", () => {
  it("renders all review tabs and deterministic evidence", () => {
    const html = renderToStaticMarkup(<FindingDetails ai={{ status: "disabled", errors: [], results: [] }} finding={finding} />);
    expect(html).toContain("Overview");
    expect(html).toContain("Patch proposal");
    expect(html).toContain(finding.description);
  });

  it("renders a review-required escaped patch and verification checklist", () => {
    const html = renderToStaticMarkup(<FindingDetails ai={completeAI} finding={finding} initialTab="patch" />);
    expect(html).toContain("Review required");
    expect(html).toContain("ownerId");
    expect(html).not.toContain("<script>");
  });

  it("classifies diff additions and removals without rendering HTML", () => {
    expect(formatDiffLines("- old\n+ new")).toEqual([{ text: "- old", kind: "removal" }, { text: "+ new", kind: "addition" }]);
  });
});
