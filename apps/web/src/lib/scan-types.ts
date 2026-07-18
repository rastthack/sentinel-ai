export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type FindingCategory = "authorization" | "authentication" | "secrets" | "cors" | "jwt" | "rate_limiting" | "redirect" | "filesystem" | "command_execution" | "file_upload";

export type Finding = {
  finding_id: string;
  rule_id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: number;
  method?: string | null;
  path?: string | null;
  model: string | null;
  operation: string | null;
  ownership_candidate: string | null;
  source_file: string;
  line_number: number;
  description: string;
  evidence: string[];
  recommendation: string;
  risk_score: number;
  risk_components: Array<{ name: string; points: number }>;
  cwe: string[];
  owasp: string[];
};

export type AIResult = {
  finding_id: string;
  explanation: {
    summary: string;
    technical_explanation: string;
    business_impact: string;
    why_detected: string;
    confidence_reasoning: string;
    false_positive_notes: string;
  };
  root_cause: string;
  remediation: { priority: string; strategy: string; steps: string[] };
  patch: { source_file: string; diff: string; review_required: true; safety_notes: string[] };
  verification: { items: Array<{ check: string; required: boolean }> };
};

export type AIAnalysis = {
  status: "disabled" | "complete" | "partial" | "unavailable";
  results: AIResult[];
  errors: Array<{ finding_id: string | null; message: string }>;
};

export type ScanResponse = {
  scan_id: string;
  repository: { name: string };
  summary: {
    route_count: number; protected_route_count: number; public_route_count: number;
    prisma_model_count: number; mapped_route_count: number; finding_count: number;
    critical_finding_count: number; high_finding_count: number; medium_finding_count: number;
    low_finding_count: number;
  };
  technologies: Array<{ name: string; category: string }>;
  analysis_summary: { routes_analyzed: number };
  findings: Finding[];
  ai: AIAnalysis;
};

export type RepositoryScanResponse = ScanResponse;

export type ReviewerStatus = "complete" | "partial" | "unavailable" | "disabled";
export type ReviewerMode = "security_review" | "prioritization" | "remediation";
export type ReviewerConfidence = "high" | "medium" | "low";

export type AIReviewerResponse = {
  status: ReviewerStatus;
  mode: ReviewerMode;
  model: string | null;
  executive_summary: {
    overall_risk: ReviewerConfidence;
    summary: string;
    key_takeaways: string[];
  } | null;
  prioritized_findings: Array<{
    finding_id: string;
    priority: number;
    confidence: ReviewerConfidence;
    rationale: string;
    root_cause: string;
    attack_scenario: string;
    business_impact: string;
    secure_recommendation: string;
    evidence_references: Array<{
      finding_id: string;
      source_file: string;
      line_number: number;
      description: string;
    }>;
    patch_proposals: Array<{
      language: string;
      description: string;
      before: string;
      after: string;
      warning: string;
      is_authoritative: false;
    }>;
  }>;
  limitations: string[];
  generated_at: string;
};

export function isScanResponse(value: unknown): value is ScanResponse {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.scan_id === "string" && Array.isArray(record.findings) && typeof record.summary === "object" && typeof record.ai === "object";
}

export function isAIReviewerResponse(value: unknown): value is AIReviewerResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return isReviewerStatus(record.status)
    && isReviewerMode(record.mode)
    && (typeof record.model === "string" || record.model === null)
    && Array.isArray(record.prioritized_findings)
    && Array.isArray(record.limitations)
    && typeof record.generated_at === "string";
}

function isReviewerStatus(value: unknown): value is ReviewerStatus {
  return value === "complete" || value === "partial" || value === "unavailable" || value === "disabled";
}

function isReviewerMode(value: unknown): value is ReviewerMode {
  return value === "security_review" || value === "prioritization" || value === "remediation";
}
