export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export type Finding = {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  method: string;
  path: string;
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

export function isScanResponse(value: unknown): value is ScanResponse {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return Array.isArray(record.findings) && typeof record.summary === "object" && typeof record.ai === "object";
}
