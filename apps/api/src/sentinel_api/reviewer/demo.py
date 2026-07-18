"""Deterministic demonstration reviewer for bounded security evidence."""

from datetime import UTC, datetime
from pathlib import PurePath

from sentinel_api.reviewer.models import EvidenceFinding, SecurityEvidencePackage
from sentinel_api.reviewer.review_models import (
    AIReviewerResponse,
    ConfidenceLevel,
    ReviewerMode,
    ReviewerStatus,
)


class DemoReviewer:
    """Generate stable, non-authoritative review text from deterministic findings."""

    model_name = "sentinel-demo-reviewer"

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        """Return deterministic review material without interpreting source instructions."""
        findings = [self._prioritized_finding(finding) for finding in evidence.findings]
        payload = {
            "status": ReviewerStatus.COMPLETE,
            "mode": ReviewerMode.SECURITY_REVIEW,
            "model": self.model_name,
            "executive_summary": self._executive_summary(evidence),
            "prioritized_findings": findings,
            "limitations": [
                "Deterministic scanner findings remain the authoritative security record.",
                "This demonstration review does not execute code or apply patches.",
            ],
            "generated_at": datetime.now(UTC),
        }
        return AIReviewerResponse.from_evidence(payload, evidence)

    @staticmethod
    def _executive_summary(evidence: SecurityEvidencePackage) -> dict[str, object]:
        risk = _overall_risk(evidence.findings)
        if evidence.findings:
            summary = (
                f"The deterministic scanner reported {len(evidence.findings)} finding(s) "
                "that require reviewer attention."
            )
            takeaways = [
                "Prioritize authorization checks on routes that access client-selected resources.",
                "Treat every patch proposal as review-required guidance.",
            ]
        else:
            summary = (
                "The deterministic scanner did not report findings in this bounded "
                "evidence package."
            )
            takeaways = ["A zero-finding review is not a claim of comprehensive security coverage."]
        return {"overall_risk": risk, "summary": summary, "key_takeaways": takeaways}

    @staticmethod
    def _prioritized_finding(finding: EvidenceFinding) -> dict[str, object]:
        ownership_field = finding.ownership_candidate or "an ownership or membership field"
        model_name = finding.model or "resource"
        language = _language_for_path(finding.source_file)
        return {
            "finding_id": finding.finding_id,
            "priority": _priority(finding),
            "confidence": _confidence(finding.confidence),
            "rationale": (
                f"{finding.title} is backed by deterministic route and model evidence for "
                f"{finding.method} {finding.path}."
            ),
            "root_cause": (
                f"The route accesses {model_name} using a client-controlled identifier without "
                f"a demonstrated {ownership_field} constraint."
            ),
            "attack_scenario": (
                "An authenticated attacker can substitute another user's resource identifier and "
                "request the route to test whether data is returned outside their authorization "
                "scope."
            ),
            "business_impact": (
                f"Unauthorized access to {model_name} data can expose private records and weaken "
                "tenant or owner isolation."
            ),
            "secure_recommendation": (
                f"Constrain the {model_name} lookup with the authenticated identity and "
                f"{ownership_field}; return a safe not-found or forbidden response when it fails."
            ),
            "evidence_references": [
                {
                    "finding_id": finding.finding_id,
                    "source_file": finding.source_file,
                    "line_number": finding.line_number,
                    "description": reference,
                }
                for reference in finding.evidence_references[:5]
            ],
            "patch_proposals": [
                {
                    "language": language,
                    "description": "Scope the resource lookup to the authenticated owner.",
                    "before": "Lookup uses only the client-controlled resource identifier.",
                    "after": (
                        "Lookup includes the client-controlled identifier and the authenticated "
                        f"{ownership_field} constraint."
                    ),
                    "warning": (
                        "Review this proposal against the actual schema, identity object, and "
                        "tests "
                        "before applying it."
                    ),
                    "is_authoritative": False,
                }
            ],
        }


def _overall_risk(findings: list[EvidenceFinding]) -> ConfidenceLevel:
    if any(finding.severity in {"critical", "high"} for finding in findings):
        return ConfidenceLevel.HIGH
    if findings:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _priority(finding: EvidenceFinding) -> int:
    severity_points = {"critical": 100, "high": 85, "medium": 65, "low": 40, "informational": 20}
    return max(1, min(100, severity_points.get(finding.severity, 20) + finding.risk_score // 10))


def _confidence(value: float) -> ConfidenceLevel:
    if value >= 0.8:
        return ConfidenceLevel.HIGH
    if value >= 0.5:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _language_for_path(path: str) -> str:
    return {
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".py": "Python",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
    }.get(PurePath(path).suffix.casefold(), "text")
