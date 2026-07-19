"""Deterministic, category-aware demonstration reviewer for bounded evidence."""
# ruff: noqa: E501

from datetime import UTC, datetime
from pathlib import PurePath
from typing import cast

from sentinel_api.reviewer.models import EvidenceFinding, SecurityEvidencePackage
from sentinel_api.reviewer.review_models import (
    AIReviewerResponse,
    ConfidenceLevel,
    ReviewerMode,
    ReviewerStatus,
)


class DemoReviewer:
    """Generate stable advisory text from deterministic findings only."""

    model_name = "sentinel-demo-reviewer"

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        """Return category-specific guidance without modifying scanner facts."""
        ordered = sorted(evidence.findings, key=_priority_key)
        payload = {
            "status": ReviewerStatus.COMPLETE,
            "mode": ReviewerMode.SECURITY_REVIEW,
            "model": self.model_name,
            "executive_summary": _executive_summary(ordered),
            "prioritized_findings": [self._prioritized_finding(item) for item in ordered],
            "limitations": [
                "Deterministic scanner findings remain the authoritative security record.",
                "Guidance is based on bounded static evidence; it does not confirm exploitation or complete data flow.",
                "This demonstration review does not execute code or apply patches.",
            ],
            "generated_at": datetime.now(UTC),
        }
        return AIReviewerResponse.from_evidence(payload, evidence)

    @staticmethod
    def _prioritized_finding(finding: EvidenceFinding) -> dict[str, object]:
        guidance = _GUIDANCE[finding.category]
        label = str(guidance["label"])
        location = _location_description(finding)
        return {
            "finding_id": finding.finding_id,
            "priority": _priority_score(finding),
            "confidence": _confidence(finding.confidence),
            "rationale": f"{finding.title} is a deterministic {label} finding at {location}.",
            "root_cause": str(guidance["root_cause"]),
            "attack_scenario": str(guidance["attack_scenario"]),
            "business_impact": str(guidance["business_impact"]),
            "secure_recommendation": str(guidance["recommendation"]),
            "verification_guidance": cast(list[str], guidance["verification"]),
            "evidence_references": [
                {
                    "finding_id": finding.finding_id,
                    "source_file": finding.source_file,
                    "line_number": finding.line_number,
                    "description": reference,
                }
                for reference in finding.evidence_references[:5]
            ],
            "patch_proposals": [{
                "language": _language_for_path(finding.source_file),
                "description": str(guidance["patch_description"]),
                "before": str(guidance["before"]),
                "after": str(guidance["after"]),
                "warning": "Review this proposal against the application context and tests before applying it.",
                "is_authoritative": False,
            }],
        }


def _executive_summary(findings: list[EvidenceFinding]) -> dict[str, object]:
    if not findings:
        return {
            "overall_risk": ConfidenceLevel.LOW,
            "summary": "The deterministic scanner did not report findings in this bounded evidence package.",
            "key_takeaways": ["A zero-finding review is not a claim of comprehensive security coverage."],
        }
    categories = _category_labels(findings)
    highest = str(_GUIDANCE[findings[0].category]["label"]).casefold()
    return {
        "overall_risk": _overall_risk(findings),
        "summary": f"The deterministic scanner reported {len(findings)} finding(s). Prioritize {highest} findings first; deterministic findings remain authoritative.",
        "key_takeaways": [
            f"Highest-severity categories present: {', '.join(categories)}.",
            "Treat every patch proposal as review-required guidance.",
        ],
    }


def _category_labels(findings: list[EvidenceFinding]) -> list[str]:
    return list(dict.fromkeys(str(_GUIDANCE[item.category]["label"]) for item in findings))


def _priority_key(finding: EvidenceFinding) -> tuple[int, int, float, str]:
    return (-_severity_rank(finding.severity), -finding.risk_score, -finding.confidence, finding.finding_id)


def _priority_score(finding: EvidenceFinding) -> int:
    base = {"critical": 90, "high": 70, "medium": 50, "low": 30, "informational": 10}.get(finding.severity, 10)
    return min(100, base + min(9, finding.risk_score // 12))


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(value, 0)


def _overall_risk(findings: list[EvidenceFinding]) -> ConfidenceLevel:
    if any(item.severity in {"critical", "high"} for item in findings):
        return ConfidenceLevel.HIGH
    return ConfidenceLevel.MEDIUM


def _confidence(value: float) -> ConfidenceLevel:
    return ConfidenceLevel.HIGH if value >= 0.8 else ConfidenceLevel.MEDIUM if value >= 0.5 else ConfidenceLevel.LOW


def _location_description(finding: EvidenceFinding) -> str:
    if finding.method and finding.path and finding.path != "(repository configuration)":
        return f"{finding.method} {finding.path}"
    return f"{finding.source_file}:{finding.line_number}"


def _language_for_path(path: str) -> str:
    return {".js": "JavaScript", ".jsx": "JavaScript", ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript"}.get(PurePath(path).suffix.casefold(), "text")


_GUIDANCE: dict[str, dict[str, object]] = {
    "authorization": {"label": "Authorization", "root_cause": "A client-selected resource access lacks a demonstrated identity, tenant, role, or membership constraint.", "attack_scenario": "An authenticated user could alter a resource identifier to test whether access is enforced outside their permitted scope.", "business_impact": "Missing authorization scope can expose or modify records outside the caller's intended access boundary.", "recommendation": "Scope resource access to authenticated identity, tenant, role, or membership and return a safe denial when the constraint fails.", "patch_description": "Add an authorization scope to the resource access.", "before": "Resource access relies on a client-selected identifier without a demonstrated authorization scope.", "after": "Resource access includes an authenticated identity, tenant, role, or membership constraint.", "verification": ["Confirm cross-user and cross-tenant requests are denied.", "Confirm legitimate authorized access still succeeds."]},
    "secrets": {"label": "Secrets", "root_cause": "Credential-like material is embedded in source or configuration evidence.", "attack_scenario": "Anyone with repository or artifact access could attempt to reuse exposed credential material; exposure does not confirm validity.", "business_impact": "Embedded credentials can increase the impact of source disclosure or accidental distribution.", "recommendation": "Remove embedded credentials, rotate them if exposure is confirmed, and load replacements from server-side environment or managed secret storage.", "patch_description": "Replace embedded credential material with a server-side secret reference.", "before": "Credential-like value is embedded in source or configuration.", "after": "Secret value is loaded from approved server-side configuration without returning it to clients.", "verification": ["Confirm no raw credential remains in source, build artifacts, or logs.", "Confirm rotation and least-privilege controls are reviewed by a human."]},
    "cors": {"label": "CORS", "root_cause": "CORS policy evidence permits an overly broad or unvalidated origin behavior.", "attack_scenario": "A browser hosted on an untrusted origin could test whether credentialed cross-origin requests are accepted.", "business_impact": "Overly permissive browser access controls can expose authenticated responses to untrusted origins.", "recommendation": "Use an explicit origin allowlist, avoid wildcard origins with credentials, and validate reflected origins.", "patch_description": "Restrict the CORS policy to trusted origins.", "before": "CORS policy accepts a broad or unvalidated origin.", "after": "CORS policy validates origins against an explicit allowlist and reviews credential behavior.", "verification": ["Test allowed and denied origins, including preflight requests.", "Confirm credentialed requests are not accepted from wildcard origins."]},
    "jwt": {"label": "JWT", "root_cause": "JWT handling evidence permits weak algorithm, verification, or key-management behavior.", "attack_scenario": "An attacker could test tokens crafted for the detected weak verification or algorithm configuration.", "business_impact": "Weak token verification can undermine authentication and authorization decisions.", "recommendation": "Reject none, restrict approved algorithms, verify signatures and relevant claims, and use managed strong key material.", "patch_description": "Harden JWT verification and key handling.", "before": "JWT handling permits weak algorithm, verification, or embedded key behavior.", "after": "JWT verification pins approved algorithms, validates claims, and obtains key material from server-side configuration.", "verification": ["Confirm invalid, expired, wrong-audience, and none-algorithm tokens are rejected.", "Confirm key rotation and issuer/audience checks are reviewed where applicable."]},
    "rate_limiting": {"label": "Rate limiting", "root_cause": "A sensitive action lacks visible rate-limiting evidence in the supported static patterns.", "attack_scenario": "An attacker could repeatedly submit requests to test brute-force or resource-consumption resistance.", "business_impact": "Unbounded sensitive actions can enable abuse or increase service resource consumption.", "recommendation": "Apply rate limiting to authentication and sensitive actions, using shared storage across instances when deployed that way.", "patch_description": "Apply server-side rate limiting to the sensitive action.", "before": "Sensitive action has no visible rate-limit control.", "after": "Sensitive action enforces a reviewed limit using a non-client-controlled key strategy.", "verification": ["Confirm repeated requests are limited without blocking normal users.", "Confirm distributed deployments share the intended limit state."]},
    "redirect": {"label": "Redirect", "root_cause": "Direct request input reaches a redirect destination without visible validation.", "attack_scenario": "An attacker could supply an external or scheme-relative destination to test whether users are redirected off-site.", "business_impact": "Open redirects can support phishing and weaken trust in application links.", "recommendation": "Restrict redirects to normalized trusted relative paths or an explicit allowlist; reject external and scheme-relative destinations.", "patch_description": "Validate redirect destinations before redirecting.", "before": "Redirect destination comes directly from request input.", "after": "Redirect destination is normalized and checked against trusted relative paths or an allowlist.", "verification": ["Test external, scheme-relative, encoded, and allowed relative destinations.", "Confirm rejected destinations use a safe fallback."]},
    "filesystem": {"label": "Filesystem", "root_cause": "Raw request-controlled path data reaches a filesystem sink.", "attack_scenario": "An attacker could submit traversal-like path values to test whether access escapes an intended base directory.", "business_impact": "Path traversal can expose or alter files outside the intended application boundary.", "recommendation": "Resolve paths against a fixed base directory, verify containment, and reject raw request values that escape it.", "patch_description": "Contain filesystem access beneath a fixed base directory.", "before": "Filesystem sink receives a raw request-controlled path.", "after": "Path is normalized beneath an approved base directory and containment is verified before access.", "verification": ["Test traversal, absolute, encoded, and symlink-like path inputs.", "Confirm valid in-base paths remain accessible as intended."]},
    "command_execution": {"label": "Command execution", "root_cause": "Direct request input reaches a shell command execution sink.", "attack_scenario": "An attacker could supply command syntax to test whether the server executes unintended operations.", "business_impact": "Shell command injection can enable arbitrary command execution with the service account's privileges.", "recommendation": "Avoid shell execution; use fixed commands and argument arrays with shell disabled and explicit allowlists.", "patch_description": "Remove request-controlled shell execution.", "before": "Shell command sink receives direct request input.", "after": "Operation uses a fixed allowlisted action and argument array with shell execution disabled.", "verification": ["Confirm shell metacharacters and unapproved actions are rejected.", "Confirm no request value is concatenated into a shell command."]},
    "file_upload": {"label": "File upload", "root_cause": "Upload handling lacks visible type or size controls in the supported static patterns.", "attack_scenario": "An attacker could submit oversized or unexpected file content to test upload validation and storage handling.", "business_impact": "Unrestricted uploads can enable resource exhaustion or unsafe file handling.", "recommendation": "Enforce size and type controls, validate content rather than filename alone, generate server-side names, and avoid executable or public storage paths.", "patch_description": "Add explicit upload size, type, and storage controls.", "before": "Upload handler lacks visible size or type validation.", "after": "Upload handler enforces reviewed size and content-type controls with safe server-side storage.", "verification": ["Test oversized, malformed, and disallowed file content.", "Confirm stored files are non-executable and inaccessible by arbitrary path."]},
    "authentication": {"label": "Authentication", "root_cause": "Authentication evidence indicates a control that requires human review.", "attack_scenario": "An attacker could test whether the detected authentication control behaves as intended.", "business_impact": "Authentication weaknesses can affect access decisions.", "recommendation": "Review authentication control behavior and enforce a server-side verification boundary.", "patch_description": "Strengthen the detected authentication control.", "before": "Authentication control requires review.", "after": "Authentication control validates identity and rejects invalid input.", "verification": ["Confirm invalid and expired credentials are rejected."]},
}
