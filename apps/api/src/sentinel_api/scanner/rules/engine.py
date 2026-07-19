"""Small, conservative multi-family deterministic rule engine."""
# ruff: noqa: E501

import hashlib
import re
from collections.abc import Iterable
from typing import Literal

from sentinel_api.scanner.analysis.models import AuthorizationFinding, RiskScoreComponent
from sentinel_api.scanner.models import IndexResult
from sentinel_api.scanner.redaction import redact_sensitive_text
from sentinel_api.scanner.rules.models import RuleCategory, RuleDefinition, SecurityRule

_PLACEHOLDERS = frozenset(
    {"changeme", "example", "your_api_key", "your-api-key", "placeholder", "test"}
)


class DeterministicRuleEngine:
    """Run high-confidence source-structural rules and deterministically deduplicate output."""

    def __init__(self, rules: Iterable[SecurityRule] | None = None) -> None:
        self.rules = list(rules or _default_rules())

    def analyze(self, index: IndexResult) -> list[AuthorizationFinding]:
        findings = [finding for rule in self.rules for finding in rule.analyze(index)]
        deduplicated = {finding.finding_id: finding for finding in findings}
        return sorted(
            deduplicated.values(),
            key=lambda item: (item.rule_id, item.source_file, item.line_number),
        )


class _PatternRule:
    """Reusable structural pattern rule; patterns require all evidence groups on one source file."""

    def __init__(
        self,
        definition: RuleDefinition,
        required_patterns: tuple[re.Pattern[str], ...],
        *,
        source_pattern: re.Pattern[str] | None = None,
        forbidden_pattern: re.Pattern[str] | None = None,
        recommendation: str,
        confidence: float,
        redact: bool = False,
        route_sensitive: bool = False,
    ) -> None:
        self.definition = definition
        self.required_patterns = required_patterns
        self.source_pattern = source_pattern
        self.forbidden_pattern = forbidden_pattern
        self.recommendation = recommendation
        self.confidence = confidence
        self.redact = redact
        self.route_sensitive = route_sensitive

    def analyze(self, index: IndexResult) -> list[AuthorizationFinding]:
        results: list[AuthorizationFinding] = []
        for path, content in sorted(index.contents.items()):
            if not _supported(path) or _excluded(path):
                continue
            matches = [pattern.search(content) for pattern in self.required_patterns]
            if not all(matches):
                continue
            primary = next(match for match in matches if match is not None)
            if self.source_pattern is not None and self.source_pattern.search(content) is None:
                continue
            if self.forbidden_pattern is not None and self.forbidden_pattern.search(content):
                continue
            excerpt = _excerpt(content, primary.start(), redact=self.redact)
            if self.redact and _placeholder_assignment(excerpt):
                continue
            results.append(
                _finding(
                    self.definition,
                    path,
                    content,
                    primary.start(),
                    excerpt,
                    self.recommendation,
                    self.confidence,
                )
            )
        return results


class _SensitiveRateLimitRule:
    definition = RuleDefinition(
        rule_id="RATE-SENSITIVE-ROUTE",
        title="Sensitive Route Lacks Visible Rate Limiting",
        category="rate_limiting",
        severity="medium",
        cwe=["CWE-770"],
        owasp_mapping=["OWASP API4:2023 Unrestricted Resource Consumption"],
        supported_languages=["JavaScript", "TypeScript"],
        supported_frameworks=["Express"],
        limitations="Infrastructure and gateway rate limits are not visible to this static rule.",
    )

    def analyze(self, index: IndexResult) -> list[AuthorizationFinding]:
        all_content = "\n".join(index.contents.values())
        if re.search(r"rateLimit|express-rate-limit|throttle", all_content, re.I):
            return []
        sensitive = re.compile(
            r"\.(?:post|put)\s*\(\s*[`\"']([^`\"']*(?:login|register|password|reset|otp|token)[^`\"']*)",
            re.I,
        )
        results: list[AuthorizationFinding] = []
        for path, content in sorted(index.contents.items()):
            if not _supported(path):
                continue
            match = sensitive.search(content)
            if match:
                results.append(
                    _finding(
                        self.definition,
                        path,
                        content,
                        match.start(),
                        _excerpt(content, match.start()),
                        "Apply route- or application-level rate limiting to this sensitive endpoint.",
                        0.70,
                    )
                )
        return results


def _default_rules() -> list[SecurityRule]:
    js = ["JavaScript", "TypeScript"]
    express = ["Express", "Next.js API routes"]

    def rule(
        rule_id: str,
        title: str,
        category: RuleCategory,
        severity: Literal["medium", "high", "critical"],
        cwe: str,
        owasp: str,
        limitations: str,
    ) -> RuleDefinition:
        return RuleDefinition(
            rule_id=rule_id,
            title=title,
            category=category,
            severity=severity,
            cwe=[cwe],
            owasp_mapping=[owasp],
            supported_languages=js,
            supported_frameworks=express,
            limitations=limitations,
        )

    return [
        _PatternRule(
            rule(
                "SECRET-HARDCODED",
                "Likely Hardcoded Secret",
                "secrets",
                "high",
                "CWE-798",
                "OWASP A02:2021 Cryptographic Failures",
                "Only recognizable tokens and non-placeholder secret assignments are detected.",
            ),
            (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),),
            recommendation="Move the credential to a server-side secret manager or environment configuration and rotate it.",
            confidence=0.98,
            redact=True,
        ),
        _PatternRule(
            rule(
                "SECRET-TOKEN",
                "Likely Hardcoded API Token",
                "secrets",
                "high",
                "CWE-798",
                "OWASP A07:2021 Identification and Authentication Failures",
                "Only recognizable token formats or explicit non-placeholder assignments are detected.",
            ),
            (re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})"),),
            recommendation="Remove and rotate the exposed token; load it from server-side secret configuration.",
            confidence=0.98,
            redact=True,
        ),
        _PatternRule(
            rule(
                "SECRET-PASSWORD",
                "Likely Hardcoded Password or Secret",
                "secrets",
                "high",
                "CWE-798",
                "OWASP A07:2021 Identification and Authentication Failures",
                "Only explicit non-placeholder password or secret assignments are detected.",
            ),
            (
                re.compile(
                    r"(?:password|secret)\s*[:=]\s*['\"](?!changeme|example|your_api_key)[^'\"]{8,}['\"]",
                    re.I,
                ),
            ),
            recommendation="Move the credential to server-side secret configuration and rotate it.",
            confidence=0.93,
            redact=True,
        ),
        _PatternRule(
            rule(
                "CORS-WILDCARD-CREDENTIALS",
                "Wildcard CORS Origin with Credentials",
                "cors",
                "high",
                "CWE-942",
                "OWASP A05:2021 Security Misconfiguration",
                "Only configurations containing both wildcard origin and credential support are reported.",
            ),
            (
                re.compile(r"origin\s*:\s*['\"]\*['\"]", re.I),
                re.compile(r"credentials\s*:\s*true", re.I),
            ),
            recommendation="Use an explicit allowlist of trusted origins and avoid wildcard origins when credentials are enabled.",
            confidence=0.95,
        ),
        _PatternRule(
            rule(
                "CORS-REFLECTED-ORIGIN",
                "Unvalidated Reflected CORS Origin",
                "cors",
                "high",
                "CWE-942",
                "OWASP A05:2021 Security Misconfiguration",
                "Only direct reflection of the request Origin into a CORS response is detected.",
            ),
            (
                re.compile(
                    r"(?:origin|Access-Control-Allow-Origin).*?(?:req|request)\.headers\.origin",
                    re.I,
                ),
            ),
            recommendation="Validate request origins against a strict allowlist before reflecting them.",
            confidence=0.90,
        ),
        _PatternRule(
            rule(
                "JWT-NONE-ALGORITHM",
                "JWT None Algorithm Accepted",
                "jwt",
                "high",
                "CWE-347",
                "OWASP A02:2021 Cryptographic Failures",
                "Only explicit acceptance of the none algorithm is detected.",
            ),
            (re.compile(r"algorithms?\s*:\s*\[[^\]]*['\"]none['\"]", re.I),),
            recommendation="Reject the none algorithm and pin an expected signed algorithm during verification.",
            confidence=0.98,
        ),
        _PatternRule(
            rule(
                "JWT-VERIFY-DISABLED",
                "JWT Signature Verification Disabled",
                "jwt",
                "high",
                "CWE-347",
                "OWASP A02:2021 Cryptographic Failures",
                "Only explicit disabled signature verification is detected.",
            ),
            (re.compile(r"(?:verify|signature)\w*\s*:\s*false", re.I),),
            recommendation="Require signature verification with a pinned algorithm and trusted key material.",
            confidence=0.98,
        ),
        _PatternRule(
            rule(
                "JWT-HARDCODED-SECRET",
                "Hardcoded JWT Signing Secret",
                "jwt",
                "high",
                "CWE-798",
                "OWASP A02:2021 Cryptographic Failures",
                "Only direct non-placeholder signing or verification secrets are detected.",
            ),
            (
                re.compile(
                    r"jwt\.(?:sign|verify)\s*\([^,]+,\s*['\"](?!changeme|example|your_api_key)[^'\"]{8,}['\"]",
                    re.I,
                ),
            ),
            recommendation="Load JWT key material from server-side secret configuration and rotate the embedded secret.",
            confidence=0.95,
            redact=True,
        ),
        _PatternRule(
            rule(
                "JWT-DECODE-AUTH",
                "Unverified JWT Decode Used for Authentication",
                "jwt",
                "high",
                "CWE-347",
                "OWASP A07:2021 Identification and Authentication Failures",
                "Only direct assignment of jwt.decode output to request authentication state is detected.",
            ),
            (re.compile(r"(?:req|request)\.(?:user|auth\w*)\s*=\s*jwt\.decode\s*\(", re.I),),
            recommendation="Use jwt.verify with a trusted key and pinned algorithm before attaching identity to the request.",
            confidence=0.95,
        ),
        _PatternRule(
            rule(
                "REDIRECT-UNTRUSTED",
                "Untrusted Input Reaches Redirect",
                "redirect",
                "high",
                "CWE-601",
                "OWASP A01:2021 Broken Access Control",
                "Only direct request query, parameter, body, or header values passed to a redirect sink are detected.",
            ),
            (
                re.compile(
                    r"(?:redirect|res\.redirect)\s*\(\s*(?:req|request)\.(?:query|params|body|headers)",
                    re.I,
                ),
            ),
            recommendation="Validate redirect destinations against an allowlist or restrict them to normalized same-origin relative paths.",
            confidence=0.92,
        ),
        _PatternRule(
            rule(
                "PATH-TRAVERSAL",
                "Request-Controlled Path Reaches Filesystem Sink",
                "filesystem",
                "high",
                "CWE-22",
                "OWASP A01:2021 Broken Access Control",
                "Only direct request-controlled paths at filesystem sinks are detected; containment helpers may not be recognized.",
            ),
            (
                re.compile(
                    r"(?:readFile|writeFile|createReadStream|createWriteStream|unlink|sendFile)\s*\(\s*(?:req|request)\.(?:params|query|body)",
                    re.I,
                ),
            ),
            recommendation="Resolve paths beneath an approved base directory and verify containment before filesystem access.",
            confidence=0.92,
        ),
        _PatternRule(
            rule(
                "COMMAND-UNTRUSTED",
                "Request-Controlled Input Reaches Shell Command",
                "command_execution",
                "critical",
                "CWE-78",
                "OWASP A03:2021 Injection",
                "Only direct request input at exec or execSync sinks is detected; argument-array execution without a shell is excluded.",
            ),
            (re.compile(r"exec(?:Sync)?\s*\(\s*(?:req|request)\.(?:params|query|body)", re.I),),
            recommendation="Avoid shell command construction. Use fixed argument arrays with shell disabled and strict allowlists.",
            confidence=0.98,
        ),
        _PatternRule(
            rule(
                "COMMAND-SHELL-INTERPOLATION",
                "Constructed Shell Command Uses Request Input",
                "command_execution",
                "critical",
                "CWE-78",
                "OWASP A03:2021 Injection",
                "Only template interpolation of direct request values into an exec sink is detected.",
            ),
            (re.compile(r"exec(?:Sync)?\s*\(\s*`[^`]*\$\{\s*(?:req|request)\.", re.I),),
            recommendation="Avoid shell command construction. Use fixed argument arrays with shell disabled and strict allowlists.",
            confidence=0.98,
        ),
        _PatternRule(
            rule(
                "UPLOAD-UNRESTRICTED",
                "Upload Handler Lacks Visible Type and Size Controls",
                "file_upload",
                "high",
                "CWE-434",
                "OWASP A04:2021 Insecure Design",
                "Only multer-style handlers with no visible size or fileFilter controls in the same file are detected.",
            ),
            (re.compile(r"multer\s*\(\s*\)\s*\.\s*(?:single|array|any)\s*\(", re.I),),
            forbidden_pattern=re.compile(r"(?:limits\s*:|fileFilter\s*:)", re.I),
            recommendation="Enforce file size limits and strict MIME type and extension allowlists before storing uploads.",
            confidence=0.85,
        ),
        _SensitiveRateLimitRule(),
    ]


def _finding(
    definition: RuleDefinition,
    path: str,
    content: str,
    offset: int,
    excerpt: str,
    recommendation: str,
    confidence: float,
) -> AuthorizationFinding:
    line = content.count("\n", 0, offset) + 1
    fingerprint = f"{definition.rule_id}|{path}|{line}"
    identifier = hashlib.sha256(fingerprint.encode()).hexdigest()[:12].upper()
    return AuthorizationFinding(
        finding_id=f"{definition.rule_id}-{identifier}",
        rule_id=definition.rule_id,
        title=definition.title,
        category=definition.category,
        severity=definition.severity,
        confidence=confidence,
        status="open",
        route_id=f"file:{path}",
        method=None,
        path=None,
        model=None,
        operation="unknown",
        ownership_candidate=None,
        source_file=path,
        line_number=line,
        description=f"{definition.title} is structurally evidenced in this source file.",
        evidence=[excerpt, f"Rule limitation: {definition.limitations}"],
        recommendation=recommendation,
        cwe=definition.cwe,
        owasp=definition.owasp_mapping,
        risk_score={"medium": 60, "high": 78, "critical": 90}[definition.severity],
        risk_components=[
            RiskScoreComponent(
                name="structural_rule_evidence",
                points={"medium": 60, "high": 78, "critical": 90}[definition.severity],
            )
        ],
    )


def _supported(path: str) -> bool:
    return path.endswith((".js", ".jsx", ".ts", ".tsx"))


def _excluded(path: str) -> bool:
    lower = path.casefold()
    return (
        ".env.example" in lower
        or "/test" in lower
        or ".test." in lower
        or ".spec." in lower
        or "/fixtures/" in lower
        or "/docs/" in lower
        or lower.endswith(("lock", ".lock"))
    )


def _excerpt(content: str, offset: int, *, redact: bool = False) -> str:
    line = content.splitlines()[content.count("\n", 0, offset)] if content.splitlines() else ""
    bounded = line.strip()[:300]
    if redact:
        bounded = redact_sensitive_text(bounded).replace("[REDACTED_API_KEY]", "<redacted>")
        bounded = bounded.replace("[REDACTED]", "<redacted>")
    return bounded or "Structural insecure configuration evidence detected"


def _placeholder_assignment(excerpt: str) -> bool:
    return any(value in excerpt.casefold() for value in _PLACEHOLDERS)
