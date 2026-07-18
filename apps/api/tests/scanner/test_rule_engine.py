"""Positive and negative fixtures for conservative multi-rule static detection."""

import pytest

from sentinel_api.scanner.models import IndexResult
from sentinel_api.scanner.rules import DeterministicRuleEngine


@pytest.mark.parametrize(
    ("rule_id", "source"),
    [
        ("SECRET-HARDCODED", 'const key = "-----BEGIN PRIVATE KEY-----\\nsecret";'),
        ("SECRET-TOKEN", 'const token = "sk-abcdefghijklmnopqrstuvwxyz0123456789";'),
        ("SECRET-PASSWORD", 'const password = "not-a-placeholder-secret";'),
        ("CORS-WILDCARD-CREDENTIALS", 'cors({ origin: "*", credentials: true });'),
        ("JWT-NONE-ALGORITHM", 'jwt.verify(token, key, { algorithms: ["none"] });'),
        ("JWT-VERIFY-DISABLED", "jwt.decode(token, { verify: false });"),
        ("JWT-DECODE-AUTH", "req.user = jwt.decode(token);"),
        ("JWT-HARDCODED-SECRET", 'jwt.sign(payload, "super-secret-value");'),
        ("REDIRECT-UNTRUSTED", "res.redirect(req.query.next);"),
        ("PATH-TRAVERSAL", "readFile(req.params.path);"),
        ("COMMAND-UNTRUSTED", "exec(req.body.command);"),
        ("COMMAND-SHELL-INTERPOLATION", "exec(`cat ${req.query.file}`);"),
        ("UPLOAD-UNRESTRICTED", "const upload = multer().single('file');"),
        ("RATE-SENSITIVE-ROUTE", "app.post('/login', handler);"),
    ],
)
def test_rule_engine_reports_only_structurally_evidenced_positive_cases(
    rule_id: str,
    source: str,
) -> None:
    findings = DeterministicRuleEngine().analyze(IndexResult(contents={"src/app.ts": source}))

    matching = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.source_file == "src/app.ts"
    assert finding.line_number == 1
    assert finding.confidence >= 0.7
    assert finding.evidence[0]
    assert not finding.source_file.startswith("/")


@pytest.mark.parametrize(
    "source",
    [
        'const token = "your_api_key";',
        'cors({ origin: "*" });',
        'jwt.verify(token, key, { algorithms: ["HS256"] });',
        'res.redirect("/account");',
        'spawn("git", ["status"], { shell: false });',
        "const upload = multer({ limits: { fileSize: 1000 }, fileFilter }).single('file');",
        "app.post('/login', rateLimit(), handler);",
    ],
)
def test_rule_engine_does_not_report_secure_or_edge_case_code(source: str) -> None:
    findings = DeterministicRuleEngine().analyze(IndexResult(contents={"src/app.ts": source}))

    assert findings == []


def test_secret_evidence_is_redacted_and_duplicate_findings_are_collapsed() -> None:
    secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    findings = DeterministicRuleEngine().analyze(
        IndexResult(
            contents={"src/app.ts": f'const first = "{secret}";\nconst second = "{secret}";'}
        )
    )

    assert len([finding for finding in findings if finding.rule_id == "SECRET-TOKEN"]) == 1
    assert secret not in findings[0].evidence[0]
