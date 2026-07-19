"""Positive and negative fixtures for conservative multi-rule static detection."""

import pytest

from sentinel_api.scanner.models import IndexResult
from sentinel_api.scanner.rules import DeterministicRuleEngine


@pytest.mark.parametrize(
    ("rule_id", "source"),
    [
        ("SECRET-HARDCODED", 'const key = "-----BEGIN PRIVATE KEY-----\\nsecret";'),
        ("SECRET-TOKEN", 'const token = "sk-abcdefghijklmnopqrstuvwxyz0123456789";'),
        ("SECRET-PASSWORD", 'const password = "not-a-real-secret-value";'),
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


@pytest.mark.parametrize(
    "source",
    [
        'const RESET_PASSWORD = "resetPassword";',
        'const VERIFY_EMAIL = "verifyEmail";',
        'const ACCESS_TOKEN = "accessToken";',
        'const REFRESH_TOKEN = "refreshToken";',
        'const PASSWORD_RESET = "passwordReset";',
        'const EMAIL_VERIFICATION = "emailVerification";',
        'const password = "change_me";',
        'const secret = "replace-with-secret";',
        'const password = "not-a-placeholder-value";',
    ],
)
def test_secret_rules_suppress_semantic_labels_and_placeholders(source: str) -> None:
    findings = DeterministicRuleEngine().analyze(
        IndexResult(contents={"src/config/tokens.js": source})
    )

    assert [finding for finding in findings if finding.category == "secrets"] == []


def test_secret_rules_suppress_weak_semantic_labels_in_test_paths() -> None:
    findings = DeterministicRuleEngine().analyze(
        IndexResult(contents={"tests/tokens.test.ts": 'const RESET_PASSWORD = "resetPassword";'})
    )

    assert [finding for finding in findings if finding.category == "secrets"] == []


@pytest.mark.parametrize(
    "source",
    [
        'const invalidPasswordErrorMessage = "Invalid password";',
        'const passwordError = "Password is incorrect";',
        'const passwordLabel = "Enter your password";',
        'const passwordDescription = "Password must contain 8 characters";',
        'const secretWarning = "Do not share your secret";',
        'const passwordValidationMessage = "Password is required";',
    ],
)
def test_secret_rules_suppress_descriptive_password_and_secret_text(source: str) -> None:
    findings = DeterministicRuleEngine().analyze(
        IndexResult(contents={"app/routes/session.js": source})
    )

    assert [finding for finding in findings if finding.rule_id == "SECRET-PASSWORD"] == []


def test_secret_rules_lower_confidence_for_weak_generic_test_passwords() -> None:
    findings = DeterministicRuleEngine().analyze(
        IndexResult(contents={"tests/config.test.ts": 'const PASSWORD = "development-password";'})
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SECRET-PASSWORD"
    assert findings[0].confidence == 0.70
    assert findings[0].severity == "medium"
    assert findings[0].risk_score == 60


@pytest.mark.parametrize(
    ("path", "source", "rule_id"),
    [
        (
            "src/config/jwt.ts",
            'const JWT_SECRET = "p9X2mK7qL4vN8sR1Zc6Yh3Qa";',
            "SECRET-PASSWORD",
        ),
        (
            "src/config/auth.ts",
            'const PASSWORD = "Tr0ub4dor&3-Production-Only";',
            "SECRET-PASSWORD",
        ),
        (
            "src/config/database.ts",
            'const databasePassword = "prod-db-password-9382";',
            "SECRET-PASSWORD",
        ),
        (
            "src/config/token.ts",
            'const API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";',
            "SECRET-TOKEN",
        ),
        (
            "src/config/key.ts",
            'const PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";',
            "SECRET-HARDCODED",
        ),
        (
            "fixtures/credentials.ts",
            'const PASSWORD = "Tr0ub4dor&3-Production-Only";',
            "SECRET-PASSWORD",
        ),
    ],
)
def test_secret_rules_preserve_strong_credentials_in_all_supported_paths(
    path: str, source: str, rule_id: str
) -> None:
    findings = DeterministicRuleEngine().analyze(IndexResult(contents={path: source}))

    assert [finding.rule_id for finding in findings] == [rule_id]
    assert findings[0].severity == "high"


def test_secret_rules_keep_high_entropy_fixture_credentials_high_severity() -> None:
    findings = DeterministicRuleEngine().analyze(
        IndexResult(
            contents={"fixtures/jwt.ts": 'const JWT_SECRET = "p9X2mK7qL4vN8sR1Zc6Yh3Qa";'}
        )
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SECRET-PASSWORD"
    assert findings[0].confidence == 0.93
    assert findings[0].severity == "high"
