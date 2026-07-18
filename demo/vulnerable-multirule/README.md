# Vulnerable Multi-Rule Demo

> ⚠️ Intentionally vulnerable security-testing fixture.

This project exists only to validate Sentinel AI's deterministic scanner.

## Safety boundary

- Local testing only
- Never deploy publicly
- Contains deliberately insecure code patterns
- Contains no real credentials
- Must not be used as an application template
- Scanner validation is static inspection only; do not execute the demo or its dangerous routes
- Do not install dependencies solely to run this fixture

## Included scanner categories

- Hardcoded secrets
- Dangerous CORS
- Weak JWT handling
- Missing rate limiting
- Open redirect
- Path traversal
- Command injection
- Unsafe file upload

The fixture does not claim comprehensive vulnerability detection or full OWASP coverage.
