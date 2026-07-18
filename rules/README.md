# Deterministic rule families

Sentinel AI rules emit authoritative findings only when direct structural evidence is present. The engine prefers no finding over a speculative result. Current rule families are focused on JavaScript and TypeScript source in Express and Next.js API-style applications.

## Implemented families

- Authorization: BOLA/IDOR and missing authentication analysis
- Secrets: private-key markers, recognizable API tokens, and explicit non-placeholder password or secret assignments
- CORS: wildcard origin combined with credentials and direct reflected request origins
- JWT: explicit `none` algorithm acceptance, disabled verification, hardcoded signing secrets, and direct unverified decode used as request identity
- Rate limiting: clearly sensitive Express routes with no visible application or route-level rate-limit signal
- Redirects: direct request-controlled redirect destinations
- Filesystem: direct request-controlled paths at filesystem sinks
- Command execution: direct request-controlled input or template interpolation at `exec`/`execSync` sinks
- File upload: multer-style handlers without visible type or size controls in the same file

## Confidence and limitations

New multi-rule findings are emitted only at medium or high confidence. They contain bounded source-line evidence, a relative path, remediation guidance, CWE/OWASP mapping, and a rule limitation. Secret values are redacted. Environment examples, tests, fixtures, documentation, generated content, and lockfiles are excluded.

These rules are experimental and intentionally narrow. They do not prove that a repository is secure, model infrastructure controls, or provide comprehensive OWASP coverage. Containment helpers, allowlists, framework abstractions, and indirect data flow may not be recognized.

The bundled TaskFlow demo remains a controlled single-BOLA fixture and is intentionally excluded from these additional families.
