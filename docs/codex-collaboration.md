# Codex collaboration record

## 2026-07-18 — Milestone 3

The human defined a static-only repository metadata milestone and explicitly prohibited execution, dependency installation, vulnerability analysis, route discovery, authentication discovery, and model integration. Codex implemented those boundaries as separate loader, indexer, detector, service, API, and CLI components inside the existing FastAPI package.

Architectural choices included request-scoped scan-root configuration, `pathlib` containment checks, no symlink following, private in-memory inspection text separated from public Pydantic models, explicit file/read/depth budgets, evidence-backed confidence values, and shared orchestration for HTTP and CLI callers.

Verification uses both synthetic repositories for focused safety behavior and the real bundled TaskFlow AI repository for TypeScript, Express, npm, Prisma, SQLite, and entrypoint detection. The existing Sentinel frontend was deliberately left unchanged.

Ruff and strict mypy passed, all 19 backend tests passed, the existing 2 frontend tests passed with clean lint and type-check results, and the shared CLI produced the expected bundled-demo scan. No target-repository command was executed during Milestone 3.

## 2026-07-18 — Milestone 2

Codex implemented the TaskFlow AI demo from the human-defined scope and security boundary. The human explicitly selected the technology stack, fixed demo identities, API surface, and the single intentional BOLA behavior.

Codex kept the vulnerability isolated in the authenticated `GET /api/projects/:id` handler and labeled both its source code and tests. Owner-scoped project and task listing behavior was implemented separately to avoid accidental expansion of the flaw.

The collaboration intentionally excluded Sentinel analysis capabilities, model integration, authentication expansion, and changes to the existing Sentinel frontend design. Verification covers the build, schema lifecycle, seed records, safe authorization behavior, and the two expected cross-user access proofs.

### Verification performed

Codex generated and applied the initial Prisma migration, seeded and reset the local database, ran repository lint and strict type-check commands, passed 15 TaskFlow integration tests, compiled the production server, validated Docker Compose configuration, completed a localhost API smoke test, and confirmed a clean production dependency audit.
