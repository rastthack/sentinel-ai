# Development log

## 2026-07-18 — Milestone 3: Repository loader, file indexer, and framework detector

### Codex contribution

- Added a modular FastAPI scanner package with typed repository loading, bounded file indexing, language detection, technology evidence, entrypoint selection, shared orchestration, routes, and CLI.
- Added `POST /api/scans/repository` and `GET /api/scans/demo` using the same service layer.
- Added temporary-repository unit tests and integration coverage against the bundled TaskFlow AI repository.
- Documented scan-root configuration, API and CLI usage, safety limits, and current detection boundaries.

### Human decisions

- Milestone 3 is deterministic and static-only; scanned repositories are never executed or modified.
- `SENTINEL_SCAN_ROOT` is the hard filesystem boundary, with the Sentinel repository as the safe local default.
- Public responses contain relative paths, metadata, and evidence but never source contents or absolute server paths.
- Vulnerability, route, and authentication discovery plus GPT/OpenAI integration remain explicitly out of scope.
- The existing frontend remains unchanged; API and CLI output are the developer-facing demonstration for this milestone.

### Tests run

- Backend Ruff — passed.
- Strict backend mypy — passed for 17 source files.
- Backend pytest — 19 tests passed, including temporary-repository safety cases and both scan endpoints against the bundled demo.
- Scanner CLI — successfully scanned `demo/vulnerable-taskflow` and detected TypeScript, Express, npm, Prisma, SQLite, and both expected entrypoints.
- Existing frontend ESLint and strict TypeScript — passed.
- Existing frontend Vitest — 2 tests passed.
- No commands, dependency installation, builds, scripts, or migrations were run inside the scanned TaskFlow repository during this milestone.

## 2026-07-18 — Milestone 2: TaskFlow AI vulnerable demo

### Codex contribution

- Implemented the standalone TaskFlow AI Express/TypeScript application.
- Added Prisma models and SQLite migration infrastructure for users, projects, project members, and tasks.
- Added deterministic seed and guarded reset workflows for the two controlled demo users.
- Implemented Bearer Token authentication and the requested REST endpoints.
- Added integration coverage for authentication, owner-scoped lists, owned project access, missing projects, and both intentional cross-user BOLA cases.
- Added local Docker assets, setup documentation, and curl examples.

### Human decisions

- TaskFlow AI is a separate bundled demo application, not part of Sentinel AI.
- The demo uses fixed public credentials for User A and User B.
- Exactly one endpoint, `GET /api/projects/:id`, intentionally omits ownership enforcement.
- All other user-data endpoints remain correctly scoped.
- No Sentinel repository analysis, GPT-5.6 integration, or frontend redesign belongs in this milestone.

### Tests run

- `prisma generate` — passed with Prisma Client 7.8.0.
- `prisma migrate dev --name init` — created and applied the initial SQLite migration.
- `npm run db:seed` and `npm run db:reset` — passed against the local demo database.
- Root `npm run lint` — passed for Next.js, FastAPI, and TaskFlow AI.
- Root `npm run typecheck` — passed strict TypeScript and Python mypy checks.
- Monorepo `npm test` — 2 web tests, 1 API test, and 15 TaskFlow integration tests passed, including the owner-scoped dashboard and both intentional cross-user BOLA cases.
- Monorepo `npm run build` — passed the Next.js production build and TaskFlow TypeScript compilation.
- `docker compose config --quiet` — passed configuration validation.
- Compiled-server smoke test — health returned 200, User A listed only Project A, and the controlled BOLA request returned Project B to User A as intended.
- `npm audit --omit=dev` — found zero production dependency vulnerabilities.
