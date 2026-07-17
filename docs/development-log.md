# Development log

## 2026-07-18 — Milestone 5: Deterministic authorization analysis and BOLA detection

### Codex contribution

- Added modular handler-context extraction, ownership/membership/role control analysis, BOLA and conservative missing-authentication detectors, explainable risk scoring, stable findings, and authorization graphs.
- Extended the shared response, API, CLI summary, and existing frontend scan panel with authorization results and severity information.
- Added secure query, post-fetch comparison, membership, authorization-middleware, role, weak-mapping, ordering, stable-ID, missing-authentication, and TaskFlow integration tests.
- Documented decision rules, confidence, scoring, false-positive controls, response additions, and focused parser limitations.

### Human decisions

- Milestone 5 is deterministic static analysis only; no GPT/OpenAI call, patch, exploit, DAST, or target execution is authorized.
- A BOLA finding requires explicit client-identifier flow, direct model access, ownership metadata, and absence of concrete authorization controls.
- Authentication alone, user references used for unrelated work, 404 behavior, and suggestive middleware names are not authorization evidence.
- The bundled expected result is exactly one High `AUTH-BOLA` finding for `GET /api/projects/:id`.

### Tests run

- Backend pytest — 46 tests passed.
- Backend Ruff and strict mypy — passed for 38 Python source and test files.
- Frontend Vitest — 4 tests passed; ESLint and strict TypeScript passed.
- CLI JSON and summary modes — identified one stable `AUTH-BOLA-D1D193AD3E` finding with 98% confidence and risk score 82.
- Frontend production build and localhost API validation — passed.
- No command, dependency installation, script, migration, server, or HTTP request was run inside TaskFlow.

## 2026-07-18 — Milestone 4: Route, authentication, and Prisma model discovery

### Codex contribution

- Added focused Express route/mount parsing with normalized paths, ordered middleware propagation, stable route IDs, evidence, and warnings.
- Added behavior-based authentication and middleware classification, focused Prisma schema parsing, ownership-field candidates, and direct Prisma route-model mappings.
- Extended the shared scan response, API endpoints, JSON/summary CLI, and landing-page demonstration without adding findings or severity concepts.
- Added synthetic unit coverage plus bundled TaskFlow integration assertions and architecture documentation.

### Human decisions

- Milestone 4 remains static, deterministic, and read-only; TaskFlow is source input and is never executed by the scanner.
- Authentication and mapping claims require explicit source evidence; weak names and route nouns do not force conclusions.
- Ownership fields are candidates only. Vulnerability detection, BOLA/IDOR identification, GPT integration, exploitation, patches, and Milestone 5 remain out of scope.
- The real TaskFlow repository is the route source of truth, including `POST /api/login` and `GET /health`.

### Tests run

- Backend Ruff and strict mypy — passed for 27 Python source and test files.
- Backend pytest — 27 tests passed, including route, authentication, Prisma, mapping, safety, API, and bundled-demo integration coverage.
- Frontend ESLint and strict TypeScript — passed.
- Frontend Vitest — 4 tests passed, including sanitized demo-scan proxy behavior.
- Scanner CLI JSON and summary modes — successfully discovered 7 routes, 5 protected routes, 2 public routes, 4 Prisma models, Bearer authentication, ownership candidates, and route-model mappings.
- No commands, dependency installation, HTTP requests, scripts, migrations, or builds were run inside TaskFlow.

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
# 2026-07-18 — Milestone 7: Product Experience and TaskFlow Demo Interface

### Codex contribution

- Built a responsive demo-first Sentinel web shell, real TaskFlow scan launcher, honest pending state, security dashboard, searchable finding list, and detailed deterministic/AI review tabs.
- Kept the existing API and deterministic scanner contract unchanged; the UI reads real response values and never exposes local scan paths.
- Added frontend contract and rendering coverage and documented the demo workflow and deferrals.

### Human decisions

- The bundled TaskFlow AI scan is the only supported product workflow in this milestone.
- AI guidance remains optional and non-authoritative; generated patches remain review-required text proposals.
- GitHub cloning, ZIP input, history, exports, automated verification, and deployment are deferred to Milestone 8 or later.

### Tests run

- Frontend Vitest, ESLint, strict TypeScript, and production build.
- Backend pytest, Ruff, and strict mypy regression checks.
