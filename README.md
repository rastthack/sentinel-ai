# Sentinel AI

> **Find it. Prove it. Fix it. Verify it.**

Sentinel AI is an evidence-driven security reviewer for AI-generated web applications. This repository contains the Next.js interface, FastAPI service, and a bundled controlled demo target.

## TaskFlow demo experience

Milestone 7 provides a one-click, demo-first security review in the web app. Run `npm run dev:api` and `npm run dev:web`, open `http://localhost:3000`, then select **Run TaskFlow Demo Scan**. The UI uses the real bundled-demo scan response and clearly separates deterministic evidence from optional AI guidance and review-required patch proposals.

Public GitHub repository scanning is available for HTTPS GitHub repository URLs. ZIP upload, scan history, exports, deployment, and automatic remediation verification are intentionally deferred. TaskFlow AI remains a bundled intentionally vulnerable demo, not a customer repository.

Milestone 6 keeps deterministic static authorization findings as the source of truth and adds an opt-in, structured GPT-5.6 Sol explanation layer. It can explain an existing finding and propose a minimal review-required diff; it never creates findings, executes targets, applies patches, or performs exploit reproduction.

## Static repository scanner

The FastAPI service inventories an allowed local repository, discovers its application structure, and performs conservative authorization analysis from static evidence:

```bash
curl --fail http://127.0.0.1:8000/api/scans/demo

curl --fail \
  --header 'Content-Type: application/json' \
  --data '{"repository_path":"demo/vulnerable-taskflow"}' \
  http://127.0.0.1:8000/api/scans/repository
```

The scanner never executes repository code, installs target dependencies, returns file contents, or exposes absolute server paths. `SENTINEL_SCAN_ROOT` bounds every requested path; when unset, local development is limited to this Sentinel repository.

Run the same service without the frontend or HTTP server:

```bash
apps/api/.venv/bin/python -m sentinel_api.scanner.cli demo/vulnerable-taskflow

apps/api/.venv/bin/python -m sentinel_api.scanner.cli \
  demo/vulnerable-taskflow --format summary

# Opt in to an explanation only when OPENAI_API_KEY is configured server-side.
apps/api/.venv/bin/python -m sentinel_api.scanner.cli \
  demo/vulnerable-taskflow --explain --format summary
```

## Bundled vulnerable demo

[TaskFlow AI](demo/vulnerable-taskflow/README.md) is a separate, realistic Express/TypeScript project-management SaaS application bundled under `demo/vulnerable-taskflow`. It intentionally contains exactly one documented BOLA vulnerability in `GET /api/projects/:id`, which Sentinel now identifies through deterministic static analysis.

TaskFlow AI is not Sentinel AI. It must remain localhost-only and must never be deployed to a public or production environment.

## Repository layout

```text
apps/web/                 Next.js, TypeScript, and Tailwind CSS
apps/api/                 FastAPI, Pydantic, pytest, Ruff, and mypy
demo/vulnerable-taskflow/ TaskFlow AI controlled vulnerable demo
docs/                     Architecture and development documentation
rules/                    Future deterministic security rules
scripts/                  Future safe automation helpers
```

## Prerequisites

- Node.js 22 or newer and npm 10 or newer
- Python 3.12 or newer

## Setup

```bash
cp .env.example .env
npm install
python3 -m venv apps/api/.venv
apps/api/.venv/bin/python -m pip install -e 'apps/api[dev]'
```

Start both services in separate terminals:

```bash
npm run dev:web
npm run dev:api
```

Open [http://localhost:3000](http://localhost:3000). The status and Application Structure Discovery panels use server-side Next.js proxy routes to reach FastAPI at `API_URL`. This keeps backend configuration and any future credentials out of browser code.

## Quality checks

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

The root commands run checks for both applications. See [docs/development.md](docs/development.md) for individual commands and troubleshooting.

## Security boundaries

The optional AI layer is disabled by default (`SENTINEL_AI_ENABLED=false`). When enabled, `OPENAI_API_KEY` remains server-side and the configured model defaults to `gpt-5.6-sol`; no `.env` files, credentials, absolute paths, or source contents are included in its prompt. Responses are validated as plain structured data and cached only in an application-owned cache location, never in a scan target. Generated diffs are review-required proposals and are never applied. Future dynamic validation must target only localhost or allowlisted bundled demos. See [the scanner architecture](docs/scanner-architecture.md) for decision rules and limitations.
