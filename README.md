# Sentinel AI

> **Find it. Prove it. Fix it. Verify it.**

Sentinel AI is an evidence-driven security reviewer for AI-generated web applications. This repository contains the Next.js interface, FastAPI service, and a bundled controlled demo target.

Milestone 4 adds safe, deterministic application-structure discovery. Sentinel now maps Express routes and middleware, classifies authentication from concrete source behavior, parses the focused Prisma schema surface, identifies ownership-field candidates, and associates direct Prisma operations with routes. Vulnerability detection, exploit reproduction, GPT integration, and patch generation are intentionally not implemented.

## Static repository scanner

The FastAPI service can inventory an allowed local repository and detect languages, technologies, entrypoints, Express routes, authentication controls, Prisma models, ownership candidates, and direct route-to-model operations from static evidence:

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
```

## Bundled vulnerable demo

[TaskFlow AI](demo/vulnerable-taskflow/README.md) is a separate, realistic Express/TypeScript project-management SaaS application bundled under `demo/vulnerable-taskflow`. It intentionally contains exactly one documented BOLA vulnerability in `GET /api/projects/:id` for future, controlled Sentinel AI validation.

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

This foundation does not execute repository code or model-generated commands. Structure discovery does not make vulnerability claims. Future validation must target only localhost or allowlisted bundled demos, secrets must never be sent to a model, and generated patches must remain reviewable proposals applied to temporary copies. See [the scanner architecture](docs/scanner-architecture.md) for supported syntax and limitations.
