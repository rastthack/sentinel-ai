# Development setup

## Install dependencies

From the repository root:

```bash
cp .env.example .env
npm install
python3 -m venv apps/api/.venv
apps/api/.venv/bin/python -m pip install -e 'apps/api[dev]'
```

The local `.env` file is ignored by Git. It must not contain browser-visible secrets, be committed, or be included in any future model context.

## Run locally

Terminal one:

```bash
npm run dev:api
```

Terminal two:

```bash
npm run dev:web
```

Useful endpoints:

- Web UI: `http://localhost:3000`
- Frontend health proxy: `http://localhost:3000/api/health`
- Frontend demo-scan proxy: `http://localhost:3000/api/scans/demo`
- API health endpoint: `http://127.0.0.1:8000/health`
- Bundled static scan: `http://127.0.0.1:8000/api/scans/demo`
- Interactive API docs: `http://127.0.0.1:8000/docs`

The web proxy uses `API_URL` on the server. FastAPI accepts direct browser requests only from origins listed in `CORS_ORIGINS`.

## Checks

Run all checks from the root:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Or run an application independently:

```bash
npm run lint --workspace @sentinel/web
npm run typecheck --workspace @sentinel/web
npm run test --workspace @sentinel/web

apps/api/.venv/bin/ruff check apps/api
apps/api/.venv/bin/mypy apps/api/src apps/api/tests
apps/api/.venv/bin/pytest apps/api
```

If the frontend reports that the API is unavailable, confirm FastAPI is running and that `API_URL` is reachable from the Next.js server process.

## TaskFlow AI demo

TaskFlow AI has an independent dependency set and database lifecycle:

```bash
cd demo/vulnerable-taskflow
cp .env.example .env
npm install
npm run prisma:generate
npm run db:migrate
npm run db:seed
npm run dev
```

The demo listens only on `127.0.0.1:4000` by default. It is intentionally vulnerable and must not be exposed publicly. See its [dedicated README](../demo/vulnerable-taskflow/README.md) for credentials, API examples, Docker setup, and the exact vulnerability boundary.

## Static repository scanner

`SENTINEL_SCAN_ROOT` defines the only directory tree the backend may inspect. Leave it empty for the source-layout default—the Sentinel repository root—or set it to an explicit absolute path:

```bash
SENTINEL_SCAN_ROOT=/absolute/path/to/sentinel-ai npm run dev:api
```

Scan the bundled demo over HTTP:

```bash
curl --fail http://127.0.0.1:8000/api/scans/demo

curl --fail \
  --header 'Content-Type: application/json' \
  --data '{"repository_path":"demo/vulnerable-taskflow"}' \
  http://127.0.0.1:8000/api/scans/repository
```

Run the shared service through the CLI from the repository root:

```bash
apps/api/.venv/bin/python -m sentinel_api.scanner.cli demo/vulnerable-taskflow
apps/api/.venv/bin/python -m sentinel_api.scanner.cli \
  demo/vulnerable-taskflow --format summary
```

Or from `apps/api`:

```bash
.venv/bin/python -m sentinel_api.scanner.cli ../../demo/vulnerable-taskflow

PYTHONPATH=src python -m sentinel_api.scanner.cli \
  ../../demo/vulnerable-taskflow --format summary

# Equivalent after installing the sentinel_api package in the environment:
python -m sentinel_api.scanner.cli \
  ../../demo/vulnerable-taskflow --format summary
```

The scanner is static and read-only. It rejects traversal, filesystem root, files, missing paths, and paths outside the configured root. It does not follow symlinks, inspect environment files, keys, certificates, binaries, or databases, and it never returns file contents or absolute paths. Default budgets are 5,000 files, 1 MB per file, 10 MB total inspected text, and 20 directory levels; skipped files and reached limits are reported as metadata or warnings.

Structure discovery is deterministic and does not start TaskFlow, install its dependencies, issue target HTTP requests, or make vulnerability findings. Express parsing covers common literal routes, router factories, mounts, and ordered middleware. Authentication classification requires source evidence. Prisma parsing intentionally supports the syntax used by the bundled demo rather than the complete Prisma grammar. Route-model mapping currently requires a direct `prisma.<delegate>.<operation>` call in an inline handler; it does not chase arbitrary service or repository call graphs.

See [scanner-architecture.md](scanner-architecture.md) for discovery rules, evidence policy, and known limitations.

Scanner-focused checks:

```bash
apps/api/.venv/bin/pytest apps/api/tests/scanner
apps/api/.venv/bin/ruff check apps/api
apps/api/.venv/bin/mypy apps/api/src apps/api/tests
```
