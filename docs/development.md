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
- API health endpoint: `http://127.0.0.1:8000/health`
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
