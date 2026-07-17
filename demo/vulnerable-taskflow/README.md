# TaskFlow AI

TaskFlow AI is a realistic project-management SaaS demo built with Express, TypeScript, Prisma, and SQLite. It is bundled with Sentinel AI as a controlled security-review target, but it is an independent application—not part of the Sentinel AI product.

> [!WARNING]
> This application is intentionally vulnerable. Run it only on localhost or in an isolated development environment. Do not deploy it to a public or production system.

## Intentional security flaw

Exactly one route contains a known Broken Object Level Authorization (BOLA) vulnerability:

```text
GET /api/projects/:id
```

The route requires a valid Bearer token but retrieves a project using only its `id`. It intentionally omits the required `ownerId` constraint. All project-list, task-list, and profile queries are scoped to the authenticated user.

This defect is isolated and covered by explicitly named integration tests. Do not “fix” it until a future Sentinel AI remediation milestone calls for a reviewed patch in a temporary copy.

## Features and structure

- Demo login and Bearer Token authentication
- User profile data
- Project dashboard data
- Owner-scoped project and task lists
- Project details, members, and tasks
- Deterministic SQLite seed data
- Express middleware, route modules, and centralized error handling
- Prisma migrations and typed database access
- Vitest and Supertest integration tests
- Local Docker Compose deployment

```text
src/app.ts                 Express composition root
src/middleware/            Authentication and error handling
src/routes/                REST resource routes
src/db/seed-data.ts        Deterministic seed/reset logic
prisma/schema.prisma       Database models
prisma/migrations/         Checked-in database migrations
tests/                     API integration coverage
```

## Local setup

Requirements: Node.js 22 or newer and npm 10 or newer.

```bash
cd demo/vulnerable-taskflow
cp .env.example .env
npm install
npm run prisma:generate
npm run db:migrate
npm run db:seed
npm run dev
```

TaskFlow AI listens on `http://127.0.0.1:4000` by default.

Reset the local database to its deterministic demo state:

```bash
npm run db:reset
```

The reset script refuses to run unless `DATABASE_URL` uses a local SQLite `file:` URL.

## Demo users

| User | ID | Email | Bearer token |
| --- | --- | --- | --- |
| User A | `user-a` | `user_a@example.test` | `user-a-demo-token` |
| User B | `user-b` | `user_b@example.test` | `user-b-demo-token` |

These are public, non-secret credentials for the controlled demo only.

## REST API

| Method | Path | Authentication | Behavior |
| --- | --- | --- | --- |
| `GET` | `/health` | None | Service health |
| `POST` | `/api/login` | Demo email and token | Validate demo credentials and return a session payload |
| `GET` | `/api/dashboard` | Bearer | Owner-scoped project and task aggregates |
| `GET` | `/api/projects` | Bearer | Correctly lists owned projects |
| `GET` | `/api/projects/:id` | Bearer | Intentionally vulnerable project lookup |
| `GET` | `/api/tasks` | Bearer | Correctly lists tasks in owned projects |
| `GET` | `/api/profile` | Bearer | Current user profile and counts |

## curl examples

Health and login:

```bash
curl --fail http://127.0.0.1:4000/health

curl --fail \
  --header 'Content-Type: application/json' \
  --data '{"email":"user_a@example.test","token":"user-a-demo-token"}' \
  http://127.0.0.1:4000/api/login
```

Correctly scoped lists:

```bash
curl --fail \
  --header 'Authorization: Bearer user-a-demo-token' \
  http://127.0.0.1:4000/api/projects

curl --fail \
  --header 'Authorization: Bearer user-a-demo-token' \
  http://127.0.0.1:4000/api/tasks
```

Controlled reproduction of the intentional BOLA—User A requests User B's project:

```bash
curl --fail \
  --header 'Authorization: Bearer user-a-demo-token' \
  http://127.0.0.1:4000/api/projects/project-b
```

The final request intentionally returns HTTP 200 and Project B. Use it only against this localhost demo.

## Quality checks

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## Docker

```bash
docker compose up --build
```

The compose configuration publishes only to `127.0.0.1:4000` and stores SQLite data in a named volume. The container applies checked-in migrations and seeds the deterministic demo records on startup.

Stop and remove the container while preserving its volume:

```bash
docker compose down
```
