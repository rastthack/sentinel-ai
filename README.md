# Sentinel AI

## Evidence-Backed AI Security Reviews

> **Find it. Prove it. Fix it. Verify it.**

![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?logo=fastapi)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)

Sentinel AI combines conservative deterministic security analysis with bounded evidence and AI-assisted security guidance to help developers understand vulnerabilities, assess their impact, and review practical remediation—while keeping deterministic findings authoritative.

**Demo Video:** _Placeholder — add link_ · **Live Demo:** _Placeholder — add link_ · **Architecture:** [below](#system-architecture) · **License:** _Placeholder — not finalized_

## Why Sentinel AI

Traditional AI reviewers can hallucinate. Traditional static scanners provide limited context. Sentinel AI combines a constrained review workflow:

- **Deterministic findings** establish the security record.
- **Bounded evidence** provides the facts available to the reviewer.
- **AI explanations** clarify impact and remediation for existing findings.
- **Human validation** remains the final decision point.

The AI reviewer never invents vulnerabilities. Deterministic scanner findings remain authoritative.

## Core Capabilities

| Capability | What Sentinel AI provides |
| --- | --- |
| Repository Scanning | Bounded static scanning for the bundled demo and validated public HTTPS GitHub repositories; repository code is never executed. |
| Evidence Package | A capped, sanitized `SecurityEvidencePackage` that excludes environment files, secrets, Git metadata, lockfiles, binaries, and unsupported content. |
| AI Security Reviewer | A deterministic demo reviewer that explains existing evidence only; a live provider remains future work. |
| Risk Prioritization | Stable finding IDs, severity, confidence, risk score, CWE/OWASP references, and a ranked review queue. |
| Patch Guidance | Review-required, text-only before/after guidance; Sentinel never applies patches automatically. |
| Responsive Dashboard | Repository summary, deterministic findings, detail tabs, reviewer guidance, search, plus severity and category filtering. |
| Accessibility | Semantic controls, keyboard focus, labelled inputs, readable severity text, and safe wrapping for paths and code. |

The current deterministic scanner supports conservative, high-confidence JavaScript/TypeScript patterns for route and authentication discovery, Prisma mapping, BOLA/IDOR, hardcoded secrets, CORS, JWT, rate limiting, redirects, filesystem usage, command execution, and file uploads. It is not comprehensive OWASP coverage; SQL injection, XSS, SSRF, and broader OWASP API coverage remain future work.

## System Architecture

```text
GitHub Repository / Bundled Demo
              │
              ▼
     Deterministic Scanner
              │
              ▼
     Bounded Evidence Package
              │
              ▼
          AI Reviewer
              │
              ▼
       Security Review UI
```

Only the bounded evidence package is sent to the AI reviewer, not arbitrary repository context. The scanner response remains the source of truth throughout the flow.

## Security Review Pipeline

```text
Repository
    ↓
Static Analysis
    ↓
Finding Generation
    ↓
Evidence Package
    ↓
AI Reviewer
    ↓
Human Review
    ↓
Security Dashboard
```

The UI presents workflow stages rather than fabricated backend progress percentages.

## Trust & Security Boundary

| Layer | Responsibility | Authority |
| --- | --- | --- |
| Deterministic Scanner | Produces findings, severity, confidence, risk, and evidence | Authoritative |
| Evidence Package | Bounds and sanitizes facts available to the reviewer | Supporting evidence |
| AI Reviewer | Explains existing evidence and proposes review-required guidance | Advisory only |
| Human Validation | Reviews context and decides whether remediation is appropriate | Final decision |

AI guidance is advisory. Scanner findings remain authoritative. Sentinel does not execute repository code or apply changes.

## Screenshots

Screenshots are intentionally not fabricated. Add project assets here when available.

| View | Placeholder |
| --- | --- |
| Landing Page | _Add landing page screenshot_ |
| Repository Summary | _Add repository summary screenshot_ |
| Security Findings | _Add findings screenshot_ |
| AI Reviewer | _Add reviewer screenshot_ |
| Patch Proposal | _Add patch proposal screenshot_ |
| Trust Boundary | _Add trust-boundary screenshot_ |

## Technology Stack

| Area | Technologies |
| --- | --- |
| Frontend | Next.js, React, TypeScript, Tailwind CSS |
| Backend | FastAPI, Pydantic, Python |
| Testing | Vitest, pytest, Supertest, Ruff, mypy, ESLint, TypeScript |
| Developer Experience | npm workspaces, Docker for the bundled demo, strict type checking |

## Running Locally

### Prerequisites

- Node.js 22+ and npm 10+
- Python 3.12+

### Installation

```bash
cp .env.example .env
npm install
python3 -m venv apps/api/.venv
apps/api/.venv/bin/python -m pip install -e 'apps/api[dev]'
```

### Environment Variables

The checked-in [.env.example](.env.example) documents local development settings.

- `API_URL` is the server-side Next.js-to-FastAPI URL.
- `CORS_ORIGINS` lists allowed development browser origins.
- `SENTINEL_SCAN_ROOT` optionally bounds local-path scanner requests.
- `SENTINEL_AI_ENABLED`, `OPENAI_API_KEY`, and `OPENAI_MODEL` remain server-side only. The current OpenAI reviewer is a safe placeholder; no live model call is implemented.

Never use `NEXT_PUBLIC_` for credentials. Do not commit `.env` files.

### Run Locally

Start the backend and frontend in separate terminals:

```bash
npm run dev:api
npm run dev:web
```

Open [http://localhost:3000](http://localhost:3000), then select a controlled demo. **Run TaskFlow Demo Scan** is the focused authorization/BOLA validation path. **Run Multi-Rule Demo Scan** validates the expanded deterministic engine against controlled secrets, CORS, JWT, rate-limiting, redirect, filesystem, command-execution, and upload examples. The browser requests the completed scan and then the bounded reviewer response; deterministic findings remain visible if reviewer guidance is unavailable.

### Development Workflow

```bash
# Full repository checks
npm run lint
npm run typecheck
npm test
npm run build

# Frontend checks only
npm run test --workspace @sentinel/web
npm run lint --workspace @sentinel/web
npm run typecheck --workspace @sentinel/web
npm run build --workspace @sentinel/web

# Backend checks only
apps/api/.venv/bin/pytest apps/api
apps/api/.venv/bin/ruff check apps/api
apps/api/.venv/bin/mypy apps/api/src apps/api/tests
```

See [development setup](docs/development.md) for troubleshooting and the controlled TaskFlow demo lifecycle.

## Repository Structure

```text
sentinel-ai/
├── apps/
│   ├── api/                   FastAPI API, scanner, reviewer, and tests
│   └── web/                   Next.js dashboard and frontend tests
├── demo/
│   ├── vulnerable-taskflow/   Focused authorization/BOLA validation demo
│   └── vulnerable-multirule/  Controlled deterministic rule-engine fixture
├── docs/                      Development and scanner architecture notes
├── rules/                     Deterministic rule assets
├── scripts/                   Safe automation helpers
├── .env.example               Local environment template
└── README.md
```

## Security Philosophy

### Evidence First

Findings are based on deterministic source analysis and structured evidence. Sentinel favors a conservative result over an ungrounded claim.

### AI Second

The reviewer assists developers with bounded evidence. It cannot create a vulnerability, change deterministic severity or risk, execute a target, or apply a patch.

### Human Validation Always

Review patch proposals, preserve authentication and ownership controls, and validate changes in an appropriate controlled environment. AI assists developers; it does not replace deterministic analysis.

## Roadmap

- Live OpenAI reviewer integration with structured output validation
- GitHub App workflow
- Pull-request comments
- SARIF export
- Multi-repository scanning
- Additional deterministic scanners and supported frameworks

These are future directions, not current product claims.

## Built for OpenAI Build Week

GPT-5.5 and Codex assisted with implementation, UI refinement, testing, and documentation. Architecture decisions, security validation, and final review remained under human control.

## Bundled Demo

[TaskFlow AI](demo/vulnerable-taskflow/README.md) is a separate, realistic Express/TypeScript project-management SaaS application included as Sentinel AI’s controlled demonstration target. It intentionally contains exactly one documented BOLA vulnerability in `GET /api/projects/:id`, which Sentinel identifies through deterministic static analysis.

[Vulnerable Multi-Rule Demo](demo/vulnerable-multirule/README.md) is a separate controlled fixture for validating supported deterministic rule families. It contains synthetic examples only for static inspection; it does not represent comprehensive vulnerability detection or full OWASP coverage.

TaskFlow AI is not the Sentinel AI product. It must remain localhost-only and must never be deployed to a public or production environment.

Both demos are local scanner-validation targets only. Sentinel never executes their code, and dangerous routes must not be invoked.

Its independent local lifecycle is:

```bash
cd demo/vulnerable-taskflow
cp .env.example .env
npm install
npm run prisma:generate
npm run db:migrate
npm run db:seed
npm run dev
```

See its [dedicated README](demo/vulnerable-taskflow/README.md) for credentials, API examples, Docker setup, and the exact vulnerability boundary.

## License

License selection is not finalized. Add the repository license and update this section before public distribution.

## Contributing

Contributions are welcome through focused issues and pull requests. Keep changes within Sentinel’s security boundaries, add appropriate tests, run the documented quality checks, and avoid expanding scanner claims beyond implemented behavior. Review [AGENTS.md](AGENTS.md) and [scanner architecture](docs/scanner-architecture.md) before contributing.
