# Static scanner architecture

Milestone 4 extends the bounded Milestone 3 file index with deterministic application-structure discovery. The scanner service orchestrates every component; FastAPI routes and the CLI are thin adapters over that same service. Public Pydantic models contain relative source locations and short evidence descriptions, never full source text or absolute paths.

## Express routes and router mounts

The route discoverer performs lexical extraction over indexed JavaScript and TypeScript. It masks strings and comments before locating Express calls, then uses balanced-delimiter parsing for arguments and inline handlers. It supports `get`, `post`, `put`, `patch`, `delete`, and `use` on app and router variables.

Router declarations receive internal file-qualified identities. Exported routers and router-factory functions form a mount graph. Resolution starts at Express app instances, composes each literal base path with the local route path, and propagates app-, router-, mount-, and route-level middleware in registration order. Paths receive one leading slash, duplicate and trailing slashes are removed, query strings are discarded, and parameter segments remain visible. Stable IDs use `route:<METHOD>:<PATH>`; duplicate IDs are resolved deterministically.

Unsupported dynamic paths, unbalanced calls, and cyclic mounts produce warnings rather than fabricated routes.

## Middleware and authentication

Middleware registrations are recorded separately from route declarations. Classification uses function bodies when available:

- authentication requires request authentication data plus concrete behavior such as user resolution, request-user assignment, or an unauthenticated rejection;
- validation requires parse/rejection behavior;
- authorization requires explicit permission, role, or policy enforcement plus an HTTP 403 response;
- error middleware requires server-error response behavior;
- everything else remains `unknown`.

Bearer, JWT, session, cookie, API-key, custom-token, and unknown-custom mechanisms have explicit evidence rules. Route protection is computed from middleware that applies before that route. A route is public only when no recognized or unresolved custom authentication middleware applies; unresolved custom middleware yields `unknown`.

## Prisma models and ownership candidates

The focused Prisma parser reads datasource and generator blocks, models, fields, optional/list modifiers, IDs, unique constraints, defaults, model attributes, enums, and relation metadata. Relation `fields` clauses connect scalar foreign keys to their related model.

Ownership inference is deliberately structural, not a security finding. A configured field-name set such as `ownerId`, `userId`, `tenantId`, or `workspaceId` creates a candidate. A confirmed relation can raise confidence, but no route is declared safe or unsafe from that fact.

## Route-to-model mapping

The mapper searches each discovered inline handler for direct Prisma delegate operations. `findUnique` and `findFirst` map to `read_one`; `findMany` and `count` to `read_many`; create, update, and delete families map to their corresponding normalized operations. Direct delegate evidence determines the model even if a route noun differs. Path names alone are considered too weak and do not force a mapping.

Mappings, models, fields, routes, middleware, and candidates are sorted before serialization. The scan UUID remains unique per request, while the discovered structure is deterministic for identical indexed input.

## Known limitations

- This is a focused lexical parser, not a TypeScript compiler or full JavaScript AST.
- Dynamic route strings, computed router variables, re-export chains, and uncommon metaprogramming may be skipped.
- Middleware order is resolved for common Express registration and mount patterns; conditional registration is not evaluated.
- Authentication rules do not interpret arbitrary helper call graphs or runtime configuration.
- Prisma support targets the bundled schema and common attributes, not every Prisma language feature.
- Route-model mapping does not yet follow named handlers into service/repository layers.
- The scanner performs no DAST, target execution, GPT call, exploit validation, or patch generation.

## Deterministic authorization analysis

Milestone 5 consumes the private route-handler text retained by the bounded index, but publishes only structured signals and short evidence. Handler context records route, query, and body references; aliases assigned from request values; authenticated identity expressions; direct Prisma operations; selector fields and sources; rejection status codes; and whether a client-controlled identifier reaches a selector. Named or unavailable handler bodies produce an analysis warning and are not eligible for a high-confidence finding.

Authentication and authorization remain separate concepts. The authenticated identity is derived from recognized middleware assignment and route-local identity references. Ownership controls require one of these concrete patterns:

- an ownership candidate and authenticated identity in the same ORM `where` clause;
- a fetched owner compared with the authenticated identity;
- a membership query combining resource and user identifiers;
- a membership collection check against the authenticated identity;
- a role/permission check that can reject with HTTP 403; or
- middleware already classified as authorization from source behavior.

A reference to `req.user`, a `404`, an omitted response field, or the name of a middleware is not sufficient by itself.

### BOLA decision and false-positive controls

`AUTH-BOLA` requires an authenticated route, a client-controlled identifier, direct flow into a single-object Prisma selector, a high-confidence model mapping, and an ownership/tenancy candidate. The detector suppresses the finding when it observes query scoping, a post-fetch owner comparison, membership enforcement, a role check, recognized authorization middleware, a list operation, no resource identifier, incomplete handler extraction, or a weak mapping.

TaskFlow's `GET /api/projects/:id` meets all positive rules and none of the suppression rules. Its project list, task list, dashboard, profile, login, and health handlers do not meet the object-level finding criteria.

### Risk, confidence, identifiers, and graphs

Risk components are returned alongside the score. A read-only BOLA receives 82 points: authenticated object route (12), single-object operation (12), explicit client-identifier flow (20), ownership candidate (14), missing query filter (10), missing post-fetch control (9), and missing authorization middleware (5). Scores 65–84 are High; update and delete receive operation-sensitivity adjustments. Confidence is separate and bounded by route, direct mapping, identifier-flow, and ownership evidence confidence.

Finding identity is a stable SHA-256-derived prefix over rule, method, normalized path, model, and relative source file. Findings sort by severity, rule, route, model, and ID. Each route also receives a deterministic graph of authentication, identity, resource identifier, ORM operation, model, ownership candidate, controls, and decision.

### Milestone 5 limitations

- Analysis recognizes focused direct Express/Prisma patterns; it is not interprocedural taint analysis.
- Alias tracking covers straightforward local assignments, not arbitrary transformations.
- Named handlers and service/repository abstractions are reported as incomplete rather than assumed unsafe.
- Conditional control flow and every possible JavaScript equality or membership idiom are not modeled.
- Missing-authentication analysis is intentionally conservative and excludes common public lifecycle paths.
- Sentinel currently produces deterministic static findings only. GPT-5.6 explanations and remediation are planned for a later milestone.
