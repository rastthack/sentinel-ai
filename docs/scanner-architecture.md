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
- The scanner performs no vulnerability detection, DAST, target execution, GPT call, exploit validation, or patch generation.
