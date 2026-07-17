"""Express route graph discovery tests."""

from sentinel_api.scanner.discovery.express_routes import ExpressRouteDiscoverer
from sentinel_api.scanner.models import IndexResult


def test_routes_mounts_methods_and_middleware_order_are_resolved() -> None:
    index = IndexResult(
        contents={
            "src/app.ts": """
                import express from "express";
                const app = express();
                app.use(helmet());
                app.get("/health?verbose=1", health);
                app.use("/api/", authenticate(db), createRouter(db));
            """,
            "src/routes.ts": """
                import { Router } from "express";
                export function createRouter(db: Db): Router {
                  const router = Router();
                  router.use(validate);
                  router.get("/projects/", listProjects);
                  router.post("/projects", createProject);
                  router.put("/projects/:id", updateProject);
                  router.patch("/projects/:id", patchProject);
                  router.delete("/projects/:id", deleteProject);
                  return router;
                }
            """,
        }
    )

    result = ExpressRouteDiscoverer().discover(index)

    assert [(route.method, route.path) for route in result.routes] == [
        ("GET", "/api/projects"),
        ("POST", "/api/projects"),
        ("DELETE", "/api/projects/:id"),
        ("PATCH", "/api/projects/:id"),
        ("PUT", "/api/projects/:id"),
        ("GET", "/health"),
    ]
    project_route = result.routes[0]
    assert project_route.middlewares == ["helmet", "authenticate", "validate"]
    assert project_route.mounted_path == "/api"


def test_duplicate_route_ids_are_deduplicated_deterministically() -> None:
    index = IndexResult(
        contents={
            "src/app.ts": """
                const app = express();
                app.get('/status/', first);
                app.get('/status', second);
            """
        }
    )

    first = ExpressRouteDiscoverer().discover(index)
    second = ExpressRouteDiscoverer().discover(index)

    assert len(first.routes) == 1
    assert first.routes == second.routes
    assert first.routes[0].route_id == "route:GET:/status"
