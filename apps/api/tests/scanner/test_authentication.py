"""Authentication evidence and route classification tests."""

from sentinel_api.scanner.discovery.authentication import AuthenticationDiscoverer
from sentinel_api.scanner.discovery.express_routes import ExpressRouteDiscoverer
from sentinel_api.scanner.models import IndexResult


def test_bearer_middleware_is_detected_from_behavior_not_its_name() -> None:
    index = IndexResult(
        contents={
            "src/app.ts": """
                const app = express();
                app.get('/public', publicHandler);
                app.use(checkIdentity(prisma));
                app.get('/private', privateHandler);
            """,
            "src/auth.ts": """
                export const checkIdentity = (prisma: PrismaClient) =>
                  async (req, res, next) => {
                    const authorization = req.header('Authorization');
                    if (!authorization?.startsWith('Bearer ')) {
                      return res.status(401).json({ error: 'Unauthorized' });
                    }
                    const user = await prisma.user.findUnique({ where: { demoToken: token } });
                    req.authUser = user;
                    next();
                  };
            """,
        }
    )
    express = ExpressRouteDiscoverer().discover(index)

    routes, authentication = AuthenticationDiscoverer().discover(index, express)

    assert [route.authentication_required for route in routes] == [True, False]
    assert authentication.mechanisms[0].name == "bearer_token"
    component = authentication.authentication_middleware[0]
    assert component.reads_authentication_data
    assert component.resolves_user
    assert component.attaches_user
    assert component.rejects_unauthenticated


def test_custom_middleware_without_auth_evidence_remains_unknown() -> None:
    index = IndexResult(
        contents={
            "src/app.ts": """
                const app = express();
                app.use(authorize);
                app.get('/resource', handler);
                function authorize(req, res, next) { next(); }
            """
        }
    )
    express = ExpressRouteDiscoverer().discover(index)

    routes, authentication = AuthenticationDiscoverer().discover(index, express)

    assert routes[0].authentication_required == "unknown"
    assert authentication.authentication_middleware == []
