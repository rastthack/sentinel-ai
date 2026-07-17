# Sentinel AI contributor guide

## Scope

Sentinel AI is an evidence-driven security reviewer for AI-generated web applications. Keep the MVP focused on the bundled, controlled demo repository. Repository scanning, exploit reproduction, and patch generation are future work unless a task explicitly requests them.

## Safety invariants

- Never execute model-generated shell commands.
- Never pass untrusted input to a shell or use `shell=True` with it.
- Keep API keys and credentials on the server. Never send `.env` files, secrets, or credentials to a model.
- Limit future dynamic validation to localhost and explicitly allowlisted demo targets.
- Treat generated patches as proposals: require human review and apply them only to temporary repository copies.
- Do not target third-party or production systems.

## Engineering conventions

- Use strict TypeScript and explicit Python type hints.
- Keep API schemas in Pydantic models.
- Add tests for behavior changes and run the relevant lint, type-check, test, and build commands.
- Avoid unrelated authentication, billing, team, or deployment features.
