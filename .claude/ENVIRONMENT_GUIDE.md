# Environment Guide

## Definitions

| Environment | Purpose | Characteristics |
|---|---|---|
| `development` | Local development | Debug on, verbose logs, hot reload, mock or sandbox services |
| `staging` | Pre-production validation | Production-like config, sandboxed real services, debug off |
| `production` | Live system | Debug off, minimal logs, hardened config, real secrets |

`APP_ENV` selects the environment. If it is missing or unknown, apply production-safe
defaults (fail closed).

## Agent Behavior

**`development`**

- Verbose logging, dev tooling, and debug ports are allowed.
- Seed scripts and migrations are allowed against the local environment.
- Prefer mock or sandbox services; never point local work at production data.

**`staging` and `production`**

- No destructive operation, migration, or configuration change without a written plan
  and explicit user confirmation.
- Never modify live configuration or secrets.
- The agent should not hold production credentials at all. If it detects that it does,
  tell the user and stop using them.
- Present the plan before acting, including the exact commands and the rollback.

**Unknown environment**

- Treat it as production for the purpose of safety.

## Docker Compose Pattern (Compose v2)

Use `docker compose`, not the legacy `docker-compose`.

- `compose.yaml`: base definitions, environment-agnostic. Do not use the obsolete
  top-level `version:` key.
- `compose.override.yaml`: development overrides (hot reload, debug ports, volume
  mounts). Loaded **automatically** by `docker compose up`.
- `compose.prod.yaml`: production overrides (no source mounts, restart policy, resource
  limits, no debug ports, pinned image tags). Used explicitly.

```bash
# Development (override file loaded automatically)
docker compose up

# Production (explicit -f flags disable automatic override loading)
docker compose -f compose.yaml -f compose.prod.yaml up -d
```

The agent must **always ask** before any Compose command that is not clearly development.
If the project uses different file names, document them here and follow the existing
names.

## Environment Files

```
.env.example      # committed; every variable with placeholder + comment
.env              # never committed; local development values
.env.staging      # never committed
.env.production   # never committed; ideally injected by the deployment platform
```

Development dependencies, debug endpoints, seed data, and admin tools must be **absent or
disabled** in production images and configuration.

## Configuration Rules

- Express environment differences through configuration, never hardcoded branches.
- Required configuration is validated at startup; the application fails closed.
- Secrets are injected at runtime, never baked into images or committed files.
- Every new variable is added to `.env.example` with a placeholder and a description.

> **Self-update:** once the real Docker setup and commands exist, replace the generic
> examples with the verified commands for this project.
