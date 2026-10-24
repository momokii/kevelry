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

- `compose.yaml`: production-safe default for one self-contained application image/
  container. Debug off, no development source mounts/admin ports, least privilege,
  durable data. Do not use the obsolete top-level `version:` key.
- The normal configuration must explicitly set `APP_ENV=production` and the chosen
  runtime's production mode. A copied development `.env` must not silently change
  normal startup into development mode; only the explicit dev override does that.
- Do not ship an automatically discovered development `compose.override.yaml` or
  `compose.override.yml`. Plain startup must not silently enable development behavior.
- `compose.dev.yaml`: explicitly selected development overrides when implemented;
  hot reload/debug/source mounts belong only in that opt-in path.
- `compose.prod.yaml`: optional explicit deployment-specific overrides if needed,
  not a mandatory extra command or additional service for normal startup.

```bash
# Normal startup (production-safe defaults)
docker compose up -d

# Development (explicit opt-in; no automatic dev override)
docker compose -f compose.yaml -f compose.dev.yaml up
```

These are approved command contracts, not verified commands: no Compose/Dockerfile
implementation exists yet. Plain `up -d` must handle normal first startup; document
upgrades/rebuilds separately because it does not guarantee rebuilding an existing image.

The agent must **always ask** before any Compose command that is not clearly development,
including the normal production-safe `docker compose up -d` path.
If the project uses different file names, document them here and follow the existing
names.

One runtime image/container must include web, ingestion/scheduling, local storage/
search and Radar/replay. Compose is a convenience wrapper, not a prerequisite for
standalone Docker operation. Persistent data belongs in a named/bind volume, not
the image. No mandatory external database/cache/worker container or host cron.

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
