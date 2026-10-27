# Coding Standards

Project-specific. Imported into every session; keep it short.

## Stack and layout

- Next.js 16 App Router, React 19, strict TypeScript, SQLite via `better-sqlite3`.
- Server Components by default; add `"use client"` only for stateful interaction
  (`src/components/charts/*`, shell, filters, tip disclosures).
- Routes: `app/**/page.tsx`; API handlers: `app/api/v1/**/route.ts`.
- Domain/data logic: `src/lib/**`; UI: `src/components/**`; shared shell:
  `src/components/shell/**`.
- Product CSS: `app/ui.css`; tokens are documented in `DESIGN.md`. Legacy
  `app/globals.css` remains for the showcase and `ledger-*` aliases.
- SQL belongs in `src/lib/**` or `app/api/v1/_lib/shared.ts`; UI components never
  build SQL. Fixed read-only fallback counters in the methodology page are the
  known exception.

## Naming

- TypeScript/React: `camelCase` values, `PascalCase` components and types.
- Database/SQL: `snake_case` columns and tables.
- Constants: `UPPER_SNAKE_CASE`; CSS custom properties `--ui-*`.
- Booleans read as predicates (`isStale`, `hasAdp`, `canRead`).
- Keep CVE IDs in mono text; never wrap the ID and title into one unlabeled string.

## Data and time

- Snapshots are the source of truth. Never estimate an unknown value or coerce it
  to zero.
- Dates: UTC is the storage/bucket basis; display instants through `TimeText` so the
  global timezone preference applies. Date-only values stay date-only.
- Shares always name their denominator. Bounded lists must be labeled as bounded.
- Preserve the no-composite-score rule: KEV, EPSS, and CVSS stay separate.

## Errors

- Validate at the boundary; return typed errors (`SearchValidationError`,
  `DbConfigError`, `DbBusyError`) and sanitized client messages.
- Never swallow an error. Best-effort cleanup catches must say why in a short comment.
- Never log secrets, record bodies, or full SQL parameters from untrusted input.

## Testing

- `npm test` runs Vitest; `npx playwright test` runs the browser suite.
- Every behavior change adds or updates a test. Bug fixes add a regression test.
- Keep E2E fixtures hermetic: seed the server DATA_DIR, restore it in `afterAll`.
- Accessibility gates are part of the tests: 44px targets, visible focus, one h1,
  no heading skips, scoped tables, no horizontal overflow at 360px or the
  200%-zoom-equivalent viewport, reduced motion at `0s`.
- Never disable or delete a failing assertion to make a change pass.

## Quality tooling

- `npm run lint`, `npm run typecheck`, `npm run build`, and `npx prettier --write`
  on touched files before completion.
- No `any`, `@ts-ignore`, or `@ts-expect-error`; no raw hex colors outside
  `DESIGN.md` (use `rgb()` tokens).
- Keep client components thin; data loading stays server-side.
- Run the Security Gate in `SECURITY_STANDARDS.md` for every change.

## Documentation

- Update `README.md` for user-visible behavior, `DESIGN.md` for visual/interaction
  contracts, `docs/DATA_WORKFLOW.md` for data/ranking contracts, and
  `docs/api/` + `openapi/v1.yaml` for API changes.
- Add every new environment variable to `.env.example` in the same change.
- Answer “why” in comments; do not narrate obvious code.

## Version control

- One logical concern per commit; message says what changed and why.
- Do not commit or push unless the owner asks. Never force-push or use `--no-verify`.
- Keep runtime data, `.env` files, evidence logs, and local agent state out of Git.
