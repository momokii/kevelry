# Project Instructions

## Project Snapshot

**Purpose:** Public CVE overview, explainable prioritization, searchable descriptions, Change Radar, and a versioned read-only API.
**Stack:** Next.js 16 App Router, React 19, TypeScript, SQLite/FTS5, one Docker image and container.
**Phase:** Implemented, verified, and deployed serve-only at `http://100.124.184.116:3100` (Tailscale). Interactive UI round shipped; 364 unit and 67 Playwright tests pass.
**Environments:** `development`, `staging`, `production`, selected by `APP_ENV`.

## Always-Loaded Context

The four files below are imported at session start. They are kept compact on purpose.
Everything else in `.claude/` is read on demand (see On-Demand References).

@.claude/AGENT_RULES.md
@.claude/CODING_STANDARDS.md
@.claude/SECURITY_STANDARDS.md
@.claude/state/CURRENT_STATUS.md

If a file above is missing or did not load, read it manually before doing any work.

## Session Protocol (Summary)

1. Confirm context: `CLAUDE.md` and its four imports appear in `/context` under Memory files. Read `.claude/HOW_TO_RESUME.md` for the full protocol.
2. Read `.claude/state/TASK_QUEUE.md`; pick the next unblocked task.
3. Identify the active environment (`APP_ENV`) before running anything. Unknown means production-safety rules apply.
4. Check git state: branch, uncommitted changes, recent commits. Never clobber existing work.
5. Read task-relevant docs, verify the environment, and run the baseline test suite.
6. State a short plan (goal, files, risks, verification) for any non-trivial task.
7. Implement using the matching template in `.claude/templates/`.
8. Verify: tests, lint, type checks, and the Security Gate.
9. Wrap up: one batched write updating state and standards (`/wrap-up`).

## Commands

| Purpose | Command | Status |
|---|---|---|
| Install dependencies | `npm ci` | Ready |
| Run (development) | `npm run dev` | Ready |
| Run (production-like) | `docker compose up -d --build` | Ready (never rebuilds without `build`) |
| Test | `npm test` | Ready (Vitest) |
| Browser tests | `npx playwright test` | Ready |
| Lint | `npm run lint` | Ready |
| Format | `npx prettier --write .` / `npm run format:check` | Ready |
| Type check | `npm run typecheck` | Ready |
| Build | `npm run build` | Ready |
| Health check | `curl -fsS http://127.0.0.1:3000/api/v1/health` | Ready |
| View logs | `docker compose logs -f app` | Ready |

## On-Demand References

| When you need... | Read |
|---|---|
| The next task or backlog order | `.claude/state/TASK_QUEUE.md` |
| Why a choice was made | `.claude/state/DECISIONS_LOG.md` |
| Environment definitions and the Compose layout | `.claude/ENVIRONMENT_GUIDE.md` |
| The full session-start protocol | `.claude/HOW_TO_RESUME.md` |
| A checklist for features, endpoints, tests, or bugs | `.claude/templates/` |
| How this `.claude/` setup works and why | `.claude/README.md` |
| Past session summaries | `.claude/state/HISTORY.md` |
| Product docs, specs, or architecture decision records | `docs/` (created with the project) |
| Source terms, competitors, and proposed CVE pipeline | `FEASIBILITY.md` |
| Exact proposed ingestion, missing-data and ranking rules | `docs/DATA_WORKFLOW.md` |

Use `/resume` to run the session-start protocol, `/wrap-up` to close a task, and
`/security-check` to audit uncommitted changes against the Security Gate.

## Maintenance Rules for This File

- Keep this file under ~150 lines. Link to deeper files instead of duplicating them.
- Update the Snapshot and Commands sections as soon as facts change; a stale entry is a bug.
- Never remove a rule to make a task easier. Extend or sharpen rules instead.
- `.claude/` is a protected path: batch edits there and expect a one-time permission prompt.

<!-- Human maintainer note: imported files load fully at launch; keep them lean. -->
