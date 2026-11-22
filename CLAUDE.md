# Project Instructions

## Project Snapshot

**Purpose:** Public CVE intelligence console (wordmark Kevelry; package/image cve-change-radar), with explainable prioritization, searchable descriptions, Change Radar, and a versioned read-only API.
**Stack:** Next.js 16 App Router, React 19, TypeScript, SQLite/FTS5, visx SVG primitives, one Docker image and container.
**Release:** 3.2.2 is the newest published image (`kelanach/kevelry`) — tagged 2026-11-22, `latest` resolves to it, and 3.2.1 (2026-11-22) / 3.2.0 (2026-11-21) / 3.1.0 (2026-11-20) / 3.0.2 (2026-11-17) remain available as previous releases; see `CHANGELOG.md` under `3.2.2` for the entries and upgrade notes (each source is polled on its own interval — CVE/KEV hourly, EPSS/SSVC on their declared 24 h — with a 60 min retry when an attempt accepts nothing new, so upstream fetches fall from ≈96 to ≈50/day and one `ingest-gate` line names what ran and why each source was skipped; the EPSS retention prune writes `maintenance_runs` (`epss-retention`, keepDays/cutoff/rowsDeleted, including no-op runs); `running` rows abandoned since 2026-11-08 are marked `interrupted` at boot by migration 010, which widens the `sync_runs` status CHECK to allow that value and runs automatically on boot with no manual step; nightly backups are idempotent/atomic and a missing or failed backup is detected by `scripts/backup-check.sh`; no API contract change and the 3.2.1 freshness semantics unchanged). **Phase:** Implemented, verified, and deployed at `http://100.124.184.116:3100` (Tailscale) with scheduled refresh ON (CVE + KEV hourly, EPSS + CISA SSVC enrichment daily). Research Console UI, relation graph, browser-private watch list, and an explainable SSVC triage view shipped; v3 epics E1–E5 (secondary/ADP CVSS context, KEV actionability, CWE catalog via migration 009, bulk lookup, RSS feed plus page-bounded export) shipped in 3.0.0; the post-3.1.0 wrap-up (correctness, consolidation, hardening) shipped as 3.2.0, the performance/cold-start pass as 3.2.1, and the scheduling/migration-010 hardening as 3.2.2; gates on 2026-11-22: 727 unit tests pass (3 skipped, network-gated) and 138 Playwright tests pass (0 skipped), lint and typecheck clean.
**Environments:** `development`, `staging`, `production`, selected by `APP_ENV`.
**Vocabulary:** band, cohort, checkpoint, acceptance ledger and aggregate cache mean exactly what
[`CONTEXT.md`](CONTEXT.md) says; read it before naming anything new.

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

| Purpose               | Command                                                                                                       | Status                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Install dependencies  | `npm ci`                                                                                                      | Ready                                                                     |
| Run (development)     | `npm run dev`                                                                                                 | Ready                                                                     |
| Run (production-like) | `docker compose up -d --build`                                                                                | Ready (never rebuilds without `build`)                                    |
| Test                  | `npm test`                                                                                                    | Ready (Vitest)                                                            |
| Browser tests         | `npx playwright test`                                                                                         | Ready                                                                     |
| Lint                  | `npm run lint`                                                                                                | Ready                                                                     |
| Format                | `npx prettier --write <paths>`                                                                                | Touched files; repo-wide `format:check` has pre-existing drift (42 files) |
| Type check            | `npm run typecheck`                                                                                           | Ready                                                                     |
| Build                 | `npm run build`                                                                                               | Ready                                                                     |
| Health check          | `curl -fsS http://127.0.0.1:3000/api/v1/health` (live Tailscale: `http://100.124.184.116:3100/api/v1/health`) | Ready                                                                     |
| View logs             | `docker compose logs -f app`                                                                                  | Ready                                                                     |

## On-Demand References

| When you need...                                      | Read                                                        |
| ----------------------------------------------------- | ----------------------------------------------------------- |
| The next task or backlog order                        | `.claude/state/TASK_QUEUE.md`                               |
| Why a choice was made                                 | `.claude/state/DECISIONS_LOG.md`                            |
| Environment definitions and the Compose layout        | `.claude/ENVIRONMENT_GUIDE.md`                              |
| The full session-start protocol                       | `.claude/HOW_TO_RESUME.md`                                  |
| A checklist for features, endpoints, tests, or bugs   | `.claude/templates/`                                        |
| How this `.claude/` setup works and why               | `.claude/README.md`                                         |
| Past session summaries                                | `.claude/state/HISTORY.md`                                  |
| Product/API docs and research records                 | `docs/` (`DATA_WORKFLOW.md`, `docs/api/`, `docs/research/`) |
| Source terms, competitors, and pre-build feasibility  | `FEASIBILITY.md`                                            |
| Implemented ingestion, missing-data and ranking rules | `docs/DATA_WORKFLOW.md`                                     |
| The domain vocabulary this code actually implements   | `CONTEXT.md`                                                |

Use `/resume` to run the session-start protocol, `/wrap-up` to close a task, and
`/security-check` to audit uncommitted changes against the Security Gate.

## Maintenance Rules for This File

- Keep this file under ~150 lines. Link to deeper files instead of duplicating them.
- Update the Snapshot and Commands sections as soon as facts change; a stale entry is a bug.
- Never remove a rule to make a task easier. Extend or sharpen rules instead.
- `.claude/` is a protected path: batch edits there and expect a one-time permission prompt.

<!-- Human maintainer note: imported files load fully at launch; keep them lean. -->
