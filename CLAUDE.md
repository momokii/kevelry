# Project Instructions

## Project Snapshot

**Purpose:** Public CVE intelligence console (wordmark Kevelry; package/image cve-change-radar), with explainable prioritization, searchable descriptions, Change Radar, and a versioned read-only API.
**Stack:** Next.js 16 App Router, React 19, TypeScript, SQLite/FTS5, visx SVG primitives, one Docker image and container.
**Release:** 4.0.4 is the newest published image (`kelanach/kevelry`) — tagged 2026-11-23, `latest` resolves to it; it is the assistant-fixes release — the web fallback negotiates JSON (`accept: application/json, text/html;q=0.9, text/plain;q=0.8, */*;q=0.1`; the old text-only header made NVD API 2.0 answer `406` and the fallback returned no content), the rail's id sample is 25 so a full 25-row call reads `25 rows` instead of `25 rows · 12 ids available` (a wider tool keeps the honest pair, e.g. `50 rows · 25 ids available`), an answer's line joins carry a collapsible space so the copied or announced text reads `latest list. Using…` rather than `latest list.Using…`, and a time-window table is pinned to `CVE | Date | EPSS` in that order; no migration, no config change. From 4.0.3, the assistant-hardening release — answers render as structure (pipe tables become real `<table>` elements with scoped headers inside a horizontally scrollable wrapper; headings, horizontal rules, blockquotes, lists, bold, italic, inline code and fenced code render as their elements; a broken marker degrades to the characters the model wrote, and an unterminated fence stays literal until it closes; everything escaped first with no HTML injection, links limited to `https:` and internal paths, record ids linking to `/explore` only when the turn's citations named them), the evidence rail is capped by calls and records rather than by a scrollbar (6 chips per call then `+N more`, three calls then `See all N calls`, `no rows`/`failed` always visible, `25 rows · 12 ids available` labels, "Cited" folded to one line, no inner `max-height`/`overflow` at ≥1024px), the page explains itself (one legend line, a three-sentence "How this works" disclosure, five `HelpTip`s, an empty state naming what it can and cannot answer), an oversized body answers `413 PAYLOAD_TOO_LARGE` with `details.maxBytes` and a second/oversized/non-image `422 BAD_IMAGE` while a malformed body stays `400` (the 20-concurrent burst cap is proven: 10 × `200` / 10 × `429`; the budget is checked before any provider call), `AI_MAX_TURNS` is deleted because no code read it, and the web fallback returns `application/json`/`*+json` responses as pretty-printed JSON instead of tag-stripped HTML, reports an HTML page's `title` plus `mayBeClientRendered` when the extracted body is under 200 characters, and names the NVD API 2.0, CISA KEV and FIRST EPSS endpoints in the prompt with an allowlist-parity test; no migration, no API change — and 4.0.2 is the formatted-answers release — an assistant answer is rendered as formatted text (pipe tables become real tables with scoped headers inside a horizontally scrollable wrapper; lists, bold, italic, inline code, fenced code and safe links render as their elements), escaped first and rendered with no HTML injection, links limited to `https:` and internal paths, and record ids linking to `/explore` only when the turn's citations named them; no migration, no API change — and 4.0.1 is the answer-token fix over 4.0.0 — the round that writes the answer takes `AI_MAX_ANSWER_TOKENS` (default 4096) instead of the 1024 tool-round cap, so a table answer is no longer cut mid-table, an empty truncated round retries once at the higher budget with a typed `retry` event, and the prompt asks for ≤12 rows plus a remainder count; no migration, new optional env var — and 4.0.0 ships the v4 AI research assistant (off unless `AI_ENABLED=true` and a gateway key is present, migration 011 `ai_usage` applied automatically on boot, `POST /api/assistant/chat` outside the GET-only v1 contract, outbound fetch opt-in via `AI_WEB_FETCH_ENABLED`), and 4.0.2 (2026-11-22) / 4.0.1 (2026-11-22) / 4.0.0 (2026-11-22) / 3.2.3 (2026-11-22) / 3.2.2 (2026-11-22) / 3.2.1 (2026-11-22) / 3.2.0 (2026-11-21) / 3.1.0 (2026-11-20) / 3.0.2 (2026-11-17) remain available as previous releases; see `CHANGELOG.md` under `3.2.3` for the entries and upgrade notes (3.2.3 is the scheduler jitter fix — a 120 s grace on the due comparison, capped at ¼ of the source's own interval, plus an adaptive wake at `min(tick, earliest due)` with a 30 s floor, so a source that a tick just missed is retried within seconds instead of waiting a whole interval, and the `ingest-gate` line reports `nextWakeInMs`; no migration and no API change. From 3.2.2: each source is polled on its own interval — CVE/KEV hourly, EPSS/SSVC on their declared 24 h — with a 60 min retry when an attempt accepts nothing new, so upstream fetches fall from ≈96 to ≈50/day and one `ingest-gate` line names what ran and why each source was skipped; the EPSS retention prune writes `maintenance_runs` (`epss-retention`, keepDays/cutoff/rowsDeleted, including no-op runs); `running` rows abandoned since 2026-11-08 are marked `interrupted` at boot by migration 010, which widens the `sync_runs` status CHECK to allow that value and runs automatically on boot with no manual step; nightly backups are idempotent/atomic and a missing or failed backup is detected by `scripts/backup-check.sh`; no API contract change and the 3.2.1 freshness semantics unchanged). **Phase:** Implemented, verified, and deployed at `http://100.124.184.116:3100` (Tailscale) with scheduled refresh ON (CVE + KEV hourly, EPSS + CISA SSVC enrichment daily). Research Console UI, relation graph, browser-private watch list, and an explainable SSVC triage view shipped; v3 epics E1–E5 (secondary/ADP CVSS context, KEV actionability, CWE catalog via migration 009, bulk lookup, RSS feed plus page-bounded export) shipped in 3.0.0; the post-3.1.0 wrap-up (correctness, consolidation, hardening) shipped as 3.2.0, the performance/cold-start pass as 3.2.1, the scheduling/migration-010 hardening as 3.2.2, and the scheduler jitter fix as 3.2.3, and the v4 AI research assistant as 4.0.0 (two real turns on `/assistant`, spend ledger written, schema 11), the answer-token fix as 4.0.1, the formatted-answers release as 4.0.2 (verified live: a real answer table renders as a `<table>` with scoped headers, scrollable at 390px without page overflow), and the assistant-hardening release as 4.0.3, and the assistant-fixes release as 4.0.4; gates on 2026-11-23 for 4.0.4: 1082 unit tests pass (3 skipped, network-gated) and 155 Playwright tests pass (0 skipped), lint, typecheck and `npm audit --omit=dev` clean.
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
