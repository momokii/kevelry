# Current Status

## Project Phase

Deployed and serving on this host: single container at
http://100.124.184.116:3100 (Tailscale). All 30 build todos delivered, F1–F4
approved, post-deployment hardening complete, and the full Research Console UI
revamp shipped. Local `main` only: no remote.

## Completed

- [x] `.claude/` agent infrastructure and root `CLAUDE.md` initialized
- [x] Free upstream CVE, KEV and EPSS access/terms checked; see `FEASIBILITY.md`
- [x] Existing close alternative verified: o2CVE search, statistics and priority list
- [x] Project-local model overrides pinned to `opencode-go/muse-spark-1.3-contributor` in `opencode.json` and `.omo/omo.jsonc`; fresh-process checks passed
- [x] Source and competitor audits in `docs/research/`; coverage index in `FEASIBILITY.md`
- [x] Implemented ingestion/ranking contract documented in `docs/DATA_WORKFLOW.md`
- [x] Full EPSS structural check: 394,803 unique rows, zero invalid under stated checks
- [x] KEV count checks and 31 synthetic ranking/boundary assertions passed
- [x] Reviewer findings addressed; earlier delegated-agent metadata verified as GPT-6 Luna (historical; current overrides are muse-spark)
- [x] Owner approved original features plus Change Radar and retained-snapshot replay
- [x] Single runtime Docker image/container required; optional Compose wrapper
- [x] Git initialized; 17 focused baseline commits independently checked, no remote/push
- [x] Runtime records/backups ignored; targeted credential-marker scan found no matches
- [x] Production-safe `up -d` approved; dev explicit; agent Compose startup now asks
- [x] Self-hosted Instrument Sans + JetBrains Mono committed with OFL licenses in `public/fonts/`
- [x] Root README added: vision, diagrams, source feasibility, deployment/security plan, docs map
- [x] Bundled brief approved by owner (historical Evidence Ledger direction, since superseded by the Research Console)
- [x] Execution plan complete and dual-approved: 30 todos + F1-F4, 4 review rounds, zero open blockers
- [x] All 30 build todos delivered: app shell, design system, TDD contracts, SQLite/FTS5, V5/KEV/EPSS importers, ranking, Radar/replay, read-only API + docs + hardening + parity, six UI views, a11y pass, Dockerfile, scheduling/health, Compose files, setup.sh, backup/restore, benchmarks — evidence `.omo/evidence/task-1` through `task-30-cve-change-radar.*`
- [x] F1 plan-compliance audit closed: 30/30 todos checked, GAP rows mapped, IS evidence paths unchanged, no Must-NOT-have in plan diff — receipt `.omo/evidence/task-31-cve-change-radar.log`
- [x] F2 code quality review approved: lint/typecheck/test green, no suppressions, pinned deps, parameterized SQL, no secrets
- [x] F3 browser QA approved: stock Playwright suite green with phone + desktop screenshots, keyboard/zoom/reduced-motion evidence
- [x] F4 ideal-state fidelity approved: 10/11 rows met outright; shortfall became tracked todo 31, now done
- [x] Live ingestion verified from upstreams: 395,286 CVEs, 1,756 KEV, 395,249 EPSS, 285,877 CVSS metric rows
- [x] Post-deployment scale fixes: bounded checkpoints/API queries, persistent CVE checkout cache, CVSS backfill
- [x] Deployed on Tailscale 100.124.184.116:3100; all pages and APIs respond <5s, 0 restarts
- [x] Global display timezone in the collapsible rail (default Asia/Jakarta), applied to overview, priority, methodology, radar, and replay instants; UTC day/month buckets stay labeled UTC
- [x] In-app `/api-docs` rendered from `openapi/v1.yaml` with curl examples, a topic/endpoint jump index, illustrative responses, and resolved parameter names
- [x] Full Research Console revamp (2026-10-26): persistent rail + command bar; Instrument Sans/JetBrains Mono self-hosted; visx volume/log-EPSS/severity/KEV charts; exact severity×EPSS matrix with KEV rings and keyboard inspector; collapsible explore filters with cohort charts; compact expandable priority table; radar feed/inspector; methodology/API restyle
- [x] Aggregate cache v3 adds `epssLogHistogram` and `severityEpssMatrix`; live refresh run on the 395k volume
- [x] Revamp verification: 365 unit + 68 Playwright tests pass (1 skipped), 44px targets, 360px/200%-equivalent overflow gates, reduced-motion gate; warm pages 0.01–0.39s, explore 2–4s cold (up to ~4.5s after restart) then 0.03s warm, 0 restarts
- [x] UI quality pass (2026-10-26): compact 17px help glyph; independently scrollable Explore filter rail; UTC date presets; collapsible/persisted desktop rail; severity donut; cumulative growth line; focus-month control with KEV additions; interactive methodology pipeline + coverage + worked example; API jump index and illustrative responses; parameter-name parser fixed
- [x] Final gates after the quality pass: 365 unit + 68 Playwright tests, lint/typecheck/build/Docker build green, zero overflow at 360px and the 200%-zoom-equivalent viewport, 0 restarts
- [x] Handoff audit (2026-10-26): README, DESIGN, CLAUDE.md, environment/resume protocol, feasibility/workflow status, and state files reconciled with the actual tree, commands, routes, cache v3, dependencies, test counts, and live deployment

## In Progress

- [x] TASK-008 rail polish (2026-10-27): themed dropdowns + Data-status rows mirror nav rows; shell e2e added, gates green. Committed as 7b70a63, rebuilt, live at 100.124.184.116:3100 (healthy, same volume, screenshot-verified).

None further. The stack runs serve-only (`INGEST_ON_START=false`, `SCHEDULE_ENABLED=false`)
so data refreshes are deliberate, not automatic.

## Blocked

None. The image was rebuilt once host DNS recovered and the container recreated on
the same volume; all data survived (395,286 CVEs, 285,877 CVSS rows).

## Open Questions

- Enable automatic refresh? Set `INGEST_ON_START=true` and `SCHEDULE_ENABLED=true`, then restart. First cycle re-clones (~1h); later cycles reuse the cache.
- Public HTTPS and a remote repository remain owner decisions. Revisit FIRST terms before monetization.
- Change Radar history accumulates only while the scheduler runs; today checkpoints = 0 and EPSS has one score date.

## Security Notes

- Application code exists and passed the Security Gate inputs: input validation, parameterized queries, generic errors, hardened headers, no secrets in code/logs, non-root container.
- `.env.example` contains placeholders; secret/runtime paths are ignored. Gitleaks unavailable;
  targeted baseline scans are not a comprehensive secret-scan guarantee.
- Owner authorizes focused local commits after verified milestones, not remote pushes.
- `npm audit` currently reports three dev-only Vitest-toolchain advisories; the production image excludes dev dependencies. Automated scanning/CI remains TASK-002.
- `npm run format:check` reports pre-existing repository-wide formatting drift (66 files); touched files are formatted individually. Do not present it as a green gate.

## Last Updated

2026-10-26: Research Console UI quality pass shipped and handoff docs reconciled with the code; 365 unit + 68 Playwright tests green; warm pages 0.01-0.39s, explore 2–4s cold (up to ~4.5s after restart) then 0.03s warm; 0 restarts.
