# Current Status

## Project Phase

Deployed and serving on this host: single container at
http://100.124.184.116:3100 (Tailscale). All 30 build todos delivered, F1–F4
approved, plus post-deployment hardening. Local `main` only: no remote.

## Completed

- [x] `.claude/` agent infrastructure and root `CLAUDE.md` initialized
- [x] Free upstream CVE, KEV and EPSS access/terms checked; see `FEASIBILITY.md`
- [x] Existing close alternative verified: o2CVE search, statistics and priority list
- [x] Project-local Luna model overrides added; fresh-process agent checks passed
- [x] Source and competitor audits in `docs/research/`; coverage index in `FEASIBILITY.md`
- [x] Exact proposed ingestion/ranking contract in `docs/DATA_WORKFLOW.md`
- [x] Full EPSS structural check: 394,803 unique rows, zero invalid under stated checks
- [x] KEV count checks and 31 synthetic ranking/boundary assertions passed
- [x] Reviewer findings addressed; actual five delegated agent models verified as GPT-6 Luna
- [x] Owner approved original features plus Change Radar and retained-snapshot replay
- [x] Single runtime Docker image/container required; optional Compose wrapper
- [x] Git initialized; 17 focused baseline commits independently checked, no remote/push
- [x] Runtime records/backups ignored; targeted credential-marker scan found no matches
- [x] Production-safe `up -d` approved; dev explicit; agent Compose startup now asks
- [x] First-party font reuse licenses and candidate stack contracts checked, not built
- [x] Root README added: vision, diagrams, source feasibility, deployment/security plan, docs map
- [x] Bundled brief approved by owner (Evidence Ledger, Next/SQLite proposal, 30-day observed replay)
- [x] Execution plan complete and dual-approved: 30 todos + F1-F4, 4 review rounds, zero open blockers
- [x] All 30 build todos delivered: app shell, design system, TDD contracts, SQLite/FTS5, V5/KEV/EPSS importers, ranking, Radar/replay, read-only API + docs + hardening + parity, six UI views, a11y pass, Dockerfile, scheduling/health, Compose files, setup.sh, backup/restore, benchmarks — evidence `.omo/evidence/task-1` through `task-30-cve-change-radar.*`
- [x] F1 plan-compliance audit closed: 30/30 todos checked, GAP rows mapped, IS evidence paths unchanged, no Must-NOT-have in plan diff — receipt `.omo/evidence/task-31-cve-change-radar.log`
- [x] F2 code quality review approved: lint/typecheck/test green, no suppressions, pinned deps, parameterized SQL, no secrets
- [x] F3 browser QA approved: stock Playwright suite green with phone + desktop screenshots, keyboard/zoom/reduced-motion evidence
- [x] F4 ideal-state fidelity approved: 10/11 rows met outright; shortfall became tracked todo 31, now done
- [x] Live ingestion verified from upstreams: 395,286 CVEs, 1,756 KEV, 395,249 EPSS, 285,877 CVSS metric rows
- [x] Post-deployment scale fixes: bounded checkpoints/API queries, persistent CVE checkout cache, CVSS backfill
- [x] Deployed on Tailscale 100.124.184.116:3100; all pages and APIs respond <5s, 0 restarts

## In Progress

None. The stack runs serve-only (`INGEST_ON_START=false`, `SCHEDULE_ENABLED=false`)
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

## Last Updated

2026-10-25: deployed on Tailscale 100.124.184.116:3100 with live data; image rebuilt with all fixes; endpoints 0.02-5.7s, 0 restarts.
