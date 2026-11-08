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

- [x] TASK-026 import short-circuit + WAL checkpoint (2026-11-07): an unchanged CVE revision no longer re-hashes the tree hourly, and the worker truncates the WAL each cycle. Commit `1c64b2f`.
- [x] TASK-027 exploit-tagged references (2026-11-07): publisher `exploit` tags surfaced as a labelled signal with links, never as a verified PoC. Commit `20668da`.
- [x] TASK-028 Sankey interactions + flow dialog (2026-11-07): clickable bands, pinned selection, drill-down dialog with filter/paging. Commit `5a8f001`.
- [x] TASK-029 volume granularity (2026-11-07): month/week/day buckets with matching windows and full-height hit targets. Commit `ab78540`.
- [x] TASK-030 fastest-confirmations card (2026-11-07): explained metric, two stats, linked rows. Commit `bfea56d` + refinement.
- [x] TASK-031 EPSS retention window (2026-11-07): `EPSS_RETENTION_DAYS` (default 90, matching the API's 90-point history cap) prunes inside the import; byte-identical CSVs short-circuit. Live DB audited at 5.18M rows / 13 days and no window before this.
- [x] TASK-032 import cost (2026-11-07): the KEV import rescanned all 396k records once per catalog entry; now one scan per import. Boot cycle 7m30s → 52s (38s after deploy), WAL in the low hundreds of KB.
- [x] TASK-033 upstream ref resolution (2026-11-08): the importer resolved the _local_ branch, so the corpus sat 11 days behind while fetches succeeded. Now resolves `refs/remotes/origin/<branch>` first. Corpus caught up: 396,841 → 401,935 records, November 3,210, newest publication 2026-11-08.
- [x] TASK-034 import hot spots (2026-11-08): content receipt is the git tree id (no 4.3 GB re-read); migration 005 deletes FTS documents by rowid (was a 396k-document scan per update, ~50 min for 17.5k updates); `cve-import-phase` timings added. CVE import 7.5s total.
- [x] TASK-036 exploit-tagged references (2026-11-08): stored flag (migration 006) filled at import and backfilled once, aggregate cache v4 counts, overview coverage card, Explore filter + row badge, API `?exploit=tagged`. Live: 46,463 tagged (12% of 401,935), 259 also KEV.
- [x] TASK-037 retention audit (2026-11-08): window proven on a DB copy (3.18M rows in 28.1s, exact cutoff), migration 007 drops the redundant EPSS index (identical plans, −180 MB), `EPSS_HISTORY_CAP` shared with retention, methodology states window + oldest retained day + VACUUM caveat.
- Final gates for the owner batch: 416 unit, 98 e2e (1 skipped), lint/typecheck/build/Docker build green; four pre-existing e2e races (Sankey band open, help tooltip sidebar measure, matrix Enter→ArrowRight, hydrated node replacement) were made deterministic rather than retried blindly.

- [x] TASK-008 rail polish (2026-10-27): themed dropdowns + Data-status rows mirror nav rows; shell e2e added, gates green. Committed as 7b70a63, rebuilt, live at 100.124.184.116:3100 (healthy, same volume, screenshot-verified).
- [x] TASK-009 console polish batch (2026-10-27): 8 owner-reported UI fixes across overview/explore/replay; committed as 27b5f93, rebuilt, live and screenshot-verified. One focus-outline regression caught and fixed mid-task.
- [x] TASK-010 tooltip bubble + accepted times (2026-10-28): committed as 011df29, rebuilt, live and screenshot-verified.
- [x] TASK-011 scheduled refresh enabled (2026-10-28, Option A): .env SCHEDULE_ENABLED/INGEST_ON_START true (gitignored); CVE hourly + KEV hourly + EPSS daily. Recovery took 3 cycles (stale lock, missing local main, forced upstream rewrite); all three sources accepted fresh, hero shows minutes-ago. New backlog TASK-012 (restart lease storm, TODO).
- [x] TASK-013 v1 public release batch (2026-10-28): Apache-2.0 LICENSE + data-terms note, SECURITY.md, XFF hardening + test, CI on pinned SHAs, robots/sitemap/favicon/OG/404, showcase noindex, API identity note, Cloud Run single-image + VM/Caddy docs. Rebuilt, live, verified end to end.
- [x] TASK-014 API docs accuracy (2026-10-28): curl uses the spec origin (machine IP appears only once, in the intentional instance note); illustrative responses rewritten key-for-key against live shapes; committed as d4abaa2, rebuilt, live verified.
- [x] TASK-015 disclosure markers (2026-10-28): response-example and data-table summaries had no visible affordance; added the rotating chevron + 44px target. Committed as 50120e2, rebuilt, live healthy.
- [x] TASK-016 row dates + rail highlight (2026-10-28): priority/explore rows now say Published; rail-status no longer double-highlights with nav. Committed as 84131bf, rebuilt, live screenshot-verified.
- [x] TASK-018 chart navigation (2026-10-29): inspector + month links go client-side; live URL swap 58ms vs 4.8s reload. Committed as 24710ae, rebuilt, live timed.
- [x] TASK-019 dashboard grid (2026-10-30): rows even left/right, legend numbers aligned; verified pixel-equal live at desktop/tablet/mobile. Committed as d629fd1.
- [x] TASK-012 lease storm + page headers (2026-10-29): lease-acquire retry, page framing headers, Dockerfile patch-shape fix. Verified live with no API header dupes.
- [x] TASK-017 nightly backups (2026-10-29): RUN_BACKUP_ONCE branch, host script + 02:00 cron, live 4.6GB backup verified, >2 GiB hash fix, dependabot, CONTRIBUTING, Permissions-Policy.
- [x] README v1 face (2026-10-29): product title, license/node badges, live screenshots, repo map + stack rationale, fresh scale counts. Committed as e2fb129 (docs-only, no redeploy needed).
- [x] Docker Hub release (2026-10-29): `kelanach/kevelry:1.0.0` + `latest` pushed (same digest, verified via Hub API); README points at the real image.
- [x] Kevelry rebrand (2026-10-29): wordmark CVE Intel → Kevelry across UI titles/brand + README. Internals (package/image/volume) intentionally unchanged. Committed as b17f2ef, rebuilt, live title verified.
- [x] GitHub launch (2026-10-29): `momokii/kevelry` created by owner; full history pushed over SSH and verified byte-identical; CI badge wired to the real repo. Remote `origin` tracks `main`.

None further. Scheduled refresh is ON (`INGEST_ON_START=true`, `SCHEDULE_ENABLED=true`):
CVE + KEV refresh hourly, EPSS daily; all three accepted fresh on 2026-10-28.

## Blocked

None. The image was rebuilt once host DNS recovered and the container recreated on
the same volume; all data survived (395,286 CVEs, 285,877 CVSS rows).

## Open Questions

- Public HTTPS and a remote repository remain owner decisions. Revisit FIRST terms before monetization.
- Change Radar history accumulates daily while the scheduler runs; checkpoints began 2026-10-28 (first daily write pending), so radar/replay history builds over the coming days.

## Security Notes

- Application code exists and passed the Security Gate inputs: input validation, parameterized queries, generic errors, hardened headers, no secrets in code/logs, non-root container.
- `.env.example` contains placeholders; secret/runtime paths are ignored. Gitleaks unavailable;
  targeted baseline scans are not a comprehensive secret-scan guarantee.
- Owner authorizes focused local commits after verified milestones, not remote pushes.
- `npm audit` currently reports three dev-only Vitest-toolchain advisories; the production image excludes dev dependencies. Automated scanning/CI remains TASK-002.
- `npm run format:check` reports pre-existing repository-wide formatting drift (66 files); touched files are formatted individually. Do not present it as a green gate.

## Incident 2026-11-07 — homepage 25–31s stall

Symptom: `/` appeared unreachable in the browser while every other page was fine. Causes: the
ingestion worker was running a **full** 395k-record import each cycle (`cve-diff-path: full-first`),
which grew the SQLite WAL to 491 MB and left the precomputed aggregate cache stale, so the
overview fell back to full-corpus scans per request. Fixed without data loss: WAL checkpoint
(491 MB → 20 KB) and `REFRESH_AGGREGATES_ONCE=true node worker.mjs`. Verified `/` at 0.26–0.31s,
`/priority` 0.30s. **Open:** the repeated full-import path is the root cause and is not yet fixed.

## Time-to-Exploitation Sankey (2026-11-03)

Overview gained a two-column Sankey: publication-year cohort → days until KEV confirmation,
with median delay, within-30-days share, excluded count and the fastest confirmations. It is
derived from `date_published` + `date_added` only (no new feed) and computed per request over
the KEV cohort. Live: 1,765 eligible, median 480 days, 292 (16.5%) confirmed within 30 days.

## Watch List, Graph, and SSVC (2026-11-03)

- `/watch`: browser-only starred CVEs, hydrated through `/api/v1/cves/{id}`; no account, no server record, 200-id cap.
- `/graph`: ranked hub landing (no implicit center) → centered ego drawing (CVE → shared attribute → records), grouped cards below, drill-down dialog with filter/sort/pagination, and a reading guide that states what a link does and does not mean.
- `ssvc-active` priority view: CISA SSVC decision points stored verbatim (migration 004), fourth ingestion source at daily cadence, 201 active-exploitation records live. Ordered by impact → automatable → **KEV catalog date descending** (newest confirmation first), with a 30/90/365-day recency window in UI and API, plus an in-page explainer of what SSVC means and how to read it.
- Theme: topbar sun/moon toggle, `data-theme` pre-painted from cookie (no flash).

## Last Updated

2026-10-26: Research Console UI quality pass shipped and handoff docs reconciled with the code; 365 unit + 68 Playwright tests green; warm pages 0.01-0.39s, explore 2–4s cold (up to ~4.5s after restart) then 0.03s warm; 0 restarts.
