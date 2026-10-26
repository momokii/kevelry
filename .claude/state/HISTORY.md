# History

Append-only. Newest entries at the top. One entry per completed or paused session.

## 2026-10-26 - Research Console quality pass

The owner accepted the new direction but flagged the remaining detail work:
oversized bordered help buttons, a filter rail that could not scroll, no desktop
rail collapse, an awkward date filter, a missing severity comparison because all
meter tracks looked alike, weak month focus on the volume chart, a methodology
page that still explained too little, and API docs without response examples or
a page jump index.

Fixed all of it: the help glyph is now a 17px inline circle inside a transparent
44px target; the Explore rail scrolls independently; date presets (7d/30d/90d/1y/
All) sit beside explicit UTC fields; the desktop rail collapses to 72px and
persists; severity composition is a real donut; the volume chart has a focus-month
select with KEV additions; a cumulative growth line was added; methodology gained
an interactive pipeline, live coverage diagram, and worked ordering example; API
docs gained a topic/endpoint jump index and illustrative response bodies. Also
fixed a long-standing spec-parser bug that left every API parameter name blank.

Final gates: 365 unit tests and 68 Playwright tests pass (1 skipped), including
new rail-collapse, date-preset, scrollable-filter, methodology-explainer, API TOC
and response-example coverage. Live timings 0.01-0.39s warm, explore 2-4s cold
then 0.03s warm, 0 restarts.
## 2026-10-26 - Full Research Console UI revamp

The owner rejected the Evidence Ledger presentation as dated and insufficiently
interactive, while keeping the palette and the data/scoring model. Ran parallel
research on 2026 dashboard patterns, chart libraries, and threat-intelligence
visualization, then built three visual prototypes (Editorial Atlas, Operations
Console, Scientific Workbench). Synthesized them into a Research Console:
persistent rail, command bar, Instrument Sans + JetBrains Mono, visx SVG charts,
and a centerpiece severity×EPSS matrix with KEV rings and a keyboard inspector.

Aggregate cache v3 adds exact log-EPSS buckets and joint severity×EPSS cells.
Explore gained a filter disclosure, auto-apply, and cohort composition; Priority
became a compact expandable signal table; Radar/Replay/Methodology/API docs were
recomposed around the same shell and primitives. All product copy, notices, and
no-composite-score rules remain. Removed the superseded overview components and
the legacy cohort styles.

Verification: 364 unit tests and 65 Playwright tests pass (1 skipped), lint,
typecheck, build, Docker build, 360/200% zoom and reduced-motion gates, live
timings 0.01-0.17s warm (explore 2.3s cold, 0.03s warm), 0 restarts.
## 2026-10-26 - Interactive UI, global timezone, and read-path speed

Reviewed the deployed site against the owner's feedback and rebuilt the weak
screen. The overview now carries five real visuals (24-month/30-day volume,
severity mix, EPSS distribution, KEV additions, corpus totals) with hover and
keyboard tooltips, denominator-labeled shares, and click-through to the exact
filtered view; source freshness leads with a plain-language verdict, per-source
meaning, relative/absolute times, and technical detail behind a disclosure.
Methodology gained pipeline, ordering, and signal-relationship diagrams with
every legal notice preserved. Explore gained filter HelpTips, debounced
auto-submit, and a matching-cohort panel (severity composition plus a monthly
histogram) that follows the applied filters. Priority rows now separate KEV,
EPSS, CVSS, and delta into explained blocks with real bars and timezone-aware
dates. The timezone selector moved into the shared masthead (default
Asia/Jakarta) and radar/replay observation times adopted TimeText. `/api-docs`
renders the OpenAPI spec in-app.

Performance work added migration 002 covering indexes and an aggregate cache,
process-wide read-only handles that reopen when the database file changes,
ETag/304 responses, and a coverage-reusing facet path. Live measurements:
`/` 0.39s, `/priority` 0.24s, `/methodology` 0.03s, `/explore` 2.34s cold then
0.018s warm, 0 restarts. Fixed a chart bar-height bug found by visual QA, a
tooltip Escape re-open bug, and 21px mobile overflow in the monthly list.
Verification: 364 unit tests pass (3 skipped), 67 Playwright tests pass
(1 skipped), lint/typecheck/build green, screenshots at 360/768/1280.
## 2026-10-25 - Deployed on Tailscale with live data

Built and deployed the single container on this host, bound to the Tailscale
address `100.124.184.116:3100`, using a verified live database (395,286 CVEs,
1,756 KEV, 395,249 EPSS, 285,877 CVSS metric rows; 4.33 GB, integrity ok).
Post-deployment testing exposed and fixed real scale defects that unit tests
missed: a 395k-variable SQL query that crashed the server, unbounded API and
page materialization (status 23s, cves 47s, priority page aborted),
a re-clone of the whole repository on every refresh (now a persistent
`/data/cve-repo` cache), a missing `cvss_metrics` write path (backfilled from
stored records), and missing `git`/CA certificates in the runtime image.
Final state: every page and API answers 200 in under 5s with restarts 0.
The stack is intentionally serve-only right now; enabling
`INGEST_ON_START`/`SCHEDULE_ENABLED` resumes refresh (first cycle re-clones).
The image was then rebuilt once host DNS recovered, and the container was
recreated on the same volume with all data intact.

## 2026-10-24 - Implementation complete, all gates approved

Executed `.omo/plans/cve-change-radar.md` Waves 1–5 plus F1–F4 on task-owned
worktrees, merged per wave to `main`. Every todo verified by an independent
reviewer before its commit (failing-first TDD, adversarial probes, secret scans).
Notable catches during execution: an unroutable dual App Router root found by the
Docker smoke test (fixed by consolidating `src/app/api` into `app/api`), a hermetic
test-suite defect (fixed with seeded env + explicit negative test), and a dev-server
hostname quirk fixed in the Playwright webServer config. F1 plan-compliance,
F2 code quality, F3 browser QA (stock suite green with phone/desktop/keyboard/zoom/
reduced-motion evidence), and F4 ideal-state fidelity (10/11 outright; shortfall
became tracked todo 31, now done) all approved. Benchmarks measured and recorded;
cold-cache drift within tolerance. No remote, no deployment, no monetization.
ORCHESTRATION COMPLETE.

## 2026-10-24 - Execution plan written, reviewed, and dual-approved

Built `.omo/plans/cve-change-radar.md`: 30 sequenced todos across 5 waves plus F1-F4,
with scope, verification strategy, dependency matrix, commit strategy, and success
criteria. Structural self-check passed (headers, grammar, per-todo contracts, all
GAPs closed, no placeholders). Metis gap review folded (traceability, IS evidence,
pins, budgets, TLS docs, terms recheck, F3 wording, KEV dependency). Momus plus
independent Oracle review ran across 4 rounds against digest-pinned artifacts with
zero open blockers; receipts recorded in the draft frontmatter. No application,
Dockerfile, Compose, dependency, or setup work was started. Next step waits for an
explicit implementation instruction.

## 2026-10-24 - Root README and pre-dev condition

Added root `README.md`: project vision, two mermaid diagrams (data/runtime flow,
checkpoint/replay lifecycle), source-feasibility table, planned deployment/security
contracts, docs map, and open pre-dev gates. All local links checked; wording keeps
planning status explicit (no app, Compose file, image, or passing tests claimed).
Committed as one focused docs commit. Remaining blockers unchanged: bundled approval
brief, final execution plan plus Metis/Momus/independent review, then implementation
on explicit instruction. True popularity, universal aliases/severity, and full
reservation counts remain explicitly out of scope.

## 2026-10-24 - Secure startup approval and consolidated planning brief

Owner approved production-safe `docker compose up -d` with explicitly selected
development. Updated environment guidance, superseded the old auto-dev convention,
and moved the agent's Compose-up permission from allow to ask; deny rules are unchanged.
No Docker, app, dependency, setup script or production command was executed.

Read-only stack/font research and parent first-party checks informed a consolidated
approval brief under `.omo/drafts/`. Proposed Next/Node plus a separately supervised
Node ingestion process in the same container, embedded SQLite/FTS5, Evidence Ledger,
30-day observed daily replay, existing ranking policy and test/security gates.
Registry versions are dated candidates, not an installed/tested/approved combination.
Three font licenses are OFL-1.1; exact assets and visual QA remain pending.
Host questions are deferred. Next action is one bundled owner approval, then creation
and review of the final execution plan. No application implementation is authorized.

## 2026-10-24 - Scope approval, Docker contract and Git baseline

Owner approved Radar/replay alongside original overview/search/priority requirements,
required one self-contained Docker runtime image/container with optional Compose, and
authorized local Git initialization and focused process commits. Updated the `.omo`
planning/design drafts and added a deployment contract covering persistence, scheduling,
PID1/shutdown, readiness, recovery, backup/upgrade and standalone/Compose parity tests.
No application or Docker implementation was started and no Docker command was executed.

Initialized `main`; 17 local baseline commits recorded exactly 30 reviewed files.
Parent independently checked history, tracked paths, clean status and no remote.
Runtime records/config backups are ignored; targeted credential-marker checks found
no matches. Gitleaks is unavailable and no comprehensive scan is claimed. Author
identity/config, permissions and existing hooks were not changed; nothing was pushed.
Planning still needs operating envelope, retention, stack and visual/policy decisions.

## 2026-10-24 - Deeper pre-build audit

Expanded `FEASIBILITY.md` with feature coverage and confidence/gaps; added
`docs/research/SOURCES.md`, `docs/research/COMPETITORS.md` and
`docs/DATA_WORKFLOW.md`. Documented source access/reuse conditions, exact proposed
Git/delta recovery, independent snapshot publication, CVSS selection, five view
orders, missing data, date anomalies, formulas, examples and launch gates.
Parsed the full EPSS daily CSV: 394,803 unique rows and zero structural errors under
the stated checks; KEV declared/actual/unique counts each 1,756. Checked live primary
CVSS for both PHP example CVEs. 31 synthetic assertions and local-link/fence checks
passed. One reviewer confirmed its feature/date/example findings resolved.
Actual model metadata for all five direct delegates showed GPT-6 Luna. Browser QA
was unavailable (Chromium missing), Markdown LSP absent, and full CVE import/search,
continuous recovery and hosting costs remain unmeasured. No website implementation
or stack/deployment decision was made. True popularity, full aliases/reservations
and universal severity remain explicitly unsupported or conditional.

## 2026-10-24 - CVE website feasibility and Luna routing

Recorded source terms, competitor overlap, live access evidence, and a proposed
minimal pipeline in `FEASIBILITY.md`. CVE List V5, KEV and EPSS can support the
planned public cybersecurity dashboard without paid feeds, subject to notices and
terms. o2CVE already overlaps the proposed product; earlier uniqueness claims were
corrected. Recommended separate priority lists instead of an unvalidated Heat score.
Added project-local GPT-6 Luna overrides and verified fresh-process agent resolution.
The running session needs restart before further task-tool handoffs. No application
code, dependencies, deployments, or paid services were introduced. JSON LSP is
unavailable because Biome installation was previously declined.

## 2026-10-22 — Infrastructure bootstrap

Created the root `CLAUDE.md` entry point with four always-loaded imports, the `.claude/`
governance files (agent rules, coding standards, security standards, environment guide,
resume protocol), three slash commands, four state files, and four task templates.
Established a security-first permission baseline in `.claude/settings.json` with secret
and destructive-command denies, network and production-affecting asks, and minimal
development allows. Defined the Compose base/override/prod pattern and the `.env.example`
contract. No product code exists yet; the first task is TASK-001 (establish the project
foundation) once the user confirms purpose and stack.

**Outcomes:** context loads automatically every session; all files are stack-agnostic and
ready to be sharpened; security and environment discipline are defined before the first
commit.
