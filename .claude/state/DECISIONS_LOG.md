# Decisions Log

Significant decisions and their rationale. Append new entries at the top. Keep entries
short but complete enough for someone who was not in the session.

---

**Decision:** Make the display timezone global in the shared masthead, default Asia/Jakarta, display-only.

**Date:** 2026-10-26

**Context:** Timestamps were a mix of raw ISO strings and page-local formatting, so the owner could not read the site in one timezone.

**Rationale:** One selector in `Masthead` follows every page, persists in localStorage plus a cookie so SSR matches, and re-renders `TimeText` without reload. Radar and replay observation instants were converted too. UTC day/month buckets keep their UTC label because converting the bucket would change the meaning of the count.

**Alternatives Rejected:** Per-page selectors (drift and duplicates); converting chart buckets to local days (misstates the source date basis); a client-only preference (SSR flash and lost state).

**Security Implications:** Preference only; no data, identity, or authorization effect. Cookie is SameSite=Lax and contains one of six supported zone names.

**Impact:** New timestamps should render through `TimeText`; raw ISO strings in visible product copy are a defect.

---

**Decision:** Hand-build interactive charts and reuse the aggregate cache; no chart library.

**Date:** 2026-10-26

**Context:** The first overview had static bars with no hover, no keyboard path, and no link to the data, while every render recomputed aggregates over 395k rows.

**Rationale:** Bars are semantic links so hover, focus, click-through, and screen-reader names share one implementation. Shares always name a denominator. Data tables sit in `<details>`. Migration 002 adds covering indexes and an `aggregate_cache` refreshed on boot/import; ETags return 304 on repeats. The explore facet path reuses listing coverage and computes only months in SQL, cutting cold explore from 4.3s to 2.3s.

**Alternatives Rejected:** A charting dependency (weight, canvas accessibility gaps, new supply-chain surface); canvas-only rendering (values hidden from AT); client-side corpus aggregation (payload and consistency risk).

**Security Implications:** Adds no third-party runtime code. Cache responses are public, carry no user data, and set SWR bounds; errors are never cached.

**Impact:** Charts must keep 44px targets and the tooltip/denominator contract in DESIGN.md 6.13; new aggregate fields require a cache version bump.

---

**Decision:** Auto-apply explore filters while keeping the native GET form.

**Date:** 2026-10-26

**Context:** The owner wanted the visualization to change with filter choices, but the page is a server component and the filters must stay script-free-safe.

**Rationale:** Checkbox, radio, and select changes submit the existing GET form after a 150ms debounce; the text query and Apply button still submit explicitly. The URL remains the state, back/forward work, and no-JS behavior is unchanged. A `data-hydrated` flag lets tests wait for interactivity.

**Alternatives Rejected:** Client-side fetch/cache layer (duplicate state and stale-data handling); submit-only filters (the chart would lag the choice); auto-submitting on every keystroke (navigation noise).

**Security Implications:** No new input surface; query parameters remain validated by `searchCves`/`searchFacets`.

**Impact:** Filter controls must preserve typed values across reloads; tests must wait for hydration before asserting auto-submit.

---

**Decision:** Deploy serve-only on the Tailscale interface; refresh stays deliberate.

**Date:** 2026-10-25

**Context:** First live import of 395k records saturated CPU/IO and made requests
time out, and each refresh re-cloned a multi-GB repository.

**Rationale:** Bind `BIND_ADDR=100.124.184.116 PORT=3100` for tailnet access while
keeping `INGEST_ON_START=false` and `SCHEDULE_ENABLED=false`, so the site serves
the verified snapshot at full speed. Refreshes reuse `/data/cve-repo` once enabled.

**Security Implications:** Listener is limited to the Tailscale address, not
0.0.0.0; no TLS termination was added; no secrets in compose or image.

**Impact:** Data is a verified snapshot (2026-10-24/25) and will not update until
the owner enables ingestion. Radar history and rising forecasts stay empty until
daily checkpoints/EPSS dates accumulate.

**Decision:** Accept the completed implementation and close the execution plan.

**Date:** 2026-10-24

**Context:** All 30 build todos plus F1–F4 verification passed with evidence;
 Wave 5 merged to `main` on this machine only.

**Rationale:** Every deliverable was independently verified (DoneClaim →
AdversarialVerify → confirmed) before its commit; review findings were fixed,
not waived.

**Security Implications:** No change to the permission baseline; no secrets
introduced; hardening, rate limits, and safe headers verified in place.

**Impact:** The codebase on local `main` is the verified product. Release steps
(remote, hosting, TLS, FIRST-terms clarification before monetization) need
explicit owner decisions.

---

**Decision:** Make normal Compose startup production-safe; development is explicitly selected.

**Date:** 2026-10-24

**Context:** Owner wants simple `docker compose up -d` startup and explicitly approved
production-safe defaults instead of automatically loaded development overrides.

**Rationale:** `compose.yaml` must represent the safe normal runtime. Development
uses explicit `compose.dev.yaml`; do not ship an auto-loaded dev override. Compose
remains a wrapper around one all-in-one runtime image/container with persistent data.

**Security Implications:** No default hot reload, source mounts, debug/admin ports or
development tools in release. Move the agent's broad Compose-up rule from allow to ask;
preserve all deny rules and confirmation for non-development execution.

**Impact:** Supersedes the automatic-dev Compose convention below. Only policy/docs
changed: no Compose file, Dockerfile, setup script or application was implemented.

---

**Decision:** Approve the bundled product/design/stack/history proposal and the reviewed execution plan.

**Date:** 2026-10-24

**Context:** Owner approved Evidence Ledger design, debuggable self-hosted stack research, DESIGN.md plus real-browser QA, single-container runtime, 30-day observed replay, and open-source public deployment.

**Rationale:** One bundled decision unblocks a single decision-complete execution plan instead of repeated partial approvals.

**Security Implications:** TDD, negative tests, image/container verification, and benchmark gates are required in the plan; no audited software exists yet.

**Impact:** `.omo/plans/cve-change-radar.md` is the implementation basis pending a separate explicit instruction. Implementation, commits beyond planning, pushes, and deployments remain unauthorized.

---

**Decision:** Include Change Radar/replay and require standalone single-container deployment.

**Date:** 2026-10-24

**Context:** Owner explicitly answered yes to Radar and retained-snapshot replay alongside
the original features, then required one Docker image that runs everything, with optional Compose.

**Rationale:** Keep the proposed differentiator while preserving a simple self-hosted
runtime: web, ingestion/scheduling, local data/search and replay in one container.

**Security Implications:** Mutable data belongs in a persistent mount, not the image;
no mandatory external database/cache/worker service, host cron, privileged mode or Docker socket.

**Impact:** Packaging is approved; exact stack, retained-history window, hosting capacity,
visual direction and implementation remain pending. See `.omo/drafts/cve-single-image-deployment.md`.

---

**Decision:** Establish local Git history and make focused commits after verified milestones.

**Date:** 2026-10-24

**Context:** Owner explicitly requested a repository in this folder and proper process commits.

**Rationale:** Initialize `main` and record the existing baseline with concise English
action messages, split by concern; do not fabricate earlier history or timestamps.

**Security Implications:** Ignore secret/local runtime/backup files; stage explicit paths,
inspect patches and preserve hooks. No author/config changes, remotes, pushes or rewrites authorized.

**Impact:** 17 baseline commits contain exactly 30 intended files. Subsequent coherent,
verified milestones should receive local commits; tests stay with their implementations.

---

**Decision:** Pin this project's configured delegation agents and categories to GPT-6 Luna.

**Date:** 2026-10-24

**Context:** User explicitly requested GPT-6 Luna for all handoffs.

**Rationale:** Project-local overrides preserve other projects and existing permissions;
cross-model fallback is disabled to honor the selected model.

**Security Implications:** No credentials, provider endpoints or permission rules changed.

**Impact:** Startup configuration changes generally require restarting the affected
OpenCode instance. On 2026-10-24, actual assistant metadata for the subsequent planner,
two researchers, writer and reviewer confirmed GPT-6 Luna, resolving the earlier
unverified restart blocker for those handoffs. Source pipeline, stack and ranking in
`FEASIBILITY.md` and `docs/DATA_WORKFLOW.md` remain proposals, not architectural decisions.

---

**Decision:** Use the root `CLAUDE.md` as the single auto-loaded entry point with four imports.

**Date:** 2026-10-22

**Context:** Claude Code auto-loads only `CLAUDE.md` (and `CLAUDE.local.md`); other files in `.claude/` are not loaded automatically. The agent needs rules and security standards in every session without manual re-briefing.

**Rationale:** Importing four compact files gives every session the behavioral rules, coding standards, security standards, and current state, while keeping the launch context bounded. Deeper references stay on demand.

**Alternatives Rejected:** Putting everything in `CLAUDE.md` (too much context, harder to maintain); relying on `.claude/README.md` or `HOW_TO_RESUME.md` being auto-loaded (they are not); enabling `.claude/rules/` now (another always-on layer before there is a stack to scope it to).

**Security Implications:** The Security Gate is present in every session, which reduces the chance that security guidance is missed. Imported files must never contain secrets because they are loaded and transmitted as context.

**Impact:** The four imported files must stay concise. Any change to them affects every future session.

---

**Decision:** Adopt a security-first permission baseline in `.claude/settings.json` without setting `permissions.defaultMode`.

**Date:** 2026-10-22

**Context:** The repository needs guardrails before any code exists, but the user must retain control of the permission mode.

**Rationale:** Deny rules block secrets and the most destructive commands. Ask rules prompt for network access, force pushes, history-clearing operations, volume deletion, and CI workflow edits. Allow rules cover only routine, low-risk development actions. Evaluation is deny, then ask, then allow, so deny wins.

**Alternatives Rejected:** Pinning `defaultMode` (removes user control and is explicitly out of scope); broad allow-lists or `Bash(*)` (not a security boundary and too permissive); a wildcard `.env.*` deny (would also block `.env.example`, which the agent must edit).

**Security Implications:** These rules are guardrails, not an enforcement boundary. Bash rules match command text as written, so alternate invocation forms can bypass them. Read and Edit denies cover built-in file tools and recognized redirects, but not indirect readers or arbitrary scripts. OS-level sandboxing is the stronger control and must be evaluated with the user before enabling.

**Impact:** Stack-specific commands are not pre-approved. Once the stack is chosen, the agent proposes an allow-list and adds it only with confirmation. Writes to `.claude/` will prompt because it is a protected path.

---

**Decision:** Use a three-file Docker Compose layout: `compose.yaml`, `compose.override.yaml`, and `compose.prod.yaml`.

**Status:** Superseded on 2026-10-24 by the owner-approved production-safe default
and explicitly selected `compose.dev.yaml`; retained as historical rationale only.

**Date:** 2026-10-22

**Context:** Development needs hot reload and debug ports, while production needs hardened, reproducible containers. The two configurations must not drift.

**Rationale:** `compose.override.yaml` is loaded automatically by `docker compose up`, so development is the easy default. Production requires explicit `-f compose.yaml -f compose.prod.yaml`, which disables automatic override loading and forces a deliberate production invocation.

**Alternatives Rejected:** A single file with profiles (easier to run the wrong configuration accidentally); unrelated development and production files (drift and duplicated definitions).

**Security Implications:** Production overrides exclude source mounts, debug ports, and development tooling; use pinned image tags, resource limits, read-only filesystems where feasible, and a non-root user. Compose commands that are not clearly development require confirmation.

**Impact:** The agent must ask before any non-development Compose command. If the project chooses different file names, document them in `ENVIRONMENT_GUIDE.md` and follow the existing convention.

---

## Entry Template

Copy this block for each new decision; newest entry at the top.

```markdown
---
**Decision:** [What was decided]
**Date:** [YYYY-MM-DD]
**Context:** [Why it was needed]
**Rationale:** [Why this option]
**Alternatives Rejected:** [Other options and why not]
**Security Implications:** [Any security impact]
**Impact:** [What it affects downstream]
---
```
