# Decisions Log

Significant decisions and their rationale. Append new entries at the top. Keep entries
short but complete enough for someone who was not in the session.

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
