# Task Queue

Ordered backlog. One task in progress at a time. Pick the top unblocked task unless the
user directs otherwise. Statuses: `TODO`, `IN PROGRESS`, `DONE`, `BLOCKED`.

## TASK-001 — Establish project foundation

| Field | Value |
|---|---|
| Task ID | TASK-001 |
| Name | Establish project foundation |
| Priority | High |
| Status | TODO |
| Complexity | M |
| Depends On | User confirmation of stack, ranking policy and deployment target; see FEASIBILITY.md |
| Scope | Confirm purpose and stack with the user. Extend `.gitignore` for the stack. Set up formatter, linter, type check, and test tooling. Set up the Compose dev/prod pattern if the project is containerized. Update `CODING_STANDARDS.md`, `SECURITY_STANDARDS.md`, `ENVIRONMENT_GUIDE.md`, `HOW_TO_RESUME.md` commands, and the `CLAUDE.md` Commands table; propose a stack-specific `settings.json` allow-list. |
| Acceptance Criteria | One command each to run, test, lint, and health-check. All `.claude/` files reflect the real stack. The baseline test suite passes. Commands are recorded in `CLAUDE.md`. |
| Security Concerns | Stack choices affect the attack surface. Verify, pin, and audit new dependencies. No secrets in configuration. Container images run non-root with pinned tags. Do not loosen permissions without approval. |
| Notes | Perform this as part of, or immediately before, the user's first real task. |

## TASK-002 — Add automated security guardrails

| Field | Value |
|---|---|
| Task ID | TASK-002 |
| Name | Add automated security guardrails |
| Priority | High |
| Status | TODO |
| Complexity | M |
| Depends On | TASK-001 |
| Scope | Propose and, with user confirmation, add pre-commit secret scanning, dependency audit, static analysis, container image scanning if containerized, and a CI pipeline running tests, lint, type checks, and these scans. |
| Acceptance Criteria | Each guardrail runs locally or in CI and fails the build on a violation. Tool versions are pinned. The workflow is documented in `.claude/README.md` and the commands are listed in `CLAUDE.md`. |
| Security Concerns | Tooling must not receive or print secrets. CI logs must not expose environment values. Actions and images are pinned to immutable versions. Least-privilege tokens for CI. |
| Notes | Do not add tooling silently; present the proposal and wait for approval. |

## TASK-003 — Verify CVE website feasibility

| Field | Value |
|---|---|
| Task ID | TASK-003 |
| Name | Verify free data, existing alternatives and manageable pipeline |
| Status | DONE |
| Scope | Upstream CVE List V5, KEV and EPSS terms/access; competitor overlap; proposed source-only pipeline and ranking policy; project-local GPT-6 Luna routing. |
| Evidence | FEASIBILITY.md; live public endpoint checks; fresh-process model checks for librarian, plan, general and sisyphus-junior. |
| Follow-up | See TASK-004 for deeper audit. Stack/ranking/hosting still need approval; full import unmeasured. Actual subsequent audit delegates verified on GPT-6 Luna. |

## TASK-004 - Deepen pre-build source, workflow and competitor audit

| Field | Value |
|---|---|
| Task ID | TASK-004 |
| Name | Document exact source/feature coverage, ingestion and ranking before website build |
| Status | DONE |
| Scope | Primary-source reuse/access review; dated competitor comparisons; full EPSS structural check; exact proposed ingestion, CVSS selection, priority rules and worked examples. |
| Evidence | FEASIBILITY.md; docs/research/SOURCES.md; docs/research/COMPETITORS.md; docs/DATA_WORKFLOW.md. 31 synthetic assertions and local-link checks passed; one reviewer confirmed material findings resolved. |
| Limits | No website, full CVE import, search benchmark, continuous sync recovery, hosting estimate, legal approval or browser-rendered competitor verification. |
| Follow-up | Owner approval of bounded scope, use purpose/notices, ranking/CVSS policy, stack and deployment. Approve benchmark targets before measuring operational feasibility. |

## TASK-005 - Finalize design-led website execution plan

| Field | Value |
|---|---|
| Task ID | TASK-005 |
| Status | IN PROGRESS |
| Scope | Preserve overview/search/priority features; include approved Radar and retained-snapshot replay. Produce a distinctive design contract and reviewed implementation plan, without implementing the app. |
| Decisions | One runtime image/container; normal Compose startup production-safe; dev explicit. Focused local milestone commits authorized. |
| Drafts | .omo/drafts/cve-change-radar.md; .omo/drafts/cve-change-radar-design.md; .omo/drafts/cve-single-image-deployment.md |
| Remaining Gates | Owner bundled approval in .omo/drafts/cve-approval-brief.md, then final plan and Metis/Momus/independent review. Host-spec questions deferred by owner. |

## TASK-006 - Initialize and verify local version control

| Field | Value |
|---|---|
| Task ID | TASK-006 |
| Status | DONE |
| Scope | Initialize Git on main, exclude runtime/config backups, record existing baseline as focused commits, and verify tracked contents. |
| Evidence | 17 baseline commits cover exactly 30 reviewed files; no remote/push; ignore checks and targeted credential-marker checks passed. |
| Limits | Gitleaks unavailable; no application build/test baseline exists. No prior dates/history fabricated. |

## Task Template

```markdown
| Field               | Value                                               |
|---------------------|-----------------------------------------------------|
| Task ID             | TASK-XXX                                            |
| Name                | [Task name]                                         |
| Priority            | High / Medium / Low                                 |
| Status              | TODO / IN PROGRESS / DONE / BLOCKED                 |
| Complexity          | S / M / L                                           |
| Depends On          | [Task IDs]                                          |
| Scope               | [Exact description of what must be built]           |
| Acceptance Criteria | [Measurable definition of done]                     |
| Security Concerns   | [Security considerations for this task]             |
```
