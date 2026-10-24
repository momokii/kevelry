# `.claude/` Agent Infrastructure

Orientation for humans and agents working in this repository.

## What This Repository Is

A blank project being bootstrapped for iterative, AI-assisted development. The purpose,
stack, and deployment targets are not defined yet. This `.claude/` directory is the
project's operating system: it tells every new session what the rules are, where the
work stands, and how to verify a change before calling it done.

## How Context Loads

Claude Code auto-loads the root `CLAUDE.md` at the start of every session, and it
persists through context compaction. Nothing else in `.claude/` is auto-loaded.

| Loaded when | Files |
|---|---|
| Every session (automatic) | `../CLAUDE.md`, which imports `AGENT_RULES.md`, `CODING_STANDARDS.md`, `SECURITY_STANDARDS.md`, and `state/CURRENT_STATUS.md` |
| On demand (agent reads when needed) | Everything else in this directory |

Import lines are plain text lines beginning with `@` and a relative path. Imports are
not evaluated inside code fences or inline code, so never wrap them. Imported files
load in full and consume context; keep them short.

## File Map

| File | Purpose |
|---|---|
| `settings.json` | Shared permission baseline (deny, ask, allow), enforced by Claude Code. |
| `README.md` | This orientation document. |
| `AGENT_RULES.md` | Non-negotiable behavioral rules; imported every session. |
| `CODING_STANDARDS.md` | Stack-agnostic coding standards; imported every session. |
| `SECURITY_STANDARDS.md` | Security requirements and the Security Gate; imported every session. |
| `ENVIRONMENT_GUIDE.md` | Development/staging/production definitions, agent behavior, and the Compose pattern. |
| `HOW_TO_RESUME.md` | The full session-start protocol. |
| `commands/resume.md` | `/resume`: run the protocol through baseline verification and report. |
| `commands/wrap-up.md` | `/wrap-up`: update state files after a task, in one batched write. |
| `commands/security-check.md` | `/security-check`: audit uncommitted changes against the Security Gate. |
| `state/CURRENT_STATUS.md` | Living state: phase, completed, in progress, blocked, open questions. Imported every session. |
| `state/TASK_QUEUE.md` | Ordered backlog with acceptance criteria and dependencies. |
| `state/DECISIONS_LOG.md` | Significant decisions and their rationale. |
| `state/HISTORY.md` | Append-only log of past session summaries. |
| `templates/new_feature.md` | Checklist for a new feature. |
| `templates/new_endpoint.md` | Checklist for a new API endpoint. |
| `templates/new_test.md` | Checklist for a new test. |
| `templates/bug_fix.md` | Checklist for a bug fix. |

## Permission Design Notes

Rules are evaluated **deny, then ask, then allow**; the first match wins, so deny
always beats allow. These rules are guardrails, not a security boundary.

- `.env.*` is **not** denied with a wildcard, because that would also block
  `.env.example`, which the agent must read and edit. Specific files are denied instead.
- `Read` and `Edit` deny rules cover Claude's built-in file tools, recognized Bash file
  commands (`cat`, `head`, `tail`, `sed`, `tee`), and redirect targets. They do **not**
  cover indirect readers such as `grep -r` run from the directory holding the file, or
  scripts that open files themselves. For OS-level enforcement, evaluate Claude Code's
  sandboxing feature; do not enable it without the user's confirmation.
- Bash rules match command text as written and are **not** a security boundary.
  `Bash(curl *)` does not match `/usr/bin/curl` or `sh -c 'curl ...'`, and
  `Bash(git push *)` does not match `git -C . push`.
- Plain `docker compose up *` matches default (development) invocations. The documented
  production form places `-f` before the subcommand (`docker compose -f compose.yaml -f
  compose.prod.yaml up`), so it does not match the allow rule and therefore prompts.
  Other flag placements can match, which is another reason Bash rules are not a boundary.
- Stack-specific commands (test runner, linter, package manager) are **not**
  pre-allowed. When the stack is chosen, propose an allow-list to the user and add it
  only with confirmation. Never add broad wildcards such as `Bash(*)`.
- `permissions.defaultMode` is deliberately **not** set; the user controls the mode.
- Do not create or modify `.claude/settings.local.json`.

## Protected Paths

`.claude/` is a protected path. In every mode except bypass, Claude Code never
auto-approves writes there (the exceptions are `.claude/worktrees` and Claude's own
auto-memory files), and allow rules such as `Edit(.claude/**)` do not pre-approve them.
Writes prompt once per session, with an option to allow edits in this project's
`.claude` folder for the session; in auto mode they are routed to the classifier. Batch
`.claude/` edits, and never work around the protection with shell redirection, extra
rules, or settings edits. If a write is refused, stop and report it.

The same protection applies to `.pre-commit-config.yaml`, `.husky/`, `.devcontainer/`,
and `.mcp.json`. Prompts for those files are expected.

## Shared vs. Local

| Shared (committed) | Local (gitignored) |
|---|---|
| `CLAUDE.md`, `.claude/settings.json`, and everything else in `.claude/` | `CLAUDE.local.md`, `.claude/settings.local.json` |

Never put personal preferences or secrets in shared files. Claude's own auto-memory is
machine-local; team-relevant knowledge must live in these versioned files.

## This Setup Evolves

Every file here starts general **by design**. As the stack, patterns, and decisions
become known, replace general content with project-specific content: real commands,
conventions observed in the code, framework-specific security guidance, and verified
environment procedures. Extend and sharpen rules; never weaken or remove a security
rule or loosen permissions without explicit user approval.

## Confirm Context Loaded

Run `/context` in a new session and check the **Memory files** list. It should show the
root `CLAUDE.md` and the four imported files. If any are missing, read them manually
and report the problem.
