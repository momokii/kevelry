# How to Resume

The full session-start protocol. `/resume` runs steps 1–7 and reports; steps 8–11 are the
task loop.

1. **Confirm context is loaded.** `CLAUDE.md`, `AGENT_RULES.md`, `CODING_STANDARDS.md`, `SECURITY_STANDARDS.md`, and `state/CURRENT_STATUS.md` should appear in `/context` under Memory files. If they are not visible, read them manually.
2. **Read `.claude/state/TASK_QUEUE.md`.** Identify the next unblocked task and its dependencies. Do not start a task whose dependencies are incomplete.
3. **Identify the active environment.** Check `APP_ENV`; consult `ENVIRONMENT_GUIDE.md`. An unknown environment means production-safety rules apply.
4. **Check git state.** Branch, uncommitted changes, and recent commits. Never clobber existing work.
5. **Read task-relevant docs.** Start with `README.md`, `DESIGN.md`,
   `docs/DATA_WORKFLOW.md`, `docs/api/`, and `openapi/v1.yaml`; use
   `state/DECISIONS_LOG.md` for _why_ and `state/HISTORY.md` for prior sessions.
6. **Verify the environment works.** Check `docker compose ps`, then
   `curl -fsS http://127.0.0.1:3000/api/v1/health` (or the Tailscale
   `100.124.184.116:3100` base). The stack is serve-only by default on this host.
7. **Run the existing test suite as a baseline.** `npm test`, then
   `npm run lint` and `npm run typecheck`; record pass/fail before changing anything.
8. **Plan.** State scope, files to create or modify, risks, and verification. Ask for confirmation if the change is significant or touches architecture, schema, dependencies, or infrastructure.
9. **Implement** using the matching template in `.claude/templates/`.
10. **Verify.** Tests, lint, type checks, and the Security Gate in `SECURITY_STANDARDS.md`.
11. **Wrap up.** Update state files in one batched write; `/wrap-up` performs this checklist.
