---
description: Run the session-start protocol through baseline verification and report state without starting implementation.
---

Run steps 1–7 of `.claude/HOW_TO_RESUME.md`. Do not implement anything yet.

- Confirm the memory files are loaded.
- Read the task queue and choose the next unblocked task.
- Determine `APP_ENV` (unknown means production-safe).
- Check git state.
- Read relevant docs.
- Verify the environment and run the baseline tests, if commands are defined.

Report in under 15 lines:

1. Current state (from `state/CURRENT_STATUS.md`)
2. Next task and its dependencies
3. Active environment
4. Baseline test/lint/type-check result, or "not yet defined"
5. Blockers or open questions

Stop and wait for the user's confirmation before starting work.
