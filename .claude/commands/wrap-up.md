---
description: Update all state and standards files after a task in one batched write, then summarize what changed.
---

Perform the Wrap-Up checklist in `.claude/AGENT_RULES.md`.

1. Gather every change first. Then write all updates **in one batch** to minimize permission prompts for the protected `.claude/` path.
2. Update `state/CURRENT_STATUS.md` (keep it under ~80 lines; move older summaries to `state/HISTORY.md`).
3. Update `state/TASK_QUEUE.md`: mark the task done, add discovered tasks, reorder if needed.
4. Append significant decisions to `state/DECISIONS_LOG.md`.
5. Update `CODING_STANDARDS.md`, `SECURITY_STANDARDS.md`, `ENVIRONMENT_GUIDE.md`, `CLAUDE.md` (Snapshot and Commands), and `README.md` only where they changed.
6. Do not commit or push.

Print a short summary: files updated, task status, next task, and any open questions.
