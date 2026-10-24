---
description: Audit current uncommitted changes against the Security Gate and report findings by severity.
---

1. Run `git diff` and `git diff --staged`. If this is not a git repository, say so and stop.
2. Review every change against the Security Gate in `.claude/SECURITY_STANDARDS.md`.
3. Also check for secrets, unsafe input handling, missing authorization, permissive CORS or CSRF, sensitive logging, dependency changes, and dev-only behavior that would leak into production.
4. Report findings grouped as Critical, High, Medium, Low. For each: file and line reference, the risk, and the smallest safe fix.
5. If there are no findings, list the gate items checked and state that the diff passed.
6. Do not modify code or configuration without asking first.
