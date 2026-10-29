# Contributing

Short version: keep the product honest, keep the tree green, stay in scope.

## Ground rules

- **Data honesty is the product.** Snapshots are the source of truth: never
  estimate an unknown value, never coerce it to zero, never interpolate a
  missing day. KEV, EPSS, and CVSS stay separate — no composite scores.
- **One logical concern per change.** Small, reviewable diffs with messages
  that say what changed and why. Never force-push. Never commit with
  `--no-verify`.
- **Zero regression.** Previously passing tests must still pass. Never
  disable, skip, weaken, or delete tests, linters, or type checks to make a
  change pass. Flag a regression immediately and stop.

## Local workflow

```bash
npm ci                  # install dependencies
npm run dev             # local dev server
npm test                # unit suite (must pass)
npx playwright test     # browser suite (must pass for UI/API changes)
npm run lint            # eslint (must pass)
npm run typecheck       # tsc --noEmit (must pass)
npx prettier --write <touched files>
```

Every behavior change adds or updates a test; bug fixes add a regression
test. The Security Gate in `.claude/SECURITY_STANDARDS.md` applies to every
change (input validation at the boundary, parameterized queries, no secrets
anywhere, generic client errors).

## What to read first

- `README.md` (product + operations), `DESIGN.md` (visual contract),
  `docs/DATA_WORKFLOW.md` (ingestion/ranking contract), `openapi/v1.yaml`
  plus `docs/api/` (API contract), `FEASIBILITY.md` (source terms and gaps).
- Agent-run housekeeping lives in `.claude/` (rules, task queue, history).

## Reporting vulnerabilities

See `SECURITY.md`. Do not open public issues for suspected vulnerabilities —
use private vulnerability reporting.

## License

Apache-2.0 (see `LICENSE`). Upstream CVE/KEV/EPSS data keeps its own terms;
see the data-license note in `LICENSE` and the in-app methodology notices.
Contributions are accepted under the same license.
