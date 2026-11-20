# v3 Wrap-up Plan

**Target release:** 3.2.0 · **Status:** planned, not started · **Scope:** no new features

Four audits (correctness, data-visibility, architecture, docs accuracy) ran against
3.1.0; this is their triage and the commit sequence that closes it. Each heading states
the symptom, then evidence, fix, acceptance and the closing commit (`TBD` until it
lands). Order is risk, not effort: P0 misreports facts, P1 is structure, P2 is hardening.

**Corrected while verifying:** the "latest month" stat is `app/page.tsx:61` via
`StatStrip.tsx:23`, the KEV rhythm is `src/components/charts/KevRhythm.tsx`, the backwards
import is `src/lib/cwe-display.ts:14`, and the `format:check` drift is 44 files, not 66.

## P0 — correctness and honesty

- **P0.1 Stale aggregates are reported under a fresh revision.** Read paths trust the
  aggregate cache on `cached !== null` alone, so a failed `refreshAggregates` serves old
  counts under the new accepted revision.
  - **Evidence.** `_lib/coverage.ts:36-43`, `status/route.ts:19`, `health/route.ts:15`,
    `overview/route.ts:68` (all under `app/api/v1/`), `loadOverview.ts:453`;
    `src/worker.ts:202`; `_lib/provenance.ts:151-158` supplies the fresh revision.
  - **Fix.** Every read path checks currency against the acceptance ledger: refresh when
    stale, or serve the cache under the revision it came from. **Accept.** A failed-refresh
    test asserts no response pairs a new revision with previous-gen counts.
    **Commit.** `TBD`
- **P0.2 Error responses are cacheable while the docs say they are not.** 4xx/5xx carry
  no `Cache-Control: no-store`, so an intermediary may cache an error for a request that
  would now succeed.
  - **Evidence.** `_lib/responses.ts:21-40` sets no cache header; `DATA_WORKFLOW.md:427`
    and `_lib/http-cache.ts:57` both state errors are never cached.
  - **Fix.** Set `Cache-Control: no-store` on the error path; the documented guarantee
    becomes the reason for the header. **Accept.** Every error status asserts the header,
    and that 429/5xx carry no ETag and no `max-age`. **Commit.** `TBD`
- **P0.3 Rate-limit buckets are never evicted.** The per-IP map grows for the life of the
  process; a scraped port or an IPv6 /64 churns it, and only a hard reset clears it.
  - **Evidence.** `_lib/guardrails.ts:22` (module-level map), `:48-52` (insert or
    overwrite on expiry, never delete); `resetHardeningState` is the only sweep.
  - **Fix.** Evict expired buckets on write, swept against a size threshold rather than a
    timer; document in `docs/api/README.md` that the 600/min budget is per process.
    **Accept.** An expired bucket is gone after the sweep; the doc says where it applies.
    **Commit.** `TBD`
- **P0.4 The "latest month" stat can report an older month.** The KEV stat comes from the
  newest month _with additions_ while the label says "in the latest month"; with an empty
  current month it describes a different month than the caption.
  - **Evidence.** `app/page.tsx:61` (`reverse().find(entry => entry.count > 0)`), rendered
    by `StatStrip.tsx:23`; the dense month spine makes a trailing zero bucket normal.
  - **Fix.** Label what is measured: last month with additions, and name it — not the true
    latest bucket, where a `+0` reads as a data failure. **Accept.** A fixture whose
    newest bucket is zero renders the named month and a matching caption. **Commit.** `TBD`
- **P0.5 One missing observation erases the whole sparkline.**
  `values.some(v => v === null)` returns `null` for the chart, contradicting plan clause 6,
  which requires the caption to state how many observations are absent.
  - **Evidence.** `PriorityView.tsx:672`.
  - **Fix.** Plot the observed points, break the line at gaps, state the absent count. A
    gap is never drawn as zero. **Accept.** A fixture with one interior `null` renders a
    visible break, the caption reports the count, and no point sits at zero for that date.
    **Commit.** `TBD`
- **P0.6 The first ArrowRight after entering the sparkline does nothing.** Focus lands on
  the latest mark, so the first ArrowRight clamps to the same index.
  - **Evidence.** `PriorityView.tsx:684-692` (`initialIndex: latest`) with the clamp
    (`min(last, i + 1)`) in the same hook.
  - **Fix.** Make initial position and step direction agree: enter at the first mark, or
    wrap Right from the last to the first. **Accept.** A keyboard test asserts one
    ArrowRight from entry changes the announcement, at both ends. **Commit.** `TBD`
- **P0.7 The KEV rhythm tap clears on lift.** A touch tap shows the tooltip and closes it
  on `pointerup`, so the promised "kept until the next tap" does not exist on touch.
  - **Evidence.** `KevRhythm.tsx:70-78` clears `hoverIndex` with no pointer-type check;
    the sparkline has the guard at `PriorityView.tsx:793`.
  - **Fix.** Apply the same `event.pointerType !== "touch"` guard. **Accept.** A
    touch-emulated test asserts the tooltip survives `pointerup` and is replaced only by
    the next tap; a mouse test asserts hover still clears. **Commit.** `TBD`
- **P0.8 README, CLAUDE and docs drift.** Three counts and one description are wrong, and
  `.env.example` claims to list every variable the app reads while omitting three.
  - **Evidence.** `README.md:532` says 129 e2e, `README.md:34` and `CLAUDE.md:7` say 130
    (`--list` reports 130 across 18 files); `README.md:544` calls the `format:check` drift
    "Markdown/test" and cites 66 files, but it is 44 including `app/api-docs/page.tsx`,
    `src/components/ledger/*.tsx`, `docker/entrypoint.mjs`; `.env.example` lacks
    `LIVE_CLONE`, `EPSS_LIVE_TEST`, `BENCH_WRITE_EVIDENCE`.
  - **Fix.** Regenerate counts, describe the drift accurately, add the three variables.
    **Accept.** Counts match `playwright test --list` and the unit run; the `.env.example`
    header rule holds under a grep for `process.env`. **Commit.** `TBD`
- **P0.9 Two false claims in the 3.1.0 CHANGELOG.** The notes credit a consolidation that
  did not happen and describe a user-visible branch that cannot execute.
  - **Evidence.** `CHANGELOG.md:19` says the primitives "replace five hand-rolled copies";
    they were added beside them and `ChartTable` has 2 call sites. `CHANGELOG.md:61`
    claims a rejected band stays a labelled mark; `isSeverityBand` is always true, so the
    branch is unreachable.
  - **Decision.** Claim 1 is **made true** by P1.1; claim 2 is **corrected in wording**,
    its dead branch deleted with P1.3 — no band is rejected, nothing needs a label.
    **Accept.** The CHANGELOG matches the code. **Commit.** `TBD`

## P1 — structure

- **P1.1 The inspectable-data contract is only half finished.** Most charts still
  hand-roll the tooltip and table; three anchoring helpers and a slot pair are copy-paste.
  - **Evidence.** Tooltips: `CumulativeChart.tsx:54`, `EpssDistribution.tsx:53`,
    `VolumeChart.tsx:131`. Tables: `VolumeChart.tsx:435`, `CumulativeChart.tsx:172`,
    `EpssDistribution.tsx:168`, `TimeToKevSankey.tsx:627`, `SeverityDonut.tsx:143`,
    `GraphView.tsx:996`. Anchoring: `KevRhythm.tsx:77`, `TimeToKevSankey.tsx:449`,
    `CohortVisualization.tsx:90`. Dead: `onActiveChange`/`onFocus` unconsumed,
    `facts.slice(0, 2)` redundant, `loadOverview.ts:51` re-exports an unimported type.
  - **Fix.** Migrate all six tables and three tooltips onto the primitives; extract the
    anchoring helper and the hover/focus slot pair into one hook; delete the redundant
    slice, unused hook surface and re-export. **Accept.** The `chart-tooltip` and
    `chart-table` class names appear only in primitive files; e2e green. **Commit.** `TBD`
- **P1.2 Two share formatters for one concept.** The KEV rhythm prints `0.3%` where every
  other chart prints `0.31%` for the same kind of share — one word, two precisions.
  - **Evidence.** `KevRhythm.tsx:12` (`shareOneDecimal`) versus `chartTokens.ts:91`
    (`sharePercent`).
  - **Fix.** One helper; delete the local one. **Accept.** Pinned output for a set of
    counts, and the rhythm's share equals the donut's for the same denominator.
    **Commit.** `TBD`
- **P1.3 Donut focus is invisible.** Segments are real links inside the SVG but have no
  focus style, so keyboard users lose the cursor — the graph has exactly this rule.
  - **Evidence.** `SeverityDonut.tsx:79`, `:119` (`<a>` in `<svg>`); no
    `.donut a:focus-visible` in `app/ui.css`; the graph's rule is `app/ui.css:4635`.
  - **Fix.** Add the matching focus-visible rule; delete the unreachable rejected-band
    branch (P0.9). **Accept.** A focused segment renders an outline distinct from hover,
    at the contrast the graph rule passes. **Commit.** `TBD`
- **P1.4 The primitives and the sparkline have no direct tests.** The shared contract has
  no assertions of its own; the sparkline is tested only through `formatEpssPercent`.
  - **Evidence.** Zero references in `tests/` for `ChartTooltip`, `ChartTable` or
    `useRovingMarkFocus`; `.claude/CODING_STANDARDS.md:46` requires the coverage.
  - **Fix.** Unit tests for tooltip rendering, clamping and the last-30% flip, truncation
    to two facts, table structure and empty-series copy, roving Arrows/Home/End/clamp;
    plus an e2e keyboard matrix. **Accept.** Each primitive asserts its documented
    behaviour; the matrix covers both ends and Home/End/Escape. **Commit.** `TBD`
- **P1.5 The 44px rule cannot be audited.** The audit selector excludes the new focusable
  marks, so a 30px mark passes a check that claims to enforce 44px.
  - **Evidence.** `tests/helpers/a11y-audit.ts:155` measures only
    `button, a[href], select, textarea, input`; the marks are `div role="img"` with
    `tabindex`.
  - **Fix.** Extend the selector to focusable `role`-bearing marks. **Accept.** The audit
    fails on a deliberately undersized mark and passes on the real ones. **Commit.** `TBD`
- **P1.6 `src/lib` depends on a route directory.** A display module imports a type out of
  the API layer, so the dependency arrow points the wrong way.
  - **Evidence.** `src/lib/cwe-display.ts:14` imports from `app/api/v1/_lib/records.ts`.
  - **Fix.** Move the display read model into `src/lib`; leave route serializers in `_lib`.
    **Accept.** No `src/lib` import resolves into `app/`; typecheck and tests green.
    **Commit.** `TBD`
- **P1.7 `CONTEXT.md` does not exist.** Readers and contributors must infer the vocabulary
  (band vs cohort vs view, acceptance ledger vs aggregate cache) from code.
  - **Evidence.** No `CONTEXT.md` at the repo root or under `docs/`.
  - **Fix.** A short glossary: CVE, CPE-free scope, KEV, EPSS, SSVC, cohort, band, exploit
    signal, checkpoint, acceptance ledger, aggregate cache, snapshot. **Accept.** Every
    non-plain-English term in `README.md` and `docs/` has an entry matching the code.
    **Commit.** `TBD`

## P2 — small hardening

- **P2.1 The backup prune trusts an operator-supplied path.** `rm -rf` runs on `find`
  results whose root comes straight from `$1`; a stray `/` or an empty expansion targets
  directories outside the backup root.
  - **Evidence.** `scripts/nightly-backup.sh:71`; the root arrives at `:18` via
    `${1:-$HOME/cve-backups}`.
  - **Fix.** Reject an empty, relative or `/` root, and require an existing absolute
    directory inside an allowed parent. **Accept.** Non-zero exit for `""`, `/`, `//` and
    a relative path; a temp root still prunes. **Commit.** `TBD`
- **P2.2 The cron artifact cannot be verified as-is.** The script gzips the dump right
  after the container's verification, so the retained artifact needs a manual gunzip
  before `verifyBackup(dir)` passes — a step the runbook carries, the script does not.
  - **Evidence.** `scripts/nightly-backup.sh:51-55` (gzip) after the container run;
    `docs/backup-runbook.md:28` (manual `gunzip -c` for the drill).
  - **Fix.** Verify the compressed artifact, or verify the uncompressed copy then compress
    it, and print the drill command in the runbook. **Accept.** A fresh cron run verifies
    with no manual step. **Commit.** `TBD`
- **P2.3 `OPTIONS` bypasses rate and concurrency limits.** Preflight is exempt, which is
  deliberate for CORS but undocumented, so it reads as an oversight and invites a "fix"
  that breaks browsers.
  - **Evidence.** `_lib/guardrails.ts:141` (`preflightResponse`) skips both checks; `rate`
    and concurrency apply only inside `withApiRoute`.
  - **Fix.** Keep the exemption, document it beside the limiter with the reason.
    **Accept.** A doc line plus a test asserting `OPTIONS` is not rate-limited and sets no
    `Retry-After`. **Commit.** `TBD`
- **P2.4 `CWE_CSV_URL` accepts any URL.** An operator-set variable can point the importer
  at any scheme or host, so a typo or a compromised env becomes an arbitrary fetch.
  - **Evidence.** `src/lib/cwe-import.ts:388-391` returns the raw value when set.
  - **Fix.** Reject non-`https:` URLs and fall back to the pinned default with a logged
    reason — env-only, so defense in depth. **Accept.** Unit tests for `http:`, `file:`,
    `ftp:` and blank; `https:` passes; the rejection is logged, never thrown.
    **Commit.** `TBD`
- **P2.5 There is no `Strict-Transport-Security`.** HTTPS deployments advertise nothing to
  the browser, so a single plaintext visit stays downgradeable.
  - **Evidence.** No `Strict-Transport-Security` in `app/` or `src/`; headers are set in
    `_lib/responses.ts` and the app shell.
  - **Fix.** Send HSTS only when the request is HTTPS or an explicit opt-in is set — never
    on plain-HTTP self-hosting. **Accept.** The header appears for HTTPS and is absent for
    plain HTTP; the self-hosting path in `README.md` is unchanged. **Commit.** `TBD`

## What we are deliberately NOT doing

Recorded, not scheduled. Each is real; none belongs in a wrap-up release.

- **Splitting the large files** — `cve-import.ts` (1541 lines), `PriorityView.tsx` (1331),
  `GraphView.tsx` (1041), `worker.ts` (977), `radar.ts` (949), `search.ts` (844). High
  regression risk, no user-visible payoff; it needs its own test-first release.
- **The priority-list registry duplication** (route, page and view each carrying a copy)
  and the dual list definitions in `priority.ts`. Feature-shaped: it changes what a list
  _is_, not just where it is written.
- **Forecast-view performance** (`highest-forecast` 1.4 s, `rising-forecast` 2.7 s on a
  410k corpus). Awaiting an explicit go/no-go from the owner; no work starts before it.
- **Unifying the test-fixture corpus builder.** A test-only cost, merged for no
  production benefit.

## Release

**Version 3.2.0**, minor, not patch: cache-freshness semantics change (a stale cache may
be labelled rather than silently reused), sparkline gaps render, KEV-rhythm touch changes,
and the chart primitives are consolidated behind one interface.

**Gates, all green before tagging:** `npm run lint`, `npm run typecheck`, `npm run build`,
`npm test`, `npx playwright test`, `npm audit`, `npx prettier --check` on touched files.
Then refresh the docs and screenshots touched by P0.8 and P1.7, commit the version bump
and CHANGELOG entry, tag, build and push the image, deploy, and verify the changed
behaviours live: honest provenance after a failed refresh (P0.1), `no-store` on errors
(P0.2), a sparkline gap (P0.5), a touch tap keeping the KEV tooltip (P0.7).

**Exit criteria:** every item carries a commit sha instead of `TBD`, or a recorded
decision to defer it. No item is closed by editing this document alone.
