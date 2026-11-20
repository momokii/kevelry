# Inspectable Data Contract — audit and implementation plan

**Status:** implemented. P1–P4 landed on `main`; §7.0 of `DESIGN.md` is the
normative text and this document is the audit it came from. What did not land is
listed under [Deferred](#7-deferred).
**Problem:** two charts hide their values behind an affordance that does not work
(EPSS sparkline on `/priority`, KEV rhythm on `/`), and no single rule says how a
reader gets the exact number out of a mark.

**Finding up front:** this repo already has most of the answer. `DESIGN.md` §7
"Chart contract" states six requirements and four charts implement them well
(Volume, Cumulative, EPSS distribution, Sankey). The gap: §7 is prose, the
implementation is hand-rolled per chart, and two charts were never migrated — so
the work is **one primitive + two migrations + a sweep**, not a new system.

## 1. Inventory

Every data visualisation, with what a reader could get **before** the migration.
The "Hover today" column is the audit snapshot that motivated the work, not the
current state; §7.0 of `DESIGN.md` says what each row is held to now, and row 8
no longer exists (see [Deferred](#7-deferred)).

| #   | File : lines                              | Component             | Type                      | Hover today                                                          | Exact value without hover                           | Keyboard                                      | aria / screen-reader story                                                                        |
| --- | ----------------------------------------- | --------------------- | ------------------------- | -------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 1   | `charts/VolumeChart.tsx:122-230`          | `VolumeChart`         | bar (SVG)                 | custom `.chart-tooltip`, positioned over the bucket                  | yes: peak label, axis, `<details>` table            | 44px hit rects, Tab, Enter/Space select, Esc  | root `role="img"`; per-hit `role="button"` + `aria-label` with count, share, "Select to inspect"  |
| 2   | `charts/CumulativeChart.tsx:52-110`       | `CumulativeChart`     | area + line               | custom `.chart-tooltip`, pinned top-left of the frame                | yes: axis, data table                               | every point `tabIndex=0`, Enter/Esc           | root `role="img"`; point `role="button"` + label "month: cumulative, that month"                  |
| 3   | `charts/EpssDistribution.tsx:51-100`      | `EpssDistribution`    | histogram                 | custom `.chart-tooltip`, pinned top-left                             | yes: binned axis, data table                        | every bar `tabIndex=0`                        | root `role="img"`; bar `role="img"` + label "EPSS bin: n records, share"                          |
| 4   | `charts/SeverityDonut.tsx:31-120`         | `SeverityDonut`       | donut                     | hover/focus updates centre number                                    | yes: legend prints count + share; data table        | segments and legend links focusable           | root `role="img"`; segments `role="button"` although none act (defect); legend links labelled     |
| 5   | `charts/DensityMatrix.tsx:95-175`         | `DensityMatrix`       | heatmap                   | hover updates an inspector aside                                     | yes: every cell prints its count                    | roving `tabIndex`, arrows, Home/End           | `role="group"`; `<button>` per cell + full label "band, EPSS bin: n CVEs, m KEV"                  |
| 6   | `charts/TimeToKevSankey.tsx:420-500`      | `TimeToKevSankey`     | sankey                    | node hover isolates bands; bands carry native `<title>`              | yes: node labels print totals; flow readout; dialog | nodes/bands focusable, Enter pins, Esc clears | root `role="img"` (flattens children); node `role="button"` + label with count and share          |
| 7   | `charts/KevRhythm.tsx:13-21`              | `KevRhythm`           | mini bar (HTML divs)      | **native `title` only** — OS tooltip after ~1s, on the bar body only | **no** — only the 12-month total in the caption     | **none**, not focusable                       | `role="img"` on the container makes the 12 `title`s presentational: SR gets one string, no values |
| 8   | `charts/SeverityMix.tsx:18-24`            | `SeverityMix`         | proportional track rows   | native `title` + `aria-label`                                        | yes: count + share printed in the row               | rows are links                                | rail `aria-hidden`; link carries the full value in its name                                       |
| 9   | `priority/PriorityView.tsx:622-666`       | `EpssTrend`           | **sparkline**             | **none** — no pointer handler, no element per point                  | **no** — only "25 observations, first..last"        | **none**                                      | root `role="img"`; label gives the span and count, not one value                                  |
| 10  | `priority/PriorityView.tsx:685-695`       | `EpssSignal` bar      | single bar                | n/a                                                                  | yes: `2.15%` in text + `.srOnly`                    | n/a                                           | track `aria-hidden`, value repeated in `.srOnly`                                                  |
| 11  | `explore/CohortVisualization.tsx:108-160` | `CohortVisualization` | severity rows, month bars | native `title` + `aria-label`                                        | yes: count and share printed                        | rows are links                                | track `aria-hidden`; link name carries value + action                                             |
| 12  | `graph/GraphView.tsx:409-520`             | `EgoGraph`            | fixed-column graph        | none                                                                 | yes: attribute count printed, leaf ids printed      | leaves are links; `+N more` button            | root `role="img"` flattens the link tree (defect); `+N more` labelled                             |
| 13  | `methodology/CoverageDiagram.tsx:1-60`    | `CoverageDiagram`     | proportional rows         | none                                                                 | yes: count + share + note per row                   | n/a (static)                                  | track `aria-hidden`, values as text                                                               |
| 14  | `overview/ExploitCoverage.tsx:29`         | `ExploitCoverage`     | single bar                | none                                                                 | yes: counts printed beside it                       | n/a (static)                                  | bar `aria-hidden`, values as text                                                                 |
| 15  | `ledger/ChartView.tsx:44-46`              | `ChartView`           | demo bars                 | none                                                                 | n/a                                                 | n/a                                           | bars `aria-hidden`; the table _is_ the content — the model to copy                                |

Notes: `.chart-tooltip` / `.chart-table` / `.data-table` / `.chart-note` exist in
`app/ui.css`; `ChartInfo` ("How to read") is used on 5 overview panels but **not**
on KEV rhythm. `PriorityView.tsx:670` puts `aria-label` on a bare `<div>` (no
role) — ignored by AT, same class of defect.

### The two quoted components

`charts/KevRhythm.tsx` — the tooltip is a native `title` on a non-focusable div:

```tsx
<div className="kev-bars" role="img" aria-label="KEV catalog additions by UTC month">
  {months.map((entry) => (
    <div
      key={entry.month}
      className="kev-bar"
      title={`${monthShort(entry.month)}: ${formatInt(entry.count)} KEV additions`}
    >
      <span
        className="kev-bar-fill"
        style={{ height: `${6 + (entry.count / max) * 78}px` }}
        aria-hidden="true"
      />
      <span className="kev-bar-label" aria-hidden="true">
        {monthShort(entry.month)}
      </span>
    </div>
  ))}
</div>
```

No `tabIndex`, no handler, no `ChartInfo`, no `<details>` table, and the month is
abbreviated without saying it is a UTC month. The hit area is only the fill plus
the label (~50–90px of a 132px row), so the whitespace above a short bar is dead.

`priority/PriorityView.tsx` — the sparkline is one polyline plus one dot:

```tsx
<svg className={styles.trend} viewBox="0 0 100 36" preserveAspectRatio="none" role="img"
     data-testid="priority-row-epss-trend"
     aria-label={`EPSS trend over ${points.length} dated observations, ${first.scoreDate} to ${last.scoreDate}.`}>
  <polyline points={coords.join(" ")} fill="none" stroke="currentColor" strokeWidth={1.5}
            vectorEffect="non-scaling-stroke" />
  <circle cx={lastX} cy={lastY} r={2.5} fill="currentColor" />
</svg>
<figcaption className={styles.trendCaption}>
  {points.length} dated observations, {first.scoreDate} to {last.scoreDate}
  {last.modelVersion !== "" ? ` · model ${last.modelVersion}` : ""}; latest point marked.
</figcaption>
```

`preserveAspectRatio="none"` with `height: 44px` (`PrioritySignals.module.css:231`)
means 25 points across a ~300–500px panel (up to `EPSS_HISTORY_CAP = 45`,
`app/api/v1/_lib/epss-history.ts:18`) — naive point targets are 7–20px. The data
already exists per point (`scoreDate`, `epss`, `modelVersion`); nothing to fetch.

## 2. The Inspectable Data Contract (IDC)

Extends `DESIGN.md` §7, which becomes its normative home in P1; §7's six bullets
survive. These ten clauses are what a reviewer checks.

1. **Every mark is a stop.** Each data-bearing mark (point, bar, segment, cell,
   band, node) is reachable by pointer hover **and** keyboard focus and has a text
   alternative. Dense read-only charts are one Tab stop, then arrows step marks
   (roving `tabIndex` at ≥12 marks).
2. **The tooltip has a fixed three-part shape.** `label` = the mark's period or
   identity in the caption's format plus the date basis (`Sep 2026 · UTC`).
   `value` = the exact number with its unit (`20 KEV additions`, `2.15% EPSS
probability`). `share` = at most two supporting facts, each naming its
   denominator (`43 of 412 additions, 10.4%`) plus the caption's caveat (model
   version). Nothing longer than this fits.
3. **Value never depends on hover.** An exact value must exist without pointing:
   printed at the mark, in the caption, or in the `<details>` table built from the
   same series. The tooltip is never the only copy; this retires `title`-only marks.
4. **Placement is deterministic.** The tooltip renders inside a `position:
relative` chart host (`chart-frame` or the mark's wrapper), is clamped to the
   host width, flips to the other side in the last 30% of the plot, never covers
   the mark it describes, and is `pointer-events: none`.
5. **Dense series get a strip, not 45 tooltips.** A sparkline's overlay is one
   invisible band per x-interval with nearest-index mapping on pointer move,
   Arrow/Home/End stepping and a polite live announcement of the value focus
   landed on. The EPSS trend is the reference implementation; its default state
   still marks the latest point.
6. **Zero, missing, and unknown are three different things.** A zero count is a
   real value: focusable, tooltip `0`, a 1px bar with a full-height hit target. A
   missing observation is never plotted at zero: the line breaks and the caption
   names the count ("3 of 25 dates missing"). Absence is stated, never inferred.
7. **Role follows behaviour.** Inspect-only marks are `role="img"`; marks that
   select, pin, or navigate are `role="button"` (or a real `<a>`) and say so in
   their label. Interactive marks never live inside a `role="img"` node — that
   flattens them out of the tree; the grouping element is a named `role="group"`.
8. **The root label describes, it does not conclude.** `aria-label` on the chart
   root gives series, unit, number of marks, and range. Sentences about the data
   ("most records sit below ten percent") belong in the note, not the label.
9. **Touch is first class.** A tap opens the same tooltip and keeps it until the
   next tap elsewhere or a second tap on the same mark. No reveal depends on
   hover, and any mark is at least 44px in its interactive dimension.
10. **One implementation.** `ChartTooltip` and `ChartTable` are the only
    permitted renderers of those two patterns. `title=` on a chart mark is a
    defect unless the same value is visible text (then it is redundant, and goes).

### Which primitive survives, which retires

| Primitive                                                                                                | Verdict                                                                        |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `.chart-tooltip` + `.tt-label` / `.tt-value` / `.tt-share` (`ui.css:1224`)                               | **survives**, wrapped as `<ChartTooltip>` so the three call sites cannot drift |
| `<details class="chart-table">` + `table.data-table` (5 hand-rolled copies)                              | **survives**, extracted as `<ChartTable>`                                      |
| focal hit-target + `aria-label` + Esc (`VolumeChart:186-228`)                                            | **survives** as the reference interaction; lifted into a hook                  |
| `ChartInfo` and the `.chart-note` caption                                                                | **survive**, unchanged                                                         |
| native `title=` as the only affordance (`KevRhythm:18`, `SeverityMix:22`, `CohortVisualization:114,157`) | **retired** (redundant where values are printed, replaced where they are not)  |
| `role="button"` on non-acting marks (`SeverityDonut:61`)                                                 | **retired**                                                                    |
| `role="img"` wrapping focusable content (`KevRhythm:13`, `GraphView:414`, Sankey root)                   | **replaced** by `role="group"`                                                 |

## 3. Phases

### P1 — shared primitive and the normative home — done (`fe076be`)

`charts/ChartTooltip.tsx`, `charts/ChartTable.tsx`, `charts/useInspectableMarks.ts`
(active index, roving tabIndex, Esc, live announcement); `DESIGN.md` §7.0 = the
IDC verbatim. Migrate the three `.chart-tooltip` and five `chart-table` call sites
onto the components with **no text or geometry change**.

Acceptance — checkable without reading code:

- `/`, `/explore`, `/graph` render identical visible text to `main` (diff the
  `data-testid` subtrees); hover/focus/Enter/Esc on Volume, Cumulative and EPSS
  distribution behave exactly as before; existing e2e assertions pass unmodified.
- `grep -rn 'className="chart-tooltip"' src` and `grep -rn '<details\
className="chart-table"' src` match only the two new components.
- `npm run lint`, `tsc --noEmit`, unit suite and the 6 route e2e specs green.

### P2 — EPSS sparkline (`/priority`, `PriorityView.tsx:622`) — done (`27f644f`, precision fixed in `98611ba`)

Bands per point, pointer + arrow stepping, `ChartTooltip`, a `<details>` table of
every observation (date, percent, model), root becomes `role="group"` while
keeping the `priority-row-epss-trend` testid and a label containing "dated
observations" (an existing e2e asserts that string).

Acceptance:

- Tab reaches the sparkline once; ArrowRight from there announces the first
  observation's date and percent; End lands on the latest point.
- Hovering anywhere in the plot shows the nearest point — including between
  points and over the flat runs that make up most of the live series.
- A point's tooltip = date (`19 Nov 2026`, UTC), `2.15% EPSS probability`, model
  version; never overflows the row panel at 390px or 1280px.
- The `<details>` table lists 25 rows for `CVE-2024-10441`, values only, and still
  renders with JS disabled.

### P3 — KEV rhythm (`/`, `KevRhythm.tsx`) — done (`d1d9872`)

Full-height hit target per month, roving keyboard, `ChartTooltip` with full month
name + `UTC` + count + share of the 12-month total, `ChartTable`, `ChartInfo`, and
an explicit zero-month rendering. Container `role="group"`. Keep the caption
sentence ("catalog activity, not exploitation volume") and the total — both are
load-bearing.

Acceptance:

- 12 bars, 12 tab stops' worth of Arrow stepping, one Tab stop into the panel.
- Focused-tooltip and hovered-tooltip text are identical for the same month.
- Every month reads `September 2026 · UTC` / `43` / `43 of 322 additions, 13.4%` —
  the denominator is the caption total, which the data table also sums to.
- A month with zero additions draws a 1px bar, is focusable, and says `0`.
- The panel has "How to read" and a data table; neither existed before.

The zero-month line is only reachable if the loader returns twelve calendar
buckets, so both loaders now build a twelve-month UTC spine
(`src/lib/kev-months.ts`) and left-join the sparse `kev_entries` counts onto it;
a gap month is a `0` bucket, never an absent row. Pinned by
`tests/kev-rhythm-months.test.ts` and the overview e2e gap-month assertion.

### P4 — sweep — done (`3e890cf`, reachability fixed in `7c3c27c`)

Cohort visualization and severity mix: drop the redundant `title`s, keep the
printed values. Donut: `role="img"`, not `button`. Graph: root `role="group"` so
the leaf links stay in the tree. Sankey: band `title` → tooltip; root role. Matrix:
add the data table (cells already print counts). Update the §1 state column so
every row reads "compliant" or names an exemption and why.

Acceptance:

- The §1 table, updated in place, has no row whose hover, keyboard or aria cell
  says `none`, except the listed exemptions (13–15: values are printable text or
  the table is the content).
- `grep -rn 'title={' src/components` matches only the allowlist printed in
  §7.0 of `DESIGN.md` (CWE names, `<time>` raw values, nav affordances).
- axe-core (`tests/e2e/a11y-audit.ts`) reports no new violation on all six routes,
  and the console is clean on a full keyboard pass of `/` and `/priority`.

## 4. Risks

- **Target size vs. density.** 45 observations in a 44px-tall, ~300px strip is
  ~7px per point. The band overlay must not become a 45-stop Tab trap; clause 5
  mandates roving arrows and P1 owns the hook.
- **Test coupling.** `tests/e2e/priority.spec.ts:519-521` asserts the sparkline's
  `aria-label` contains "dated observations"; P2 keeps it. Overview e2e asserts
  panel text, so P3 must not reword the caption.
- **`role` churn is visible to axe.** Swapping `img`→`group` on four roots changes
  what the audit reports; P1's e2e run is the gate, not a manual read.
- **Tooltip clipping in the priority panel** (~360px on mobile, scrolls). Clamped
  placement (clause 4) is the mitigation; verify at 390px.
- **SSR/no-JS.** Tooltips are client state; the table must stay in the SSR payload.
  "Make the charts consistent" also invites a redesign — the contract fixes
  content, placement and reachability, not styling.

## 5. Out of scope

- New chart types, new aggregates, or any API/payload change (the sparkline's
  per-point data already ships).
- Restyling `.chart-tooltip`, the palette, or typography.
- Mobile layout rework beyond tooltip clamping and 44px targets.
- Visual-regression tooling, i18n, and the 45-cap retention policy itself.
- Any change to ranking, ordering, filtering, or the honesty caveats.

## 6. Evidence (live instance `http://100.124.184.116:3100`)

- `/overview` returns **404**; the overview is `/` (nav label "Overview", `href:
"/"`, `Shell.tsx:30`). "Overview" below means `/`.
- `GET /priority` → 200, 562,693 bytes SSR, 25 rows, **one** rendered sparkline:
  row 1 `CVE-2024-10441`, 2.15%, dated 2026-11-19, model v2026.06.15, 25 dated
  observations 2026-10-24 → 2026-11-19. `CVE-2020-46217` from the brief is not on
  this instance (`/api/v1/cve/CVE-2020-46217` → 404, 0 occurrences in the page).
- Sparkline hover: **nothing happens.** The DOM is one `<polyline>` and one
  `<circle>`; no `title`, no `tabindex`, no listener, so Tab skips it. Screen
  reader: one node, "EPSS trend over 25 dated observations, 2026-10-24 to
  2026-11-19." — no probability appears anywhere.
- KEV rhythm hover: the OS tooltip appears after the browser's delay over the bar
  body or its label only (e.g. `Sep 26: 43 KEV additions`); the 132px row's empty
  upper area is inert, the text is unstyled, and there is no `UTC` or share.
  Focus: none of the 12 bars is focusable. Screen reader: `role="img"` makes the
  twelve `title`s presentational, so the only output is "KEV catalog additions by
  UTC month" — no month, no count. The panel has no "How to read" and no table.

## 7. Deferred

Recorded so the next reader does not mistake "P1–P4 done" for "every acceptance
line in §3 was executed".

- **axe is not available as a dependency.** `@axe-core/playwright` is not
  installed, and `tests/e2e/a11y-audit.ts` is a hand-rolled audit (horizontal
  overflow, 44px control size, live-region count, control labels) rather than an
  axe wrapper. So the P4 acceptance line "axe-core reports no new violation on
  all six routes" could not be run at all — the P1–P4 e2e suites exercise the
  audit that does exist, and nothing here is evidence about axe. Adding the
  dependency and running it on the six routes stays open. This also means the
  `role="img"` → `role="group"` swaps were validated by the existing specs and a
  manual pass, not by axe.
- **`SeverityMix` outcome: deleted, not migrated.** `charts/SeverityMix.tsx` had
  no importer — `grep -rn "SeverityMix" src/ app/ tests/` matched only its own
  declaration — and the overview had already moved to the severity donut, so its
  P4 migration (drop the redundant `title`, keep the printed count and share in
  the link name) is superseded by removing the component (`8435791`). Row 8 of
  §1 therefore has no current file; the pattern it demonstrated lives on in the
  donut and in `CohortVisualization`.
- **The Escape tests flake and were not fixed here.** The Escape paths that end a
  tooltip, a pinned mark or a dialog (`tests/e2e/overview.spec.ts` around the
  filter/dialog dismissals, `tests/e2e/graph.spec.ts` for the attribute dialog)
  were reported intermittently failing while P1–P4 were being built. No cause was
  found and no fix was applied: the final full run was 129 passed / 0 skipped, so
  there is no reproduction to work from. Treat these as the suite's known
  flake — re-run before believing a failure, and do not "fix" them by widening a
  timeout.
