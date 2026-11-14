# Design System — Research Console

Status: current product design as of 2026-10-26. The previous Evidence Ledger
product styling is retired; the primitive showcase under `app/showcase/` remains
as a regression fixture and is the only place where legacy `ledger-*` classes are
still authored directly.

## 1. Concept

CVE Intel is a **research console**, not a report and not a generic dashboard.
The interface should feel like a precise instrument for reading a large,
imperfect corpus:

- one clear question per page;
- charts lead, prose explains only what the chart cannot;
- exact counts, named denominators, visible uncertainty;
- warm paper, dark ink, one working accent, semantic color only for meaning;
- direct manipulation with a keyboard equivalent for every interaction.

The three reference directions (Editorial Atlas, Operations Console, Scientific
Workbench) were synthesized. The shell and density discipline come from the
console; the opening statement and large numerals come from the editorial
direction; the joint-distribution inspector comes from the scientific direction.

## 2. Palette

| Token              | Value              | Role                               |
| ------------------ | ------------------ | ---------------------------------- |
| `--ui-paper`       | `rgb(247,246,243)` | page canvas                        |
| `--ui-paper-deep`  | `rgb(240,238,232)` | rail / recessed chrome             |
| `--ui-surface`     | `rgb(255,255,255)` | panels, tables                     |
| `--ui-ink`         | `rgb(26,26,26)`    | primary text, bars, primary button |
| `--ui-ink-2`       | `rgb(89,89,89)`    | secondary prose                    |
| `--ui-ink-3`       | `rgb(132,129,123)` | labels, axes, metadata             |
| `--ui-rule`        | `rgb(214,211,205)` | section rules, borders             |
| `--ui-rule-soft`   | `rgb(232,229,223)` | table rows, gridlines              |
| `--ui-accent`      | `rgb(0,106,159)`   | links, selection, focus            |
| `--ui-accent-soft` | `rgb(230,243,249)` | selected surfaces                  |
| `--ui-critical`    | `rgb(170,40,52)`   | critical CVSS band                 |
| `--ui-high`        | `rgb(188,88,20)`   | high band                          |
| `--ui-medium`      | `rgb(142,104,0)`   | medium band                        |
| `--ui-low`         | `rgb(52,102,80)`   | low band                           |
| `--ui-legacy`      | `rgb(104,88,128)`  | CVSS v2 only                       |
| `--ui-unknown`     | `rgb(130,127,121)` | unscored / no data                 |

Rules:

- Never encode severity or source state with color alone. Pair with a word, a
  symbol, a shape, or a ring.
- Semantic hues are for marks and badges, not page chrome.
- Text uses ink tokens; accent text must sit on paper or `--ui-accent-soft`.
- New colors require a token and a contrast check.

### Dark theme (`[data-theme="dark"]`)

Warm charcoal carrying the same hue family; the accent and semantic hues are
lifted for contrast on dark surfaces. Primary buttons invert (near-white fill,
dark text). Every product surface flips by token assignment; showcase-only
legacy styles outside the tokens intentionally stay light.

| Token                 | Dark value         | Note                    |
| --------------------- | ------------------ | ----------------------- |
| `--ui-paper`          | `rgb(22,21,19)`    | canvas                  |
| `--ui-paper-deep`     | `rgb(15,14,12)`    | rail / recessed         |
| `--ui-surface`        | `rgb(33,32,29)`    | panels, tables          |
| `--ui-surface-raised` | `rgb(44,42,37)`    | hover wells             |
| `--ui-ink`            | `rgb(236,234,228)` | primary text, bars      |
| `--ui-ink-2`          | `rgb(178,174,166)` | secondary prose         |
| `--ui-ink-3`          | `rgb(138,134,125)` | labels, axes            |
| `--ui-rule`           | `rgb(64,61,55)`    | borders                 |
| `--ui-rule-soft`      | `rgb(46,44,40)`    | rows, gridlines         |
| `--ui-rule-strong`    | `rgb(100,96,87)`   | strong borders          |
| `--ui-accent`         | `rgb(104,186,228)` | links, selection, focus |
| `--ui-accent-deep`    | `rgb(150,210,245)` | accent text             |
| `--ui-accent-soft`    | `rgb(20,48,62)`    | selected surfaces       |
| `--ui-accent-line`    | `rgb(52,112,142)`  | selected borders        |
| `--ui-critical`       | `rgb(228,115,124)` | critical band           |
| `--ui-high`           | `rgb(236,150,88)`  | high band               |
| `--ui-medium`         | `rgb(222,176,66)`  | medium band             |
| `--ui-low`            | `rgb(112,182,146)` | low band                |
| `--ui-legacy`         | `rgb(172,152,212)` | v2 only                 |
| `--ui-unknown`        | `rgb(150,146,138)` | unscored                |
| `--ui-positive`       | `rgb(96,180,140)`  | good states             |
| `--ui-caution`        | `rgb(224,178,64)`  | warnings                |

Supporting tokens (`--ui-ink-raise`, `--ui-nav-hover`, `--ui-topbar-veil`,
`--ui-scrim`, `--ui-drawer-veil`, `--ui-pill-x`, `--ui-tooltip-label`,
`--ui-{danger,critical,high,medium,low,legacy}-{bg,border}`) each carry a
dark assignment in `app/ui.css`. The select chevron data-URI has a dark
variant. `color-scheme: dark` keeps native controls (scrollbars, date
inputs) legible. The theme persists via `ui-theme` localStorage + cookie
(`DisplayPrefs`), applied pre-paint from the cookie so themed first paint
never flashes.

## 3. Typography

Self-hosted variable fonts in `public/fonts/` (OFL, copied with licenses):

- **Instrument Sans** (`400–700`) for UI, prose, headings, and numerals.
- **JetBrains Mono** (`100–800`) for CVE IDs, eyebrows, axes, tabular labels.

Scale:

| Role             | Size / treatment                                    |
| ---------------- | --------------------------------------------------- |
| hero number      | `clamp(52px, 8vw, 104px)`, 600, `-0.055em`, tabular |
| h1               | `clamp(30px, 3.6vw, 44px)`, 600, `-0.035em`         |
| h2 / panel title | 19–23px / 15px, 600                                 |
| body             | 15px / 1.5, max 68ch                                |
| data / table     | 13px, tabular numerals                              |
| eyebrow / label  | 10–11px mono, uppercase, `0.08em`                   |

`font-variant-numeric: tabular-nums` is global. Do not use the retired Newsreader
serif stack for product headings.

## 4. Shell

Desktop (`>1080px`):

- 232px persistent rail, `--ui-paper-deep`, 1px right rule; collapse control
  reduces it to 72px and persists the choice in `localStorage`.
- Brand, seven primary destinations with inline SVG icons, active item = white
  surface + inset accent rule + `aria-current="page"`.
- Rail footer: source-status link, API reference, display timezone.
- 58px sticky topbar with current context, global search (`⌘K` focuses it),
  data-status link, and an Explore action.
- Content column max 1560px, 24px gutters.

Mobile / 200% zoom:

- Rail becomes an off-canvas sheet with a scrim and a 44px menu button.
- The same switch is triggered by a container query on `.app-shell` so 200%
  zoom reflows without requiring a viewport change.
- Search, topbar actions, and the rail remain keyboard reachable.

The shell owns the `*-masthead` test ids (`overview-masthead`, `explore-masthead`,
etc.) so page-level navigation assertions stay stable.

## 5. Layout primitives

- `.page` — page content wrapper inside the shell.
- `.page-head` — eyebrow, h1, lede, actions; exactly one h1 per page.
- `.grid` — 12-column grid with `min-width: 0` children and `align-items:start`.
- `.panel` — white surface, 1px rule, 8px radius. Used for actual modules only,
  never as a universal card wrapper.
- `.stat-grid` / `.stat` — four-up corpus numbers with hairline dividers.
- `.section` — open section separated by a rule; preferred over another panel.
- `.table-wrap` / `.data-table` — scrollable table with sticky mono header.
- `.drawer` — reserved for future row detail; not yet used by product pages.
- `.notice`, `.empty-state`, `.pill`, `.badge`, `.btn` — shared state/action
  primitives. Interactive targets are at least 44×44px.

Spacing uses the 4/8/12/16/20/24/32/40/48/64 scale.

## 6. Page composition

### Overview

1. Page header with snapshot instant and data-status action.
2. Hero: factual statement, corpus number, KEV/forecast coverage.
3. Four stats: unknown dates, KEV-listed, EPSS-scored, unscored severity.
4. Volume panel (month/week/day buckets, matching windows, focus-bucket select,
   hover/focus tooltip, click selection with KEV additions and an Explore link)
   - cumulative growth line.
5. Severity donut with an interactive legend and log-EPSS distribution.
6. Joint severity×EPSS matrix with KEV rings and a cohort inspector.
7. KEV rhythm, freshness, and honesty notes.
8. Priority evidence in four compact lists.

### Explore

Rows carry the same evidence as a Priority row, in the same order and with the
same component: severity badge, `KEV` (with its catalog addition date), the real
`EPSS` probability with its ordinal percentile (`0.391% · 33rd pct`), the primary
CVSS version and score, the updated instant, and — when the record has one — the
`Exploit refs` block with the linked references. A badge never appears without
the evidence behind it: `Exploit ref` and the reference list are produced by the
same walker (`exploitReferenceUrls`) and rendered by the same
`src/components/ledger/ExploitSignal.tsx` that the Priority view uses, so the two
views cannot drift apart again.

### Explore

Filter disclosure (open by default, collapsible) inside a rail that scrolls
independently on desktop. UTC date fields pair with 7d/30d/90d/1y/All presets.
Cohort composition shows severity meters, monthly counts, and signal coverage;
compact result rows carry severity/KEV/EPSS chips and official-record actions.

**Export control contract.** The results header carries two 44px controls,
`Export CSV` and `Export JSON`, each labelled with the row count it will write
(`Export CSV (20 rows)`). Both are real links to `/api/v1/search` carrying the
page's own query string and cursor plus `format=csv|json`, so the file is
**page-bounded**: exactly the rows on screen, never the whole cohort and never a
second scan. The label is the promise: the count equals the rendered rows and
the file's data rows. Each control is disabled with a visible explanation only
when the page has no rows. The default unfiltered Explore view is exportable:
`format=csv|json` is the one request shape allowed to omit both `q` and
`vendor`, and it serializes the same unfiltered first page (publication date
descending, unknown dates last, the page's `limit`). A JSON request without
`format` still requires `q` or `vendor`. Provenance and coverage stay in the JSON
envelope (and beside the control) — the CSV file is a header row plus data rows,
with no `#` comment lines, because spreadsheet and SQL importers would read them
as data. The column contract lives in `docs/api/search.md`.

### Priority

Compact expandable table. The first five rows open their signal blocks; the rest
stay one line plus badges. A sticky rail holds the exact ordering rules and
snapshot evidence. No composite score, ever.

### Radar / Replay

Radar: a `Subscribe` block (44px link to `/api/v1/radar/feed.xml` with the RSS
type, plus the same absolute URL in a read-only input that selects itself on
focus, so the URL is copy-able by keyboard alone), then the snapshot pair,
change-kind filter, feed on the left, sticky evidence inspector on the right.
Replay: retained-checkpoint selector, historical banner, then the five replayed
lists with the same row language.

### Methodology / API docs

Methodology adds an interactive six-stage pipeline with a detail panel and
failure branch, a live signal-coverage diagram, and a worked ordering example
with mode tabs and a highlighted deciding key. It keeps the anchor nav, legal
notices, and per-source health. API docs adds a jump index for topics and every
endpoint, resolved parameter names, and an illustrative response body per
endpoint; the spec remains the source of truth.

## 7. Chart contract

All charts are SVG or semantic HTML built from visx primitives; no canvas-only
values. Every chart must provide:

- a visible title, a one-line takeaway, and a `How to read` disclosure;
- hover and keyboard-focus tooltips with the exact value and a named share;
- a `<details>` data table generated from the same series;
- an explicit empty/unknown state, never a fabricated zero;
- a date basis in the tooltip or caption (UTC day/month);
- 44px interactive targets where the element is a control.

### Volume

UTC buckets at three granularities, each with its own honest window: month
(12/24), week (26/52, Monday-anchored) and day (30/90). The loader ships a
400-day daily series so the week view is never silently truncated to the 90 days
the day view needs; buckets are aggregated from that one series, so granularity
changes the view and never the corpus. Y-axis is count, the x-axis is the bucket
start, and tick labels thin out to ~8 so day labels never collide.

Every bucket carries a full-height transparent hit target in front of its visible
bar: an empty day draws a 1px bar, and a 1px target would be impossible to hover
or focus. The visible bar is `pointer-events: none` and `aria-hidden`, so the
accessible element is always a 44px-wide column rather than an arbitrary bar
height.

Selecting a bucket opens a strip with the total, its corpus share and an Explore
link; the KEV-additions clause appears only for months, because KEV additions are
not bucketed weekly or daily. Peak is directly labeled, the y-axis is count, and
Arrow/Enter/Escape work on focused buckets. The plot grows into the panel height
when a taller sibling stretches the grid row, with the resize observer pinned to
a zero flex basis and integer heights so it can never feed back into itself.

### EPSS distribution

Nine log-spaced probability buckets (`<0.1%` … `50–100%`), log count height.
Labels are abbreviated; the tooltip and data table carry the full range. This
chart shows the base rate; it is not a risk score.

### Severity composition

Seven bands from the primary CNA CVSS policy. A donut shows the true proportions
(no same-length tracks); hovering a segment updates the centre, and the counted
legend rows are the Explore links. A data table is provided.

### Cumulative growth

Running total inside the displayed 24-month window, not the full corpus and not a
forecast. Hover/focus points show the month’s additions and the cumulative total;
a data table is provided.

### Joint matrix

Rows = severity bands (critical → unscored), columns = the same nine EPSS log
bins. Cell hue is the severity band, alpha is `0.12 + 0.8·√(count/max)`, a ring
marks cells containing KEV entries. Hover/focus updates a readout; click selects;
arrow keys move the roving selection. The inspector shows count, corpus share,
EPSS-scored share, KEV count, and KEV rate, plus explicit links. Counts come from
aggregate cache v3 and are exact for the accepted snapshot. The matrix scrolls
horizontally on narrow screens with a visible hint.

### Sankey (time-to-exploitation)

Two columns, deterministic layout: publication cohort → delay bucket. Node
heights and band thickness are record counts; labels sit **outside** the flow
area so no band ever runs under text, in symmetric gutters (no dead margin on
either side). Hover or keyboard focus on a node isolates its bands, and every
band carries the exact count and its share of the eligible denominator.

Nodes and bands are both controls, not decoration: click, Enter or Space pins the
selection (nodes get an accent outline, bands a stronger fill plus an accent
stroke) and Escape, or a second click, clears it. The pin outlives the pointer
and the dialog: closing the details dialog leaves the highlight and its
distribution on the chart, because the reader picked it deliberately.

While a node is hovered, focused or pinned, a readout under the chart lists every
flow through that node as **label · count · share of the node**, so the
distribution is legible without opening anything. Clicking a node opens the same
details dialog as a band, headed by the node, listing its flows with counts and
shares, and offering the union of their record sample (filter, paging, links). Pinning opens the same flow
drill-down dialog the relation graph uses: from→to labels, the exact count with a
"first N by CVE id" caveat when the sample is capped, an ID filter, a paged list
of links into Explore, and an official cve.org chip. Escape closes it from
anywhere in the dialog, including the search field (a `type="search"` input eats
the first Escape to clear its own text, so the close is handled explicitly).

The caption states the excluded count, and the identical series is available as
a data table.

### Fastest confirmations

The Sankey answers "how long does confirmation take" and carries the two delay
statistics (median days, confirmed within 30 days with its denominator); the
adjacent card answers "which records were confirmed fastest". Splitting them this
way keeps each statement next to the thing it describes, and balances the row:
both cards end up the same height instead of one stretching around a dead band.

- The Sankey never shows a median without its denominator, and the excluded count
  (no retained publication date) is stated in the chart note.
- Each fastest row is a linked CVE id, a delay badge in whole days, then the
  publication and KEV-listing instants in the reader's timezone. Dates wrap under
  the id rather than forcing the id to truncate.
- The footnote defines the metric (KEV listing date − publication date) and says
  plainly that a zero-or-negative delay is a pre-publication listing, not a fast
  confirmation. No record is ever labelled fast on a missing date.

### Exploit-tagged coverage

The overview closes with what share of the corpus carries a publisher-tagged
exploit reference, because "does this have a PoC?" is the question readers ask
first and the honest answer is a classification, not a verdict:

- One proportional bar plus plain counts: tagged records, how many of those are
  also KEV-listed, how many carry an EPSS forecast, and the KEV catalog size.
  Every overlap names its own denominator.
- The wording is fixed: "Records whose CVE references carry the publisher's
  exploit tag. A classification, not a verified working exploit." Nothing here
  enters ranking, and no badge claims exploitability.
- Both container shapes are walked: `containers.cna` is one object and
  `containers.adp` is an array. Most exploit tags arrive through ADP (CISA
  Vulnrichment), so reading only the CNA object makes the badge appear without
  the link it promises.
- The panel links to `/explore?exploit=tagged`, and Explore shows an
  `exploit ref` badge on each matching row with the same caveat in its tooltip.
- The flag is computed at import from the document already in memory
  (`hasExploitTagInDocument`) and backfilled once for older rows, so the counts
  cost one indexed read rather than parsing 4 GB of JSON per request.

### Watch

A watched row shows the same three signals plus the exploit reference, and the
`exploit ref` badge **is** the link (`target="_blank"`, `rel="noreferrer
noopener"`). A compact row cannot carry a full reference list, so the badge
itself points at the evidence instead of being a claim without one.

### Relation graph

A layered ego drawing, never a node-link hairball: **center CVE → shared
attribute → the records carrying it**, three fixed columns, deterministic
layout (same data always draws the same picture, so positions are stable for
keyboard users). Rules:

- The middle column is always labelled with the attribute value and its
  record count; a count without its denominator is a defect.
- Line colour encodes the link kind (shared CWE / vendor / reference host) and a
  legend names all three; the drawing never relies on colour alone.
- Only the first few leaves per attribute are drawn; the remainder collapses
  into a `+N more · view all` control whose pill is sized from its own label so
  text can never overflow its box.
- No implicit center: the landing view ranks the most-connected records and the
  center input stays empty until the reader picks one.
- A "How to read this graph" disclosure names what a dot is, what a line means,
  what a line does **not** mean, how the counts work, and why advisory
  aggregator hosts are excluded.

### Drill-down dialog

Attribute groups can hold 50+ records, so the full list is a result set, not a
scroll: filter by ID/title/description, sort (EPSS, published, signal count,
ID), page size 10/25/50, and Previous/Next with "Page N of M". The count line
names both the filtered total and the group total so a filter never reads as a
shrunken cohort. The dialog is a native `<dialog>` (focus trap, `Escape`,
backdrop) and every row carries the CVE id, severity and EPSS badges, title,
description excerpt, publication date and remediation due.

### Priority rows

A record row is a **list item first**: one row opens by default, each record is
separated by a rule, and the collapsed header carries the facts needed to
decide whether to open it (id, title, excerpt, KEV/EPSS/CVSS badges, publication
date, and the KEV catalog date when listed). Expanding shows the signal panels,
whose dates never repeat the header's publication date. The SSVC view adds an
explainer above the list (what the three decision points mean, how the order is
formed, the coverage caveat) and a recency window control; the right-hand rail
keeps a short ordering summary rather than repeating the explainer.

### KEV signal block

The KEV block renders in the expanded signal panel of a Priority row (and in any
future inspector that shows KEV). It is never colour-only: every state carries a
word. Contract:

- The membership state is exactly `Listed` or `Not listed`; the remaining rows
  are labeled and source-scoped: _Date added (catalog)_, _Due date (catalog,
  federal context)_, _Required action_ (catalog-supplied and wrapped),
  _Ransomware campaign use_, _Catalog name_, and _CWEs_ as monospace ID chips
  (names arrive with the E3 taxonomy; the ID is always the label).
- _Ransomware campaign use_ renders one of three explicit catalog states —
  `Known (catalog)`, `Unknown (catalog)`, `Not stated`. The UI branches on the
  tri-state `ransomwareUse`, never on the legacy boolean alias. `Unknown` is the
  catalog's own value for a field it published; `Not stated` means the field was
  absent. `unknown` and `unstated` never collapse, and no state is ever negated:
  **never infer "no ransomware"** (nor "not ransomware", nor "no known
  ransomware") from an unknown, unstated, or missing value.
- The block's HelpTip states the scope plainly: KEV is catalog membership
  evidence — not first-exploitation time, not a universal SLA — and repeats that
  `Unknown` is the catalog's value while `Not stated` is absence.
- Every value states its scope: the catalog-entry date is not first-exploit
  time, and the due date is a federal remediation deadline for the named
  directive, not a universal SLA. `requiredAction` is labeled as
  catalog-supplied text, never as our remediation guidance.
- Absent fields render the words `Not provided`, never a misleading blank. A
  long `requiredAction` wraps/breaks instead of silently truncating.
- A11y/layout: the HelpTip trigger is keyboard reachable (focus opens it, not
  hover only) and keeps its 44px target; labels wrap, so the block holds at
  360px and 200% zoom in both themes.
- API counterpart: the `kev` block on `CveItem` (`listed`, `dateAdded`,
  `dueDate`, `requiredAction`, `vulnerabilityName`, `ransomwareUse`, the legacy
  `ransomwareKnown` alias, and `cwes`).

### Unscored severity split (overview)

The "Unscored severity" stat keeps its own value and note, and gains one
subnote below them: `X with ADP secondary (context) · Y with no published
metric (of N unscored)`. Contract:

- The denominator is the **unscored cohort**, never the whole corpus, and the
  two counts always add up to `N`. The existing "share of the corpus · not low"
  note above it is unchanged.
- The subnote is a count of what can be read, not a severity statement: no band
  colour, no chip, no filter link, and it never reorders anything.
- A `HelpTip` beside it says the same in words: an ADP metric is context only,
  never used for ranking, ordering, filtering, or eligibility; "no published
  metric" is a data gap, not low severity.
- API counterpart: `/api/v1/overview` carries both counters as additive
  `coverage` fields (`secondaryOnly`, `noMetric`). Existing fields keep their
  names and meaning.

### Secondary CVSS block

The block renders on exactly one surface: the **expanded Priority row**. There is
no record-detail route and no Explore inspector in this product, so Explore
result rows, Watch rows, and the Graph "+N more" dialog deliberately stay static
and never expand into it; the API detail (`GET /api/v1/cves/{cveId}`) carries the
same data as `cvssSecondary`. Contract:

- **Secondary never looks like a band.** It is a list of rows under a
  "Secondary (context only)" label, never a second severity badge, chip, or
  band. The primary line keeps the only severity colour; secondary rows stay
  neutral text (published score, version, origin/provider, and the vector in
  mono) so a v4.0 ADP score cannot read as this record's severity. No
  `badge-*`, band, or severity class may appear inside it.
- It lives in the **expanded severity block of a Priority row only** — never
  in the compact signal line where the KEV/EPSS/CVSS chips sit — and it is
  never filterable, sortable, or an eligibility input. Adding an
  expanded/inspector surface that shows severity means rendering this same
  block there, not a second implementation; a static list row must not grow an
  expansion just to host it.
- Every row is labeled `secondary (context only)`, the group carries a
  `HelpTip`, and a closing line says the metrics are never used for ranking,
  ordering, filtering, or eligibility.
- Order is fixed by the data layer, not by the component: ADP before CNA, then
  version preference 4.0 > 3.1 > 3.0 > 2.0, then exact base score descending,
  then stored source order. At most four rows render.
- Scores are printed as the published decimal text, unfused with EPSS and never
  re-derived; malformed values are absent rather than shown as zero or unknown.
  A missing provider reads "provider not specified", never blank.
- An empty or absent secondary set is stated in words, not hidden and not
  rendered as a disabled row: "No secondary (ADP or non-selected CNA) metric
  published." when a primary exists, and "No CNA or ADP metric published." when
  the record has no metric at all. Nothing here may reorder a list, change a
  filter result, or alter a severity band.

### CWE taxonomy labels

CWE ids already appear in KEV rows, record attributes, and graph groups. The
local taxonomy catalog supplies the published label for those ids, and the
read path reports exactly one of three states per id — it never guesses.

- **`known`.** The id exists in the accepted catalog. Render the mono id plus
  the published name (e.g. `CWE-94 · Improper Control of Generation of Code`),
  linking to the canonical MITRE page. Optional fields (`abstraction`,
  `summary`, `mitigation`) appear only when the taxonomy published them; a
  missing mitigation is not an empty mitigation block, and the label never
  implies remediation guidance is ours.
- **`unmapped`.** The id is well-formed but absent from the accepted catalog,
  or the input is not a valid CWE id shape. The raw id is **always shown** with
  a short explanation that it is not present in the loaded taxonomy — never
  hidden, never silently dropped from a list, never rendered as a blank chip,
  and never given an invented name. A valid-shaped id keeps its canonical
  link; an unparseable input is plain text with no fake URL.
- **`taxonomy-unavailable`.** No accepted catalog is available (never loaded,
  failed refresh, or unreadable). The id still renders as the raw mono id with
  a “taxonomy unavailable” note, and no name is claimed. Empty/absent catalog
  states are stated in words, not rendered as a disabled row.

Catalog status is context, not a verdict: it never changes ranking, filtering,
severity bands, or whether a record is listed. The reader is local-only, so
these labels never depend on an upstream request completing.

## 8. Interaction

- Global `⌘K` / `Ctrl+K` focuses search. `Escape` closes menus/tooltips.
- Explore filters auto-submit checkbox/radio/select changes after 150ms; the
  text query and Apply button remain explicit. URL is the state.
- Every chart tooltip has a focus path. Hover-only values are a defect.
- Selection is reversible: `Escape` or a clear control restores the default.
- No hover-only required information; no motion that conceals values.
- Graph nodes are links: `Tab` reaches each one, `Enter` re-centers, `+N more`
  is a real button that opens the dialog, and `Escape` closes it.
- Theme is a topbar sun/moon toggle (44px) that flips `data-theme` on `<html>`
  and persists via cookie + localStorage, so the first paint is already themed.

## 9. Accessibility

Target WCAG 2.2 AA. Maintained gates:

- one h1, no heading-level skips;
- every control named, every table header scoped;
- 44×44px targets for standalone controls;
- visible focus ring on every keyboard stop;
- no horizontal page overflow at 360px or 200% zoom;
- reduced motion removes transitions/animations (`0s`);
- live regions bounded (the product currently uses none in charts);
- color never the only signal;
- data tables in disclosures for every chart.

## 10. Motion

CSS only. 120–180ms ease-out for state feedback. No chart animation that changes
the encoded value, no count-up numbers, no scroll reveals that delay data.
`prefers-reduced-motion: reduce` sets durations to `0s`.

## 11. Implementation notes

- Fonts: `public/fonts/instrument-sans-latin.woff2` and
  `jetbrains-mono-latin.woff2`; licenses alongside. No CDN.
- Charts: `@visx/scale`, `axis`, `group`, `grid`, `responsive` (primitives only; no `xychart`/spring peer).
- Design CSS lives in `app/ui.css`; `app/globals.css` remains for the showcase
  and legacy primitives, with token aliases in `ui.css`.
- The aggregate cache version is 3 (`epssLogHistogram`, `severityEpssMatrix`).
  Refresh once after upgrading a live volume:
  `docker compose exec app env REFRESH_AGGREGATES_ONCE=true node worker.mjs`.
