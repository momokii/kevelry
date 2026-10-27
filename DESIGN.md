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

| Token | Value | Role |
| --- | --- | --- |
| `--ui-paper` | `rgb(247,246,243)` | page canvas |
| `--ui-paper-deep` | `rgb(240,238,232)` | rail / recessed chrome |
| `--ui-surface` | `rgb(255,255,255)` | panels, tables |
| `--ui-ink` | `rgb(26,26,26)` | primary text, bars, primary button |
| `--ui-ink-2` | `rgb(89,89,89)` | secondary prose |
| `--ui-ink-3` | `rgb(132,129,123)` | labels, axes, metadata |
| `--ui-rule` | `rgb(214,211,205)` | section rules, borders |
| `--ui-rule-soft` | `rgb(232,229,223)` | table rows, gridlines |
| `--ui-accent` | `rgb(0,106,159)` | links, selection, focus |
| `--ui-accent-soft` | `rgb(230,243,249)` | selected surfaces |
| `--ui-critical` | `rgb(170,40,52)` | critical CVSS band |
| `--ui-high` | `rgb(188,88,20)` | high band |
| `--ui-medium` | `rgb(142,104,0)` | medium band |
| `--ui-low` | `rgb(52,102,80)` | low band |
| `--ui-legacy` | `rgb(104,88,128)` | CVSS v2 only |
| `--ui-unknown` | `rgb(130,127,121)` | unscored / no data |

Rules:

- Never encode severity or source state with color alone. Pair with a word, a
  symbol, a shape, or a ring.
- Semantic hues are for marks and badges, not page chrome.
- Text uses ink tokens; accent text must sit on paper or `--ui-accent-soft`.
- New colors require a token and a contrast check.

## 3. Typography

Self-hosted variable fonts in `public/fonts/` (OFL, copied with licenses):

- **Instrument Sans** (`400–700`) for UI, prose, headings, and numerals.
- **JetBrains Mono** (`100–800`) for CVE IDs, eyebrows, axes, tabular labels.

Scale:

| Role | Size / treatment |
| --- | --- |
| hero number | `clamp(52px, 8vw, 104px)`, 600, `-0.055em`, tabular |
| h1 | `clamp(30px, 3.6vw, 44px)`, 600, `-0.035em` |
| h2 / panel title | 19–23px / 15px, 600 |
| body | 15px / 1.5, max 68ch |
| data / table | 13px, tabular numerals |
| eyebrow / label | 10–11px mono, uppercase, `0.08em` |

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
4. Volume panel (24/12 months, focus-month select, hover/focus tooltip, click
   selection with KEV additions and an Explore link) + cumulative growth line.
5. Severity donut with an interactive legend and log-EPSS distribution.
6. Joint severity×EPSS matrix with KEV rings and a cohort inspector.
7. KEV rhythm, freshness, and honesty notes.
8. Priority evidence in four compact lists.

### Explore

Filter disclosure (open by default, collapsible) inside a rail that scrolls
independently on desktop. UTC date fields pair with 7d/30d/90d/1y/All presets.
Cohort composition shows severity meters, monthly counts, and signal coverage;
compact result rows carry severity/KEV/EPSS chips and official-record actions.

### Priority

Compact expandable table. The first five rows open their signal blocks; the rest
stay one line plus badges. A sticky rail holds the exact ordering rules and
snapshot evidence. No composite score, ever.

### Radar / Replay

Radar: snapshot pair, change-kind filter, feed on the left, sticky evidence
inspector on the right. Replay: retained-checkpoint selector, historical banner,
then the five replayed lists with the same row language.

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

UTC month bars, 24 or 12 months, y-axis count. Selecting a bar opens a strip with
the month total and an Explore link. Peak is directly labeled. Arrow/Enter/Escape
work on focused bars.

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

## 8. Interaction

- Global `⌘K` / `Ctrl+K` focuses search. `Escape` closes menus/tooltips.
- Explore filters auto-submit checkbox/radio/select changes after 150ms; the
  text query and Apply button remain explicit. URL is the state.
- Every chart tooltip has a focus path. Hover-only values are a defect.
- Selection is reversible: `Escape` or a clear control restores the default.
- No hover-only required information; no motion that conceals values.

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
