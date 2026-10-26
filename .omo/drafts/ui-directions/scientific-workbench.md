# Scientific Workbench — UI direction draft

Static prototype: `.omo/drafts/ui-directions/scientific-workbench.html` (single self-contained file, inline CSS/SVG/JS, no network, no framework).
Evidence: `.omo/evidence/ui-directions/scientific-workbench-1280.png`, `scientific-workbench-360.png`.

## 1. Concept

The overview page is a **data instrument, not a dashboard**. One research question owns the page —
*where does real exploitation risk concentrate in a 395,286-record corpus?* — and every panel is a
lens on that question rather than an equal-weight card. The visual language borrows from Observable
notebooks, Figma/Hex side panels, Our World in Data explorers, and lab instruments: warm paper canvas,
hairline rules, figure numbers (`Fig. 01…05`), mono annotations, and explanations that appear as
**annotations and an inspector**, never prose blocks.

Core loop: **see the joint distribution → brush/select a cohort → read the inspector → follow the
linked timeline/multiples → open the cohort in Explore.** Selection is the only navigation that matters
on this page.

## 2. Shell

- **Compact top bar (sticky):** wordmark + dataset-revision chip (`snapshot 2026-10-26 · epss v2026.06.15`),
  section nav (Overview active), freshness chips (CVE stale 11h / KEV stale 12h / EPSS current), CVE search.
  No heavy sidebar anywhere.
- **Active-cohort strip** directly beneath: the linked-selection state made visible as a pill
  (`CVSS 9–10 × EPSS 1–5% · 363 CVEs ×`) plus severity-band pills; one-line hint that the page follows it.
- **Thin left dataset rail** (~172px): View (Density/Hexagon/Contour), Cohort preset select,
  Time range segmented control (6M/12M/24M), Brush mode (Cell select/Drag cohort), Reset bench.
  Tools, not navigation.
- **Modular asymmetric canvas:** 12-column grid; hero density plot spans 8 cols × 2 rows, inspector
  spans 4 × 2, wide timeline spans 8, three small multiples span 4 each, corpus ledger spans 12.
  Deliberately unequal — the centerpiece is ~4× the area of any multiple.

## 3. Type scale

- Variable grotesk for prose/UI (system stack: Avenir Next / Segoe UI / system-ui), mono for all numerals
  and annotations (ui-monospace stack), tabular figures everywhere (`font-feature-settings: "tnum"`).
- 10px mono kickers with 0.12em tracking (`FIG. 01 · JOINT DISTRIBUTION`), 11–13px labels and captions,
  17px small-multiple titles, 20–21px section titles, one 30px inspector numeral (cohort count).
  Large but not magazine-scale; the 30px count is the only hero numeral on the page.

## 4. Palette use

- Canvas `rgb(247,246,243)`, surface `#fff`, ink `rgb(26,26,26)`, secondary `rgb(89,89,89)`,
  rule `rgb(214,211,205)`, accent `rgb(0,106,159)` with a 9%-alpha wash for selected states.
- Density uses a single-hue log sequence (accent at 6%→96% alpha): one variable, one hue, no rainbow.
- Severity tints are restrained earth tones used **only** in the severity multiple and legend:
  critical `#a93226`, high `#b45309`, medium `#7c6a00`, low `#4d7c0f`, none/legacy gray, unscored warm gray.
- KEV is the single warm-red signal (`rgb(169,50,38)`): rings on density tiles, September bar, KEV tag.
  Red means exactly one thing — confirmed exploitation.

## 5. Chart set + interaction spec

| Fig | Chart | Encoding | Interaction |
|-----|-------|----------|-------------|
| 01 (hero, 2×2) | CVSS×EPSS 10×10 density tiles | log-alpha fill; red ring + dot = KEV present; dashed quadrant guides at CVSS 5 / EPSS ~10%; drag-cohort brush rect with handles | Hover tooltip (cohort, n, KEV, share); click tile → selection; "Reading this plot" popover; View switch re-renders Density/Hexagon/Contour |
| 02 (wide) | 24-month publications, bars | accent bars, last quarter full-strength; gridlines at 5k/10k/15k | Follows selection (dims, caption rewrites to "shape holds / surge persists"); range seg rescales |
| 03 | Severity bands, horizontal bars | earth-tone bars, exact counts | Click band → severity pill in cohort strip |
| 04 | EPSS histogram, 10 bins | sqrt scale (floor bin labeled 377,908) | Hover exacts; follows cohort preset |
| 05 | KEV additions, 12 bars | red, Sep spike (43) full-strength | Hover exacts |
| Ledger | Corpus totals table | mono numerals, exact brief values | None — provenance record |

Every chart carries a one-line **takeaway caption** (the chart's conclusion, not its description).
Density binning is labeled illustrative with exact totals: row masses equal the EPSS histogram bins
(`377,945; 7,218; 3,057; 1,652; 1,081; 913; 961; 940; 713; 806` — the +37 no-EPSS records folded into the
floor bin so tiles sum to 395,286); right-skewed toward mid/high CVSS; KEV overlay concentrated on the
right-edge ridge. Unscored CVEs (215,998) are binned at CVSS 0–1 **for display** and the axis says so.

## 6. Linked-state model

Single selection object: `{ cvssBin, epssBin } | { severity } | null`, mirrored in three places —
cohort pill strip, inspector panel, timeline/multiples emphasis. Rules:

- Selecting a density tile sets the cohort, rewrites the inspector (count, share, KEV in tile, KEV rate,
  median EPSS, max CVSS, three exemplar CVEs incl. CVE-2026-110447/48/49), dims the timeline, and rewrites
  its takeaway to confirm or deny whether the pattern survives the filter.
- Selecting a severity band adds a second pill; pills clear independently (×) or jointly (Reset bench).
- Cohort preset select (KEV only / EPSS ≥ 1% / CVSS ≥ 9 / Unscored) re-bins the hero and re-labels Fig. 01's n.
- "Open this cohort in Explore →" and "Copy cohort filter" serialize the selection to a URL query the
  Explore page can consume — the bench is a query builder, not a dead end.

## 7. Explanation model

No wall of text. Three mechanisms, all co-located with the visual they explain:

1. **Axis and in-plot annotations** — quadrant labels ("patch-first quadrant", "likely noise, whatever
   the score"), axis footnotes (unscored binning, log bins, illustrative-binning disclaimer).
2. **"Reading this plot" popover** — four numbered steps (axes → corner → rings → click), toggled from
   the hero subtitle; the only instructional prose on the page, hidden by default.
3. **Inspector as explainer** — "Why it matters" / "Action" rows translate the selected tile into a
   decision (KEV + forecast agree → patch-first cohort), with exemplar CVEs as evidence.

Freshness is ambient (top-bar chips + ledger row), never a modal: CVE stale 11h, KEV stale 12h,
EPSS current with score date 2026-10-24 and model v2026.06.15 inline.

## 8. Page-by-page blueprint (same language, other rooms)

- **Explore:** the bench's selection arrives as URL state; rail becomes filter panel (same pill strip);
  results table keeps mono numerals and KEV/EPSS tags; matching-cohort panel reuses Figs. 03–04 at small size.
- **Priority:** four inspector-style columns (Known-exploited / Highest forecast / New critical / Rising
  forecast); each entry is a mini-inspector (count-share-KEV block + why-it-matters row); CVE-2026-110447
  headlines KEV with EPSS 2.285% / CVSS 9.2 rendered as separate explained blocks.
- **Radar:** before/after evidence diffs styled as ledger rows (dotted kv rules from the inspector);
  change feed grouped by source-change vs rank-only move, each with the same takeaway-caption pattern.
- **Replay:** snapshot checkpoint selector in the rail position; canvas re-renders the overview at the
  pinned date + policy version with a "history begins" empty state; replay banner replaces the cohort strip.
- **Methodology:** the three explanation mechanisms scale up — annotated pipeline/joint-distribution/
  ordering diagrams with figure numbers, popovers for definitions, ledger table for coverage gaps
  (unscored policy, bounded checkpoints, UTC buckets).
- **API docs:** endpoint reference in the ledger voice — mono method paths, exact-shape examples from the
  same snapshot revision chip; "try it" console styled as the inspector (request → response + share stats).

## 9. Mobile behavior (360px)

Deliberate stack order: top bar (wraps to two rows) → cohort strip → dataset rail (horizontal wrap) →
hero density → inspector → timeline → multiples → ledger. Density keeps full 10×10 geometry but the axis
simplifies (alternate tick labels hidden under 900px); quadrant annotation shortens. The inspector becomes
a **bottom sheet**: fixed, rounded top, drag handle, 52vh max with scroll, canvas padded so content below
remains reachable. Freshness chips compress to horizontal scroll; search narrows to 130px. No hover
dependency — tap tile opens the sheet with the cohort already inside.

## 10. What it rejects

- Equal-card dashboards where every chart shouts at the same volume.
- Severity-first triage framing (54.6% unscored makes it dishonest); severity is one multiple, not the hero.
- invented scores or popularity signals; unknown EPSS renders as exclusion from the plot, never zero-fill.
- Prose methodology sections on the overview page; explanation lives in annotations, popovers, inspector.
- Dark-mode trading-floor aesthetics, rainbow heatmaps, 3D, donut charts, magazine-scale numerals.
- Any modification to app/, src/, tests/, package.json, or docs for this direction — drafts and evidence only.
