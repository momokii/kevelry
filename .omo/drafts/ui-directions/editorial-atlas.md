# Editorial Atlas — UI direction + overview prototype

Status: draft direction, not app code. Prototype: `.omo/drafts/ui-directions/editorial-atlas.html`
(self-contained, inline CSS/SVG/JS, no network). Evidence: `.omo/evidence/ui-directions/editorial-atlas-1280.png`, `-360.png`.

## 1. Concept

**Editorial Atlas** treats the CVE corpus as a beat to cover, not a dashboard to monitor.
The page reads top-to-bottom like a data-journalism feature (The Pudding / Reuters Graphics /
FT Visual Journalism / Our World in Data grammar, set in a modern 2026 grotesk — no newspaper pastiche,
no Georgia serif anywhere):

- One manifesto-scale opening claim, answered in seconds: volume has doubled in a year, almost none of it is exploited yet, half of it is unscored.
- One dominant 24-month volume chart instead of six equal cards.
- Supporting blocks in narrative order — severity → exploit forecast → KEV rhythm → freshness → priority queue — each opening with a **takeaway sentence**, not a title alone.
- Charts are large, direct-labeled (no legend decoding), annotated inline (peak, dip, climb), with hover/focus tooltips and a statically open tooltip proving the pattern.
- Definitions ride alongside claims as `<details>` affordances and "Why this matters" boxes, so explanation is one tap away and never a separate page hunt.

## 2. Shell

- Slim sticky top bar: wordmark (orb mark + "CVE Atlas" + section label), section links (Overview / Explore / Priority / Radar / Methodology), pill search, monospace timezone select. 56px, ink bottom border, blurred canvas.
- No sidebar, ever. Second sticky row: chapter rail (`01 Volume → … → 06 Priority queue`) with scroll-spy underline — the "mini-nav".
- Main column max 1120px, canvas background, story blocks as white cards with 14px radius; hero numerals sit directly on canvas (no card) for manifesto scale.
- Footer: frozen-values disclaimer + page map.

## 3. Type scale

| Role | Spec |
|---|---|
| UI + numerals | Modern variable grotesk class (Inter Tight / Archivo); prototype uses system stack with identical metrics intent |
| Hero numerals | 800–850 weight, −3.5% tracking, ~0.98 line-height; **72–120px** (395,286 at clamp 64–120px) |
| Section titles | 18–20px, weight 750, −1.5% tracking |
| Body / takeaway | 15.5–20px; takeaway carries 3px accent left border |
| Labels / axes | 11–13px; axes monospace 10.5–11px |
| Numerals | Tabular everywhere (`tnum` + `font-variant-numeric: tabular-nums`) |
| Rejected | Georgia-serif fallback stack — retired by policy, called out in the colophon block |

## 4. Palette use

Kept tokens: canvas `rgb(247,246,243)`, surface white, ink `rgb(26,26,26)`,
secondary `rgb(89,89,89)`, rule `rgb(214,211,205)`, accent `rgb(0,106,159)` (+ ink `#004E75`, tints `#E3EFF6`/`#F0F6FA`).
Restrained extensions: critical `#A4262C`, high `#B4550A`, medium `#8A6D00`, low/olive `#5B6E1E`,
KEV green `#0B6E4F`, warn amber tint, stale red tint. No neon; severity colors only appear inside their own blocks.
Rule of thumb: ink carries structure (borders, peak bars, annotations), accent carries interaction and claims, tints carry state.

## 5. Chart set + interaction spec

| # | Chart | Encoding | Interactions |
|---|---|---|---|
| 01 | 24-month volume bars (4054…13606, max 14,934 Sep 26) | Linear 0–16k, peak bar ink, sub-5k bars muted, gridlines at 5k steps, sparse month labels | Hover/focus tooltip per bar (static open tooltip pinned on Sep peak in mock); brush mini-map below with 4 click/keyboard-cycled windows (F7: click track cycles, arrows move); brush selection would filter Explore in production |
| 02 | Severity horizontal bars (179,288 scored) + unscored callout (215,998) | Length ∝ count (max medium 83,820), per-band deep color chip + fill, mono counts | Static direct labels; unscored rendered as oversized-numeral callout, never a bar that normalizes it |
| 03 | EPSS 10-bucket histogram (377,908 … 806) | Linear 0–400k; first bar is the story; 50%+ buckets carry direct count labels + tail rule | Hover darkens bar; tail annotation ("3,420 ≥ 50%"); pills summarize <10% / 10–50% / 50%+ |
| 04 | KEV additions 12-mo (11…43, peak Sep 26) | Compact bars, peak ink, rest KEV green, value labels on every bar | Annotation leader to Sep spike; takeaway-first layout |
| 05 | Freshness ledger | 3 rows: V5 stale 11h rev 509084ac / KEV stale 12h / EPSS current 2026-10-24 model v2026.06.15 | Status pills (stale red tint / current green tint); mono revision + score-date metadata |
| 06 | Priority queue (110447/48/49) | Numbered editorial list (01–03), tag chips (KEV / CVSS 9.2 v4.0 / EPSS 2.285%), one "Why Nth" sentence each | CVE links to record; "full ranked lists live under Priority" handoff |

Global: every chart has title + subtitle stating window and basis; tooltip pattern is dark-ink card with mono context line; keyboard focus reaches every bar (`tabindex`, `aria-label`); `prefers-reduced-motion` disables reveal/scroll smoothing.

## 6. Explanation model

Three layers, co-located, never linked away: (a) **takeaway sentence** opens each block (the claim);
(b) **ⓘ definition `<details>`** states basis/provenance/edge cases (UTC buckets, CNA-only severity, EPSS-as-forecast, KEV absence ≠ safety);
(c) **"Why this matters"** box translates the claim into a triage consequence. Freshness is a story block (05), not a footer badge — numbers are snapshots with revisions.

## 7. Page-by-page blueprint (applying the direction beyond Overview)

- **Explore:** lede becomes the active filter sentence ("8,214 CVEs · high+critical · 2026 · unscored excluded"); cohort panel reuses severity/EPSS blocks at small scale; results as annotated list with excerpt + evidence chips, not a grid of cards.
- **Priority:** four ranked lists open with one-line ordering-rule statements; KEV list reuses the queue pattern (numbered, why-ranked sentence); forecast lists show EPSS probability bars with score dates.
- **Radar:** change feed as dated marginalia — before/after pairs with reason lines, grouped by day, newest first; replay entry points inline ("see this day as published").
- **Replay:** checkpoint viewer styled as an archived edition (dateline, policy version, frozen numbers), with diff-vs-current strip.
- **Methodology:** pipeline / signal-relationship / ordering diagrams redrawn in Atlas style (ink rules, accent highlights, annotated steps); coverage gaps as a dedicated "what we don't know" block.
- **API docs:** same narrative shell; endpoint reference set like a data appendix — one-line plain-language purpose per route above the schema, frozen example values matching the Overview numbers.

## 8. Mobile behavior (360px)

Designed vertical narrative, not squeezed desktop: top nav links collapse (search + timezone survive); hero numerals become 2-col with the 395,286 figure full-bleed on its own row; all grids (KEV, colophon) stack; severity rows drop to label+bar with counts on their own line; queue numbers sit above entries; chapter rail scrolls horizontally; brush window remains tappable (click cycles windows); tooltips pin within viewport width. Verified at 360×900.

## 9. What it rejects

- Left sidebar and card soup (six equal stat cards, icon tiles, sparklines without claims).
- Legend decoding (color keys the reader must memorize) — every mark is directly labeled.
- Title-only sections, unexplained numbers, severity-without-provenance.
- Tables as evidence (the queue is three reasons, not 500 rows).
- Georgia-serif fallback, neon severity ramps, dashboard chrome (gauges, donut percentages, "at a glance" widgets).
- Timezone-shifting buckets; display timezone re-renders instants only, UTC month boundaries never move.

## 10. Prototype notes

Single file, inline everything, JS renders SVG from the exact frozen values (no network, no framework).
Known mock simplifications: brush cycles 4 preset windows instead of free-drag; search/timezone are visual only;
volume chart gridline ceiling fixed at 16k; screenshots must be re-taken if values change.
