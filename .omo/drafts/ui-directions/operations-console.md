# Operations Console — UI Direction

Prototype: `.omo/drafts/ui-directions/operations-console.html` (single self-contained file, inline CSS/SVG/JS, no network, no framework).
Evidence: `.omo/evidence/ui-directions/operations-console-1280.png`, `operations-console-360.png`.

## 1. Concept

A serious analyst workspace, not a document and not a magazine. The operator opens the site the way they open Linear, Grafana, or GitHub Security: a persistent left rail for orientation, a command bar for action, and dense-but-calm panes where every number is one hover away from its cohort. Warm paper palette (`rgb(247,246,243)` canvas, white surfaces) keeps it approachable; the discipline — rules over shadows, tabular numerals, mono IDs, 13–14px data text — keeps it professional. Nothing on the page is decoration: the signal strip, the volume chart, the severity stack, and the priority table are four views of one linked selection.

## 2. Shell

- **Left rail (236px, desktop):** wordmark + console version; MONITOR group (Overview, Search `kdb:/`, Priority with `1,756` count, Radar, Replay); REFERENCE group (Method, API `v1`); source-health mini panel (CVE stale 11h amber, KEV stale 12h amber, EPSS current green — always visible, no scrolling to find it); bottom timezone (`UTC−04:00 EDT`) + Settings (`⌘,`).
- **Top command bar (52px, sticky):** breadcrumb context (`CVE Intel / Overview · all sources`), centered global search with `⌘K` hint, freshness chip (`EPSS current · CVE 11h · KEV 12h`), density segment (Cozy/Compact), avatar. Rules and blur separate it from content; no shadow.
- **Content column (max 1240px):** page head (title + snapshot meta + Export/Triage actions) → filter pills → signal strip → 12-col split (8 chart / 4 stack) → priority table → collapsible source health → legend + keyboard footer.

## 3. Type scale

- Page title 17px/700, −1% tracking. Panel titles 12px/700 uppercase, +5% tracking, secondary color.
- KPI values 23px/700 tight; KPI labels 10.5px uppercase; KPI subs 11.5px mono.
- Data text 13–14px; table headers 10.5px uppercase faint; IDs/CVE refs `ui-monospace` 12.5px bold accent; all numerals `font-variant-numeric: tabular-nums`.
- System stack only; mono only for IDs, counts, dates, shortcuts. No display face — this direction earns gravity from density and order, not typography.

## 4. Palette use

Canvas `rgb(247,246,243)`, surface white, ink `rgb(26,26,26)`, secondary `rgb(89,89,89)`, rule `rgb(214,211,205)`, accent `rgb(0,106,159)`. Accent is reserved for selection, links, and the pinned series; accent-wash (`8%`) is the single highlight surface for linked rows/bands. Semantic hues appear only on severity/state: critical `#B42318`, high `#C65D0E`, medium `#8A6D00`, low `#4D7C0F`, neutral `#6B7280`, KEV red, ok-green/stale-amber health dots. Borders are 1px rules; radius ≤8px (panels) / 6px (controls); shadows effectively zero (tooltip only).

## 5. Chart set + interaction spec

- **Signal strip (4 KPIs):** Published 395,286 / KEV-listed 1,756 / EPSS-scored 395,249 / Unscored+tombstones 215,998 with sub-lines carrying the rest of the corpus facts (tombstones 18,638, unknown dates 0, model v2026.06.15). Clickable — selects the matching cohort.
- **Volume chart (24 bars, exact brief values):** hover shows crosshair + dark tooltip (month, count, KEV delta, "linked"); click pins the month (accent bar + pin line + banner). Brush mini-map below shows the in-view window. Keyboard `←/→` moves the pinned month.
- **Severity stack:** 7 horizontal bars on a shared scale (unscored dominates honestly); hover cross-highlights. **EPSS histogram:** 10 buckets (first bucket towers, shown as-is); **KEV/month:** 12 trailing bars, latest red.
- **Priority table:** CVE-2026-110447 (KEV + RCE, EPSS 2.285%, CVSS 9.2 crit, primary Triage action), 110448, 110449; inline chips, cohort sub-lines, pagination footer.
- **Source health:** `<details>` row, 3 cells with exact freshness facts (CVE stale 11h, KEV stale 12h, EPSS score date 2026-10-24 model v2026.06.15).

## 6. Linked-state model

Single selection object: `{ month, severity[], kpi }`. Hovering or pinning a month, hovering a severity band, or clicking a KPI recomputes every pane: non-matching table rows dim, matching rows highlight, severity bands heat, pills reflect the filter, and the URL carries it (`?month=2026-09&sev=critical,high`). `esc` clears; pills are removable; unpin restores the neutral table. The prototype simulates all of this client-side with the brief's static data.

## 7. Page-by-page blueprint

- **Explore:** rail + command bar persist; left filter column replaces the chart pane (severity, EPSS floor, KEV-only, date basis UTC-labeled); cohort panel + histogram stay on the right; results reuse the priority-table row pattern with excerpts.
- **Priority:** four tabs (known-exploited / highest-forecast / new-critical / rising-forecast) as segmented control under the command bar; table gains EPSS probability bars and timezone-aware dates; KEV tab pins the red treatment.
- **Radar:** before/after split rows (record / KEV / forecast / membership changes) with reason strings; same pills + URL state; replay checkpoint selector in the command bar.
- **Replay:** checkpoint timeline scrubber (daily) + policy-version tag; banner states "what the site showed, bounded to retained checkpoints."
- **Methodology:** diagram-first (pipeline, signal-relationship, ordering) in calm bordered panels; coverage gaps and stale states inline, not footnoted.
- **API docs:** three-pane (endpoint rail / reference / live example) reusing the console shell; rendered from the OpenAPI spec so it cannot drift; `v1` badge in the rail.

## 8. Mobile behavior (360px)

Rail becomes a hamburger slide-over with scrim; KPI strip goes 2×2; chart keeps full width with sparser x-labels (every 4th) and a clamped in-bounds tooltip; table drops the CVSS column and tightens padding (full compact-row cards are the production step beyond this prototype); source-health cells stack; density control and avatar hide; search shortens to `Search…`. Verified in `operations-console-360.png`.

## 9. What it rejects

Card soup (no floating shadow cards, no metric tiles with icons); dark-mode cosplay; magazine devices (hero, editorial type, pull quotes); chartjunk (gradients, 3D, donut-for-everything); color as decoration (semantic hues only); hidden state (freshness and filters are always on screen); hover-only function (everything hoverable is also pinnable, keyboard-reachable, and URL-addressable).
