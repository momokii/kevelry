# UI Revamp Brief — CVE Change Radar

Date: 2026-10-26
Status: direction research

## Owner feedback (verbatim intent)

- The data, sources, and scoring are trusted. The UI is not.
- The current interface feels old and not interactive enough.
- Full revamp, not another polish pass.
- Research the newest/trending design approaches; changing the chart library is allowed.
- The interactive chart/diagram experience with proper explanation is the highest priority.
- Keep the existing palette (warm canvas, ink, restrained blue).
- Dislikes the overall composition and how the data is presented, not the palette.
- No rush; no mistakes.

## What must not change

- Data semantics: CVSS, KEV, and EPSS stay separate; no composite risk score.
- Every number remains traceable to an accepted snapshot, with date basis, coverage, and unknown states.
- One Docker image, one container, no runtime CDN, no external service.
- Server-rendered content where possible; client islands only for interaction.
- Public read-only posture and the existing API contract.
- Security, validation, and bounded-query behavior.
- Accessibility: WCAG 2.2 AA, keyboard equivalents, 44px targets, reduced motion.
- Mobile at 360px, tablet, and desktop.

## What must change

- The document/ledger aesthetic: serif-led, boxed sections, text-heavy explanations, tabular fallbacks that dominate, static charts.
- Navigation and page composition: make the product feel like one coherent instrument, not seven separate documents.
- Explanations: move from paragraphs below charts to contextual, progressive disclosure attached to the data.
- Interactivity: direct manipulation, linked views, brush/zoom, cross-highlighting, click-through, keyboard parity.
- Hierarchy: one clear focal question per page, with supporting evidence in layers.

## Success criteria

1. A first-time visitor can answer, without scrolling through prose:
   - How much CVE volume exists, and how is it trending?
   - What is currently most urgent, and why?
   - How fresh is each source, and what does staleness mean?
   - How do CVSS, KEV, and EPSS differ?
2. Charts are the primary interface, not decoration:
   - Hover/focus reveals exact values and definitions.
   - Selection filters or drills into the matching cohort.
   - Linked charts respond to the same selection.
   - Annotations explain notable points without fabricating causality.
3. The interface feels contemporary in 2026: strong typographic hierarchy, fluid composition, purposeful color, restrained motion, no card soup, no raw ISO strings.
4. Performance on the 395k-row volume: no page interaction should block on a full-corpus scan without feedback; warm navigation under 1s.
5. All existing tests updated and green; new visual/interaction coverage at 360/768/1280 and 200% zoom.

## Design constraints

- Palette anchors: canvas `rgb(247,246,243)`, surface white, ink `rgb(26,26,26)`, secondary `rgb(89,89,89)`, rule `rgb(214,211,205)`, accent `rgb(0,106,159)`. Extend with tints/accents only if accessible and documented.
- No color-only encoding for severity or state.
- No chart library that hides values from assistive technology; prefer SVG with a data-table equivalent.
- Fonts must be self-hosted and OFL/compatible; no runtime font CDN.
- One primary chart dependency, at most one diagram dependency, at most one motion dependency.

## Candidate directions to evaluate

1. Editorial Atlas — narrative data journalism, large display type, annotations, scroll-linked story.
2. Operations Console — persistent rail, command palette, split panes, linked selection, keyboard-first.
3. Scientific Canvas — bento/small-multiples, zoomable scatter, modular panels, notebook-style explanations.
4. Signal Brutalist — monochrome grid, oversized mono numerals, raw data aesthetics, minimal chrome.

Each direction must specify: shell/navigation, type scale, palette use, chart set, interaction model, page-by-page composition, mobile behavior, and what it deliberately rejects.

## Decision rubric

- Clarity for a non-expert vs density for an analyst.
- Interaction depth vs implementation and maintenance cost.
- Distinctiveness vs familiarity.
- Fit with warm neutral palette.
- Accessibility and performance.
- Ability to explain uncertainty and provenance without clutter.
