# DESIGN.md — Evidence Ledger Design System

Status: **Wave 1 deliverable for todo 2.** Implements the candidate direction in
`.omo/drafts/cve-change-radar-design.md` sections 2-6. No product screens, no data
logic, no invented tokens beyond the draft.

## 0. Research Log

- Routed references: minimalist editorial hierarchy plus wired-style data density
  (typographic role contrast, thin structural rules, deliberate density,
  source/date labels, no marketing detour). This is not a WIRED clone.
- Draft sections 2-6 read in full; every token below traces to the draft table or
  it is explicitly marked as a mechanical scale step, not a new color.
- No external screen galleries, generated concept images, or browser comparisons
  were used for this deliverable. The showcase in `app/showcase/` is the visual
  evidence surface.
- Font basis: Newsreader, Source Sans 3, IBM Plex Mono (OFL-1.1, checked
  2026-10-24 in the draft). No proprietary fonts. No runtime webfont fetch;
  families are referenced by name with local/system fallbacks until bundled
  font assets land with hashes and a loading budget.

## 1. Atmosphere

A scientific field bulletin: warm paper, ink, editorial headings, and evidence
labels. The memorable object is a dated **evidence strip** answering "source,
observed when, and what this signal means" beside each item — not a decorative
radar animation, KPI-card carpet, neon-green hacker chrome, faux terminal
wallpaper, glass panel, or gradient blob.

Rules:

- One vertical document-scroll owner per page. Sticky masthead never covers a
  keyboard-focused target.
- Square editorial geometry. Radius scale is `0` except for always-usable control
  shapes where a `2px` control radius aids affordance; never pill cards.
- Separation comes from typographic contrast, thin rules, and restrained surface
  changes — never colored accent-edge cards or tinted washes to mark selection.
- State is always text plus symbol, never color alone.

## 2. Color Tokens

Single source of truth. Components reference `var(--ledger-*)` only. Raw color
literals anywhere outside this file fail the build gate.

| Token                    | Value     | Use                                                                                                              |
| ------------------------ | --------- | ---------------------------------------------------------------------------------------------------------------- |
| `--ledger-canvas`        | `#F7F6F3` | Page background. Warm paper, not a gradient hero.                                                                |
| `--ledger-surface`       | `#FFFFFF` | Inputs, menus, reading and compare surfaces needing separation.                                                  |
| `--ledger-ink`           | `#1A1A1A` | Headlines, body, important numeric values.                                                                       |
| `--ledger-ink-secondary` | `#595959` | Source and date labels. Must stay readable at 14px+.                                                             |
| `--ledger-rule`          | `#D6D3CD` | Quiet separators. Never the sole evidence of a control boundary.                                                 |
| `--ledger-link`          | `#006A9F` | Underlined links and visible keyboard focus. Not a decorative accent.                                            |
| `--ledger-focus-ring`    | `#006A9F` | Focus outline. Same value as link by intent; separate token so focus stays visible if link styling ever changes. |

What is deliberately absent:

- No severity red/green scale. KEV, severity, forecast, and data-health states
  must not share one undifferentiated good/bad color. Until tested semantic
  text/background tokens are approved, use explicit words plus symbols on neutral
  surfaces.
- No success/warning/danger fills. Stale, failed, and missing states are
  distinguished by label text, symbol prefix, and border style — not hue.

Contrast intent (to be verified with a rendered audit before product screens):
body ink on canvas and surface, secondary ink at 14px+ on surface, link on
surface. If any pair misses WCAG 2.2 AA, darken the foreground token here first;
never patch a single component.

## 3. Type Scale

Three families, three jobs. Never substitute silently; if the loading budget
forces two families, test tabular numerals first and record the decision here.

| Role       | Family stack                                                 | Sizes                                                         | Use                                                                |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------ |
| Display    | `"Newsreader", Georgia, "Times New Roman", serif`            | 36px desktop / 28px phone, weight 600, line-height 1.15       | Page title and section emphasis only. Not tables.                  |
| Body       | `"Source Sans 3", "Segoe UI", system-ui, sans-serif`         | 22px section / 16px body / 14px controls and metadata minimum | Descriptions, navigation, controls, readable body.                 |
| Identifier | `"IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace` | 14px minimum, tabular figures                                 | CVE identifiers and compact technical values only. Not paragraphs. |

Rules:

- Controls and metadata are never below 14px. Never shrink data labels to tiny
  mono to fit another column.
- Long titles wrap. Long identifiers and URLs break without forcing viewport
  overflow (`overflow-wrap: anywhere` on identifier runs inside constrained rows).
- Semantic elements carry the scale: `h1` display, `h2` section, `p` body,
  `code`/identifier class for CVE IDs.

### 3.1 Emphasis roles

Three classes, three jobs. Each marks a short run inside an otherwise plain
sentence — never an entire paragraph, never a whole card.

| Class              | Style                                              | Use                                                                          |
| ------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------- |
| `.ledger-emphasis` | Bold, ink                                          | The key value: an entity name, a CVE identifier, a count, a verdict word.    |
| `.ledger-caveat`   | Italic, secondary ink                              | Caveats and definitions: scope limits, date basis, methodology asides.       |
| `.ledger-label`    | Mono, uppercase with letter-spacing, secondary ink | Signal names: KEV, EPSS, CVSS, and other short controlled-vocabulary labels. |

Rules:

- One emphasis per sentence in the common case; two at most. If everything is
  emphasized, nothing is.
- Emphasis never carries meaning alone: the surrounding words already name the
  value, the caveat, or the signal (no-color-alone rule applies to weight and
  style as much as to hue).
- `.ledger-emphasis` for key values and verdicts; `.ledger-caveat` for the
  sentence that limits them; `.ledger-label` for the signal name that produced
  them. Example: `<span class="ledger-label">EPSS</span> <span
  class="ledger-emphasis">0.82</span> <span class="ledger-caveat">forecast,
  not observed exploitation</span>.
- Forbidding: wrapping whole paragraphs, lists, or sections in any of the
  three; using `.ledger-label` for prose; using bold ink for caveats.

## 4. Spacing

4px base. Every margin, padding, and gap uses a step. No ad-hoc pixel values.

| Token               | Value  |
| ------------------- | ------ |
| `--ledger-space-1`  | `4px`  |
| `--ledger-space-2`  | `8px`  |
| `--ledger-space-3`  | `12px` |
| `--ledger-space-4`  | `16px` |
| `--ledger-space-6`  | `24px` |
| `--ledger-space-8`  | `32px` |
| `--ledger-space-12` | `48px` |
| `--ledger-space-16` | `64px` |

Layout contract:

- Document max measure `72ch` for reading surfaces; data surfaces may run wider
  but keep description columns readable.
- Phone is single column. Tablet stacks the support rail below its content.
  Desktop may add a restrained support rail for source and context.
- Filter controls wrap before they overflow. Before/After pairs stack by field
  on phone so nothing depends on remembering a far-away column.

## 5. Depth Strategy

- Elevation 0: canvas with rules between sections.
- Elevation 1: surface panels with a `1px` solid rule border. No shadows for
  decoration.
- Elevation 2 (reserved): surface plus a `1px` rule border and a single
  `0 1px 2px` shadow using ink at low alpha, for menus and compare inspectors
  that must sit above content. The shadow color derives from the ink token via
  `color-mix`, never a second black literal.
- Borders always pair a visible `1px` outline with the rule token; a rule line
  alone is never the only boundary of an interactive control.

## 6. Primitives and Required States

Every primitive below renders in `app/showcase/` in each listed state. A state
that cannot occur for a primitive is documented as not applicable rather than
faked.

### 6.1 Masthead / navigation

Current page marked with `aria-current="page"` plus a text marker, not color
alone. Keyboard focus always visible. Wrapped and mobile menu states collapse to
a disclosure, never a horizontal scroller. Historical-context variant carries a
retained-date banner line.

States: default, hover, focus-visible, current-page, wrapped-menu,
historical-context.

### 6.2 Search field / action

Button beside the input; `44px` minimum target. Pending disables the action and
announces via a polite status node. Invalid query keeps the typed text and names
the rule violated. No matches and error are distinct honest states with
recovery actions.

States: default, populated, focus-visible, hover-action, pending (loading),
invalid-query (error), no-matches (empty), error.

### 6.3 Filter control / group

Checkbox-chip group with a clear/reset action. Selected is a text prefix plus an
inset underline marker and `aria-pressed`, never a colored fill. Disabled keeps
its label readable. Wrapped labels flow to multiple lines without clipping.

States: default, selected, hover, focus-visible, disabled, cleared (empty),
wrapped-labels.

### 6.4 CVE result row

Identifier in mono, supplied title or excerpt in body, signal line in metadata,
official-record action as an underlined link. Long text wraps; unbroken URLs
break inside the row. Missing description, unscored, unknown-forecast, and
rejected-transition variants use the exact copy guardrails from section 8.

States: default, long-text, missing-description (empty), unscored, unknown-EPSS,
rejected-transition, hover, focus-visible.

### 6.5 Evidence strip

One line per source: provider, source date, check time, version or model.
Stale, failed, and missing are three distinct labeled states with symbol
prefixes (`~` stale, `!` failed, `?` missing) plus words, never hue alone.

States: default, stale, failed (error), missing (empty), loading.

### 6.6 Chart and accessible data view

Every chart ships a data-table equivalent, kept in a `<details>` disclosure so
the visual leads without hiding access. Loading is a skeleton with a status
announcement, not a spinning decoration hiding axes. Empty interval, unknown
bucket, and correction-note variants are explicit rows, not zero bars.

States: default, loading, empty-interval (empty), unknown-bucket, correction-note,
keyboard-equivalent (focus-visible table), error.

### 6.7 List mode / ordering explanation

Names the current policy, the tie and missing-value rules, and the coverage
denominator. Adjacent to the list it explains; never a tooltip-only detail.

States: default, tie-explained, missing-values-explained, coverage-denominator,
stale-policy (error), focus-visible.

### 6.8 Compare field

Before/After pair for one field across two snapshots. Labels are literal words
Before and After. Unchanged, added, removed, changed, unknown, and incomparable
model/version are distinct labeled rows. Changed values stay selectable.

States: unchanged, added, removed, changed, unknown (empty), incomparable
(error), focus-visible.

### 6.9 Snapshot selector

Selects a retained checkpoint. Available, missing, expired, initial-no-history,
and stale-historical-source are distinct labeled options or notices. Expired
and missing never substitute current data.

States: default (available), missing (empty), expired (error), initial-no-history
(empty), stale-source (error), disabled, focus-visible, loading.

### 6.10 Update notice

New data available without moving rows under active reading or focus. A polite
live region announces once; the visitor applies the update with an explicit
action. Never auto-reorders a list being read.

States: default, pending-update, applied, dismissed (empty), focus-visible.

### 6.11 Display timezone and timestamp

`TimeZoneSelect` is a compact select listing at least Asia/Jakarta (default),
UTC, Asia/Singapore, Europe/London, America/New_York, and America/Los_Angeles.
The choice lives in the `DisplayPrefs` client context, persists in
`localStorage` plus a cookie readable by server components, and re-renders every
`TimeText` on the page with no reload. `TimeText` renders a `<time dateTime>`
with a human absolute form in the selected zone plus the pinned abbreviation
("25 Oct 2026, 12:14 WIB"), an optional relative form, `title` with the exact
ISO for precision, and `suppressHydrationWarning`. Invalid or missing input
renders the explicit words "not recorded" — never a bare ISO string.

States: default (Jakarta), switched-zone, date-only, relative, invalid/missing
(empty), persisted-after-reload.

### 6.12 Help tip disclosure

`HelpTip` explains one term or filter with a real `<button type="button"
aria-expanded aria-controls>` carrying a "?" symbol (never emoji). The panel
opens on hover, focus, and click; Escape closes it and returns focus to the
trigger; click-outside closes it; content is linked via `aria-describedby` and
styled with `ledger-*` tokens under reduced-motion rules. Panel text is always
supplementary: the surrounding prose stands alone without it.

States: closed, open (pinned), hover, focus-visible, escaped-closed.

### 6.13 Interactive chart

Charts are hand-built from semantic links and CSS tokens; no chart library and
no canvas that hides values from assistive technology. Every bar, segment, or
month row is a real `<a>` with an accessible name stating its label, count, and
share of a named denominator ("13,606 of 395,286 published (3.44%)"). Hover and
keyboard focus show the same visible tooltip; Escape clears it. Activation opens
the exact filtered view (`/explore?dateStart=…&dateEnd=…` or `severity=…`).
Touch targets stay at least 44px in both dimensions even when the drawn bar is
shorter; the drawn height encodes the value, the target stays usable. ``>= 8%``
segments may label themselves; smaller segments rely on the counted legend.
No color-only encoding, no smoothing, no animation that changes values. Charts
declare their date basis (UTC day or UTC month) in the visible tooltip and
caption. A toggle may switch intervals (24 months / 30 days) but never changes
the underlying filter state.

States: default, hover, focus-visible, selected interval, empty interval,
unknown bucket, scroll region at narrow widths, data table open.

### 6.14 Signal block (priority rows)

Each row separates KEV, EPSS, CVSS, and optional forecast movement into labeled
blocks: mono uppercase signal name, bold key value, normal explanation, italic
caveat. EPSS carries a real 0–100% bar with a screen-reader text equivalent;
CVSS carries the version and a bordered band word. Unknown values render
"Unavailable" or "Unscored", never 0. A HelpTip beside each signal name explains
the definition; the block remains understandable without opening it. Ordering
rules stay adjacent as a definition list, and no composite risk score is shown.

States: listed/not listed, forecast present/absent, modern/legacy/unscored,
ADP-only, rising delta, stale score date, focus-visible, help open.

## 7. Motion

Purposeful state feedback only: focus outline arrival, disclosure open, pending
skeleton shimmer is static text when reduced motion is requested. Forbidden:
ornamental radar sweep, flashing feed, count-up statistics, scroll reveals that
delay data, animated charts that conceal exact values.

- Duration tokens: `--ledger-motion-fast: 120ms`, `--ledger-motion-base: 180ms`.
  Easing: `ease-out`.
- `prefers-reduced-motion: reduce` disables every transition and animation on the
  showcase; the reduced-motion stress case screenshots prove the stable path.

## 8. Accessibility Constraints

- Target WCAG 2.2 AA: 4.5:1 normal text, 3:1 large text and essential non-text,
  visible focus on every interactive element, semantic headings and tables,
  announced async results without live-region noise.
- Touch targets are at least `44px` in both dimensions for this product.
- No hover-only critical action. Changed values remain selectable and keyboard
  reachable. No automatic table movement while reading or typing.
- Data copy guardrails (exact strings used in components and showcase):
  `EPSS unavailable for this snapshot`, `Unscored under this view's policy`,
  `History begins`, `Snapshot unavailable`, `Forecasts use different models;
change is not compared`, `Not listed in this KEV snapshot`, quiet state with a
  date, last-known-good content with a visible source-specific warning.

### 8.1 Accessibility debt (todo-24 hardening, 2026-10-24)

| Item                                                                                                | Status             | Owner / exit                                                                                                                                                                                                                                        |
| --------------------------------------------------------------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Showcase-only `OrderingExplanation` keeps `tabIndex={0}` plus `aria-label` on a static `div`        | Open, low          | Product UI owner; remove both when the showcase primitive is next touched (Wave-4 pages already dropped the pattern). Exit: `rg "tabIndex" src/components/ledger` prints nothing.                                                                   |
| Showcase-only `SnapshotSelector` note uses `role="status"` for static text                          | Open, low          | Same as above. Exit: status/alert roles appear only on dynamic results, errors, and the radar filter count.                                                                                                                                         |
| Inline sentence links (e.g. the methodology body link) are exempt from the 44px rule per WCAG 2.5.8 | Accepted, not debt | Recorded so a future audit does not "fix" readable prose. Exit: none; `tests/e2e/a11y-audit.ts` encodes the inline exception.                                                                                                                       |
| Automated checks are Playwright assertions, not axe-core                                            | Accepted           | axe-core was not warranted: every route is server-rendered with a small primitive set, and the audit covers headings, names, scopes, live regions, focus, touch, zoom, and reduced motion. Exit: adopt axe-core only if a client-heavy route lands. |

## 9. Token-to-Code Map

| Token group                   | Defined in                    | Consumed by                             |
| ----------------------------- | ----------------------------- | --------------------------------------- |
| Colors, spacing, type, motion | `app/globals.css` `:root`     | Every component via `var(--ledger-*)`   |
| Primitives                    | `src/components/ledger/*.tsx` | `app/showcase/page.tsx` sections        |
| State coverage                | `tests/e2e/showcase.spec.ts`  | Evidence dir `task-2-cve-change-radar/` |

Grep gate: `rg -n "#[0-9a-fA-F]{3,8}\\b" --glob '!DESIGN.md' --glob '!.git/**' --glob '!node_modules/**' --glob '!.next/**' app src tests || true`
must print nothing. The only sanctioned color literals live in the table in
section 2 of this file.
