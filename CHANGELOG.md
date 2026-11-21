# Changelog

All notable changes to Kevelry (package/image `cve-change-radar`). The public API
is versioned separately at `/api/v1`; every API change in 2.0.0 is additive.

## Unreleased

The v3 wrap-up: correctness first, then structure and hardening. No new product
surface, no schema migration, no API contract change. `package.json` stays at
`3.1.0`; this section is unpublished until the release step (planned as 3.2.0)
bumps, tags and pushes the image.

### Fixed

- **A stale aggregate count is never served under a fresh revision.** Every read
  path (overview, status, health, coverage) now checks the aggregate cache against
  the acceptance ledger before trusting it; when the cached snapshot predates the
  accepted source revision, the request falls back to a live query instead of
  pairing new provenance with previous-generation numbers. The cache also stops
  seeding an ETag it cannot vouch for. Covered by a failed-refresh test that
  asserts no response mixes a new revision with old counts.
- **API error responses carry `Cache-Control: no-store`, and no ETag.** A 4xx/5xx
  can now never be memoized by an intermediary for a request that would succeed;
  the documented promise in `docs/DATA_WORKFLOW.md` and `docs/api/README.md` is the
  reason for the header rather than a claim the code did not keep.
- **Expired rate-limit buckets are evicted.** The per-IP map used to grow for the
  life of the process, so a scraped port or an IPv6 /64 churned memory with no
  sweep. Eviction rides an insertion-ordered expiry queue (O(1) amortised, no
  timer), and `docs/api/README.md` now says the 600/minute budget is **per
  process**.
- **The "latest month" stat names the month it measures.** It was the newest month
  _with additions_ labelled as the latest month, so an empty current month made a
  stat and its caption describe different months. It is now "last month with
  additions" with the month named.
- **A missing EPSS observation no longer erases the whole sparkline.** One `null`
  used to collapse the figure to nothing, contradicting `DESIGN.md` §7.0 clause 6.
  The observed points still plot, the line breaks at each gap, and the caption
  states how many observations are absent — a gap is never drawn at zero.
- **Arrow keys wrap at both ends of a roving chart group.** Entering the sparkline
  on the latest mark made the first ArrowRight a no-op; focus and step direction
  now agree, and the wrap is pinned without a DOM.
- **A touch tap pins the KEV rhythm readout.** `pointerup` used to clear the
  tooltip, so the promised "kept until the next tap" did not exist on touch. The
  same pointer-type guard the sparkline already had is applied, and a tap on
  another bar moves the pin.

### Changed

- **One renderer for every chart tooltip and data table.** Seven tooltips
  (`/`, `/explore`, `/priority`, `/graph` surfaces included) and eight data tables
  now render through `ChartTooltip` and `ChartTable`, and the share formatter is
  one helper instead of two precisions. Verified rather than asserted:
  `grep -rn 'className="chart-tooltip\|className="chart-table' src app` matches only
  the primitive files, and the 3.1.0 line claiming the primitives "replace five
  hand-rolled copies" is now true.
- **Donut segments show a visible keyboard focus ring**, matching the graph's rule,
  so a focused segment is distinguishable from hover.
- **Dense chart marks meet the 44px hit-target rule where the layout allows.** The
  accessibility audit now measures focusable `role`-bearing marks, not just form
  controls, and fails on a deliberately undersized one. One measured exception is
  pinned and printed: the KEV rhythm's twelve columns are **23×124** in a 320px
  panel, 1px under WCAG 2.5.8's 24px floor — moving the chart to `span-8` is a page
  composition decision, not a hit-geometry one, and the "All months" table carries
  every value meanwhile.
- **`src/lib` no longer imports out of `app/`.** The CWE display read model moved
  into `src/lib`, so the dependency arrow points the way it should.
- **`OPTIONS` preflights are throttled.** Preflight spends one hit from the same
  per-IP budget (a client can no longer loop them for free) but still takes no
  concurrency slot, because it does no database work. Documented beside the limiter.
- **`CWE_CSV_URL` must be an absolute `https:` URL.** `http:`, `file:`, `data:` and
  relative overrides are refused before any fetch, with the reason logged and the
  pinned MITRE default used instead of throwing.
- **Optional HSTS.** `Strict-Transport-Security` is sent on every HTTPS request;
  `HSTS_ENABLED=true` adds it on plain HTTP too, for deployments behind a TLS
  terminator. Default off, so a direct-HTTP self-host is never bricked.

### Added

- **`CONTEXT.md`** — the domain language this code actually implements: band vs
  cohort, checkpoint vs snapshot, acceptance ledger vs aggregate cache, and the
  narrower-than-common uses of "exploit signal" and "inspectable data".
- **`scripts/nightly-backup.sh --verify <dir>`** re-checks a stored generation with
  the same `verifyBackup()` the nightly run uses (hash, schema, row counts),
  decompressing the gzip into a `mktemp -d` directory that is removed on success
  and on failure. The cron artifact is now verified after compression, so the
  retained gzip passes with no manual `gunzip` step, and the prune refuses a
  backup root that is empty, relative, `/`, or shallower than two path components
  (`exit 2`, before anything is created or mounted).

### Tests

- **632 → 708 unit tests (3 skipped).** The additions cover the chart primitives
  (tooltip shape, clamping and last-30% flip, table structure and empty-series
  copy, roving Arrow/Home/End plus the wrap at both ends), the 44px audit selector
  and its pinned exception, aggregate-currency fallbacks, `no-store` on every error
  status, rate-bucket eviction, the sparkline gap rules, and the https-only CWE URL
  guard.
- **130 → 138 Playwright tests (0 skipped).** The keyboard matrix now covers both
  ends of the roving groups, and the touch-pin journey asserts the KEV tooltip
  survives `pointerup`.

## 3.1.0 — 2026-11-20

Making every chart value inspectable: a written contract, shared primitives, and the KEV rhythm's twelve months made real.

### Added

- **Inspectable data is a written contract, not a per-chart habit.** `DESIGN.md`
  §7.0 states what "inspectable" means in ten checkable clauses — every mark is a
  hover and keyboard-focus stop, the tooltip has a fixed label / value / share
  shape, a value never exists only on hover, a genuine zero stays a value while a
  missing observation is never plotted as one, and a role follows behaviour. The
  per-chart sections point at it instead of repeating it. The audit and the
  migration phases stay in `docs/plans/data-visibility-standard.md`.
- **`ChartTooltip`, `ChartTable` and `useRovingMarkFocus` replace five
  hand-rolled copies.** `ChartTooltip` renders the fixed shape inside the chart's
  own positioned host, clamps to its edges, flips in the last 30% of the width and
  never covers the mark it describes. `ChartTable` is the `<details>` fallback
  that survives with JavaScript off and states an empty series instead of drawing
  zeros. `useRovingMarkFocus` is the keyboard contract: one Tab stop,
  Arrow/Home/End between marks, real DOM focus so the focused mark's own label is
  the announcement, and Escape for the surface's dismiss.
- **The EPSS sparkline on `/priority` is readable point by point.** One hit band
  per observation maps the pointer to the nearest index, Arrow/Home/End step the
  same series from a single Tab stop, and both show that observation's UTC date,
  probability and model version. The caption prints the observed range and a data
  table lists every observation, so no value needs a pointer.
- **The KEV rhythm on `/` is twelve focusable bars.** Each month gets a
  full-height hit target; hover and keyboard focus produce identical text (full
  month name, `· UTC`, count, and share of the window total); and the window
  maximum is labelled. A month with no additions is drawn as a focusable 1px mark
  reading `0` rather than vanishing — the loaders emit a dense twelve-month UTC
  spine, so a calendar month with no rows is a real zero bucket (see Fixed). The
  panel gains a "How to read" line and a data table, neither of which existed
  before.

### Fixed

- **The KEV rhythm's "twelve months" is twelve calendar months.** `kevByMonth`
  grouped only months that had rows and took the twelve most recent of those, so a
  month with no additions was absent rather than `0`, the window could span more
  than twelve calendar months, and the chart's zero-bar rendering was
  unreachable. Both loaders now build the trailing twelve-month UTC spine
  (`src/lib/kev-months.ts`) and left-join the sparse counts onto it. The caption
  total is the sum of the twelve bars: the real count inside the window. The
  aggregate version goes 6 → 7 so a cached sparse snapshot is recomputed rather
  than served.

### Changed

- **`/graph` links and the severity donut segments are reachable.** Both chart
  roots were `role="img"`, which flattens interactive children out of the
  accessibility tree. The graph root is now a named `role="group"`, so its leaf
  links are reachable again. Each donut segment is now the same real link to the
  severity-filtered Explore view its legend row already was, rather than a
  `role="button"` that did nothing; a band Explore does not accept stays a
  labelled, non-interactive mark.
- **Chart tooltips print full precision.** EPSS is printed from the stored decimal
  string at one fixed three-decimal precision (`54.000%`, not `54%`) at every
  print site — sparkline tooltip, caption range, data table, live announcement and
  the graph badges — instead of passing through a float and trimming trailing
  zeros. The number was never rounded upstream; the loss was in the formatter.
- **The Sankey bands and the Explore cohort months no longer lean on a native
  `title`.** Each is a real mark carrying the shared tooltip, or printed text
  where the value was already on screen.

### Removed

- **`charts/SeverityMix`.** Nothing imported it: no route and no test, and the
  overview had already moved to the severity donut. Its P4 migration is superseded
  by removing the component rather than maintaining an unmounted copy of the
  pattern.

### Tests

- **622 → 632 unit tests (3 skipped).** The seven EPSS-precision cases pin
  `displayProbabilityPercentFixed` and `formatEpssPercent` so a formatter change
  cannot silently re-round a published probability; three more pin the dense KEV
  month spine (twelve buckets, zeros in the gaps, window-bounded sum) in both the
  cached and live loaders. The Playwright suite gains one gap-month KEV rhythm
  assertion (129 → 130 passed / 0 skipped).

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- `AGGREGATE_VERSION` moves 6 → 7, so the aggregate cache is rebuilt on the first
  boot after the upgrade. That is expected and needs no action.
- No API contract change: every 3.1.0 entry is presentation, documentation, or an
  internal cache version.
- The KEV rhythm now always shows twelve calendar months, including zero months,
  so a month that previously vanished from the chart now appears as `0`.

## 3.0.2 — 2026-11-17

### Fixed

- **The `/graph` attribute dialog ignored Escape once the filter had focus.** The
  filter is a `type="search"` input, so the browser consumed the first Escape to
  clear the field itself: the dialog never received `cancel` and stayed open. The
  input now clears the filter and closes the dialog on the first Escape, without
  `preventDefault`, so the native close path still runs. Covered by an
  unconditional regression test that arms the swallowed-Escape path, then asserts
  the dialog closed and the filter was dropped for the next open.

### Changed (tests only)

- **The e2e suite runs against its own fixture corpus.** `global-setup` seeds
  `.e2e/data` and `global-teardown` removes it, and the Playwright dev server
  starts with `DATA_DIR=./.e2e/data`, `SCHEDULE_ENABLED=false` and
  `INGEST_ON_START=false`. The suite no longer reads or writes the checkout's
  `data/cve.db`, so a spec that swaps its corpus cannot disturb a running
  instance, and full-suite counts are deterministic: 129 passed / 0 skipped,
  with no guard left to skip. The `+N more` journey now deploys a dense cohort
  so the attribute group clears the drawing cap. No runtime change.

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- No API contract change: the fix is a client-side key handler.
- No config change: the Compose environment contract and `/data` layout are
  unchanged.

## 3.0.1 — 2026-11-17

### Security

- **Next.js 16.4.3 → 16.4.5** for CVE-2026-119348 (GHSA-pc58-hwjq-p385).
  `npm audit --omit=dev` is clean.

### Added

- **Atom 1.0 change feed** at `GET /api/v1/radar/feed.atom`, conforming to
  RFC 4287 and built from the same retained checkpoints as the RSS feed.
- **CWE names in the relation graph.** The graph payload now carries
  `cweDetails` plus the `cweCatalog` envelope, so shared-CWE groups, hub chips,
  and drill-down labels read `CWE-416 · Use After Free`.

### Fixed

- **CWE phase markers leaking into payloads, then mitigations parsing to
  empty.** The importer strips marker runs before the 600-code-point cap, and
  the read path parses `::PHASE:`/`:DESCRIPTION:` segments instead of deleting
  `::…::` pairs. Across the 692 stored mitigations this took empty results from
  333 to 0 and left 692 non-empty, with no `::PHASE` or `PHASE:` text in any
  payload.

### Changed

- **One `withApiRoute` wrapper** now serves all 14 API routes, replacing the
  repeated guard sequence; duplicated display and feed helpers are
  consolidated, and the v3 files are formatted with Prettier.

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- No API contract change: every 3.0.1 addition is additive, and the wrapper is
  structural only.

## 3.0.0 — 2026-11-15

All five v3 epics are implemented, verified, and shipped in this release.

### Added

- **CWE names in the relation graph (E3).** The graph payload now carries the
  additive `cweDetails` (keyed by normalized `CWE-<n>`, covering every id the
  cohort references) plus the `cweCatalog` envelope, resolved in one batched
  catalog lookup per response, and the shared-CWE group labels, hub attribute
  chips, drill-down title and data table render `CWE-416 · Use After Free` with
  the canonical MITRE link, `not in the loaded catalog` for an unmapped id, and
  one block-level `taxonomy unavailable` note when no catalog is loaded.

- **CWE chips, states, and mitigation disclosure in the Priority view (E3 step
  3b).** The expanded Priority row now renders every `kev.cweDetails` ref from
  the API instead of the raw id strings: the mono id is the label, and a
  `known` id joins it with the published catalog name at a bounded width
  (`CWE-79 · Improper Neutralization of Input During Web Page Generation …`).
  The id never truncates, is never replaced by the name, and is never hidden.
  The whole chip is one link to the canonical
  `https://cwe.mitre.org/data/definitions/<n>.html` (`target="_blank"`,
  `rel="noreferrer noopener"`), with a 44px target and a visible keyboard focus
  ring; `unmapped` chips add the words **not in the loaded catalog**, and
  `taxonomy-unavailable` says **taxonomy unavailable** once at block level so
  each id still renders as its own chip. No severity colour, no band class, and
  no "vulnerable to" phrasing: an id names a weakness class, not a confirmed
  exploit. `known` ids that published mitigation text gain a `<details>`
  disclosure labelled `Mitigation (reference, MITRE CWE <version>)`, with the
  version read from a new additive `cweCatalog` envelope block
  (`{status, version, retrievedAt, source}` on the detail and priority
  responses) rather than hard-coded, the already-stripped body text, and a
  `HelpTip` stating it is published guidance whose applicability depends on the
  product. The page resolves every rendered row's ids in one batched catalog
  lookup; the component stays presentational. Docs: `DESIGN.md` (chip anatomy,
  the three states, disclosure contract), `docs/DATA_WORKFLOW.md` (catalog
  provenance and the version-label rule), `openapi/v1.yaml` (`CweCatalog`),
  `docs/api/cves.md`, `docs/api/priority-lists.md`, and `.env.example` /
  `README.md` now describe `CWE_REFRESH_ENABLED` as **fail-closed** for config
  parsing (fetch failure remains fail-soft/last-known-good). Tests:
  `tests/priority-view.test.ts` covers the chip/name and disclosure-label
  helpers; `tests/api-routes.test.ts` covers the `cweCatalog` envelope;
  `tests/e2e/priority-cwe.spec.ts` covers a known chip's id, name, canonical
  href and `rel`, an unmapped id, a single block-level `taxonomy unavailable`
  with an empty catalog, the keyboard-opened disclosure (no `::`, names the
  version, HelpTip present), and 360px/dark-theme readability asserted through
  computed colours.

- **CWE labels in API payloads with marker stripping and a fail-closed flag
  (E3 step 3a).** `GET /api/v1/cves/{cveId}` now serves a top-level
  `cweDetails: CweRef[]` alongside `kev.cwes` (same order, deduped after
  normalization, never omitted), and every priority row carries the additive
  `kev.cweDetails`, resolved for the whole page in one batched catalog lookup.
  `CweRef.status` keeps the three states distinct — `known` (published `name`
  plus `abstraction`/`summary`/`mitigation` only when MITRE published them),
  `unmapped`, and `taxonomy-unavailable` (still present, with its canonical
  `url`) — so an absent or stale catalog never removes an id and never invents a
  name. List, search, and bulk rows stay ID-only by design. A new
  `stripCweMarkers` in `src/lib/cwe-catalog.ts` removes MITRE's `::PHASE:…::`
  control markers (plus any other `::…::` run), collapses whitespace, and never
  throws; it runs at projection time only, so stored rows stay verbatim and no
  payload contains `::`. `CWE_REFRESH_ENABLED` is now **fail-closed**: only
  `true`/`false` are accepted, absent still means enabled (the job is 24 h-gated
  and hash-conditional), and any other value disables the refresh and logs one
  `cwe-refresh-config-invalid` event with the value sanitised to a single,
  length-capped line — a typo can no longer look like consent to fetch
  upstream. Docs: `openapi/v1.yaml` (`CweRef`, detail `cweDetails`, priority
  `kev.cweDetails`), `docs/api/cves.md`, `docs/api/priority-lists.md`,
  `DESIGN.md` (chip anatomy, marker rule, list rows stay ID-only), and
  `docs/DATA_WORKFLOW.md` (payload states, fail-closed flag).

- **CWE catalog ingest with last-known-good (E3 step 2b).**
  `refreshCweCatalog(db, options)` in `src/lib/cwe-import.ts` is now the only
  writer of `cwe_entries` / `cwe_catalog_meta`: fetch → `extractSingleEntryZip`
  → `parseCsvRows` → `mapCweCsv` → one transaction. The pin is MITRE's
  “Research Concepts” view, `https://cwe.mitre.org/data/csv/1000.csv.zip`
  (verified 2026-11-14: HTTP 200, `application/zip`, 644,612 bytes, one 3.2 MB
  CSV, 956 accepted entries); `CWE_CSV_URL` may override it but must be an
  absolute https URL. Caps: **8 MiB** downloaded zip, **64 MiB** extracted CSV
  entry, **16 MiB** parsed CSV text, **30 s** fetch timeout, **300 chars** per
  stored reason. `version` is `<view id>-<entry count>` (`1000-956`) because the
  published CSV carries no version marker; `source_hash` (SHA-256 of the
  accepted zip bytes) is the exact pin. Acquisition is **conditional**: when the
  downloaded bytes hash to the accepted `source_hash` nothing is parsed and
  nothing is written (`{ status: "unchanged" }`), and a hash match on a
  non-`ready` row whose entries are intact restores `ready` without re-parsing.
  **Publication is one transaction** (`DELETE` + inserts + meta upsert), so a
  reader never sees a half-replaced taxonomy and a failure mid-publish rolls
  back. Failure is **last-known-good**: entries are never deleted, the meta row
  records `status='stale'` with a sanitised `notes` reason (single line,
  credentials stripped, ≤300 chars), and the call returns
  `{ status: "failed", reason }` instead of throwing. The worker hooks this as
  maintenance that is _not_ a scheduler source (it cannot contribute to
  `failed`/readiness or block an import): at most one attempt per 24 h, gated by
  the accepted `retrieved_at` and tracked in-process, awaited once at boot and
  fired after each settled cycle, logging `cwe-refresh`,
  `cwe-refresh-unchanged`, or `cwe-refresh-failed`. `CWE_REFRESH_ENABLED=false`
  disables it and `REFRESH_CWE_ONCE=true node dist/worker.mjs` performs exactly
  one attempt (exit 1 on failure) for seeding or retrying a stale catalog.
  `tests/cwe-import.test.ts` drives everything through injected fetchers — no
  network — covering publish, the unchanged no-write path, HTTP 500, timeout,
  bad zip, oversize payload, mid-publish rollback, stale recovery, the
  https-only URL rule, reason sanitisation, the cadence gate, and the one-shot
  path; `tests/setup.ts` pins `CWE_REFRESH_ENABLED=false` so no test boot reaches
  upstream. Source terms, the verified URL, and the safety properties are
  documented in `docs/research/SOURCES.md`; cadence and failure semantics in
  `docs/DATA_WORKFLOW.md`.

- **Dependency-free CWE zip reader and CSV mapping (E3 step 2a).**
  `src/lib/zip.ts` reads a single-entry MITRE `CSV.zip` using only
  `node:zlib`: End of Central Directory, the central-directory record, then the
  one local header; stored (0) and deflate (8) are supported, sizes come from
  the central directory, and rejections are typed `ZipExtractError`s
  (`not-zip`, `entry-count`, `encrypted`, `unsupported-method`, `multi-disk`,
  `zip64`, `declared-size`, `inflated-size`, `corrupt`) instead of raw Node
  errors. The required `maxUncompressedBytes` cap is enforced against the
  declared size and passed to `inflateRawSync` as `maxOutputLength`, so a zip
  bomb is stopped before it allocates. `src/lib/cwe-import.ts` adds a bounded
  RFC 4180 reader (`parseCsvRows`, 16 MiB cap; quoted fields, embedded commas
  and line breaks, doubled quotes, CRLF/LF, no final newline) and `mapCweCsv`,
  which maps by header name (`cwe-id`/`id`, `name`, `abstraction`, `status`,
  `description`, `mitigation`), ignores unknown columns, normalizes ids through
  `normalizeCweId`, skips and counts rows with an unusable id, blank name, or
  duplicate id, strips CR/LF to spaces, and truncates summary/mitigation at 600
  code points with `…`. No fetch, worker wiring, UI, or database write in this
  step. Tests in `tests/cwe-import.test.ts` build zip fixtures in-process
  (stored, deflated, multi-entry, encrypted, declared-size, bomb) and cover CSV
  quoting, CRLF/LF, header reordering, unknown columns, skipped ids, and
  truncation.

- **Local CWE taxonomy schema and reader (E3 step 1).** Migration 009 adds two
  additive tables: `cwe_catalog_meta` (a pinned one-row pointer to the accepted
  catalog with `version`, `source`, `source_hash`, `retrieved_at`, `status`,
  `record_count`, and `notes`) and `cwe_entries` (normalized `CWE-<n>` primary
  key with `name`, optional `abstraction`/`status`/`summary`/`mitigation`,
  `version`, `updated_at`). No fact table changes and no extra index beyond the
  entry primary key. `src/lib/cwe-catalog.ts` is the purely local read seam:
  `getCweCatalogMeta` reports `ready`, `stale`, `unavailable`, or `empty`, and
  `resolveCweIds` maps caller ids to a `CweRef` in one of three states —
  `known` (with the published fields and canonical MITRE URL), `unmapped`
  (valid-shaped id absent from the catalog, or an unparseable input retained as
  its raw string), or `taxonomy-unavailable` (no accepted catalog, so no name
  is claimed). `CWE-79`, `cwe-79`, and `79` normalize to `CWE-79`; inputs are
  deduped and looked up in bounded `IN` batches. The reader never throws on
  caller input, never fabricates a label, and never touches upstream. Tests in
  `tests/cwe-catalog.test.ts` cover known/unmapped/unavailable resolution,
  absent mitigation, normalization, dedupe, invalid shapes, chunk boundaries,
  and the `empty` meta state before any load.

- **Page-bounded CSV/JSON export and subscribe controls (E5).**
  `GET /api/v1/search` now accepts `format=csv|json` and serializes **exactly
  the page it already returned** — the same validation, filters, ordering,
  `limit`, and `cursor`, with no fan-out and no second scan. `format=csv` answers
  `text/csv; charset=utf-8` with `Content-Disposition: attachment;
filename="kevelry-search-<UTC date>-<n>rows.csv"` and the stable column order
  `cveId,title,state,publishedAt,updatedAt,severityBand,primaryCvssVersion,
primaryCvssScore,kevListed,kevDateAdded,epssValue,epssPercentile,
exploitTagged,officialUrl`, RFC 4180 quoting (comma, quote, CR, LF; embedded
  quotes doubled), null/absent values as empty cells, and **no `#` comment
  rows** — the file is a header row plus data rows only, because spreadsheet and
  SQL importers would read comment rows as data. `format=json` is the unchanged
  envelope (`q`, `vendor`, `data`, `pagination`, `coverage`, `provenance`) plus
  the attachment headers; an absent `format` keeps today's JSON response and an
  unknown value is `400 BAD_FILTER`. Exports share the JSON routes' ETag/304 and
  cache policy. Explore's results header adds `Export CSV` / `Export JSON`
  controls labelled with the page's row count (`Export CSV (20 rows)`), 44px
  targets that link to `/api/v1/search` with the current query string, cursor,
  and page `limit`; they are disabled with a visible explanation only when the
  page genuinely has no rows. Export mode is the one documented exception to the
  `q`/`vendor` requirement, so the default unfiltered Explore view is
  exportable: `format=csv|json` without either serializes the same unfiltered
  first page (same ordering and bounds), while a plain JSON request without
  `format` still answers `400 BAD_QUERY` and the error message states the
  exception. The Radar view adds a `Subscribe` block: a 44px
  link to `/api/v1/radar/feed.xml` with the RSS type plus a read-only URL field
  that selects itself on focus, so the feed URL is copy-able by keyboard. Docs
  updated in `docs/api/search.md`, `docs/api/radar.md`, `openapi/v1.yaml`, and
  `DESIGN.md`; tests cover quoting, the column/header contract, `limit`-bounded
  rows, filter parity with JSON (an `exploit=tagged` export cannot leak the
  unfiltered set), row-set parity between the page's own query path and the
  unfiltered export, the invalid-format error, and the controls at 360px.

- **RSS 2.0 change feed (E5).** `GET /api/v1/radar/feed.xml` serializes the
  events `GET /api/v1/radar` already serves from retained checkpoints, for
  anonymous pull subscribers. It reuses the JSON route's parsers and filters:
  `since` (UTC `YYYY-MM-DD`), `kind`, `cveId`, and `limit` (default 50, max 200);
  invalid values return the same `BAD_FILTER`/`BAD_LIMIT` codes. `since` older
  than the 30-day checkpoint retention window is `400 BAD_FILTER` naming the
  earliest allowed date — never an empty 200 that would read as "no changes".
  Items are factual only: `<guid isPermaLink="false">` is the `eventId`,
  `<title>` is `<cveId> — <kind>`, `<pubDate>` is the RFC 822 form of
  `observedAt`, `<link>` is the canonical cve.org record, and `<description>`
  lists `field: before → after` lines then `reason:` then `sourceRevision:`,
  XML-escaped (`&`, `<`, `>`). The channel names accepted local snapshots and
  the retention window and sets `<lastBuildDate>` from the newest checkpoint.
  Success responses use `Content-Type: application/rss+xml; charset=utf-8`,
  `Cache-Control`, and a strong `ETag` seeded from the retained checkpoint set
  (newest date, oldest date, count) plus the validated query shape, so a repeat
  request revalidates as `304`. The feed uses the shared rate-limit,
  concurrency, request-bound, preflight, and security-header guards; errors
  stay JSON. Docs updated in `docs/api/radar.md`, `docs/api/README.md`, and
  `openapi/v1.yaml`. Export, UI subscribe controls, and Playwright remain out
  of scope for this API-only step.

- **Atom 1.0 change feed (E5).** `GET /api/v1/radar/feed.atom` serializes the
  same retained change events as the RSS feed into an RFC 4287 document for
  subscribers that prefer Atom. It shares the RSS route's query parsers, 30-day
  retention clamp, event selection and ordering, ETag seed, conditional `304`,
  cache policy, and guardrails; only the serializer, content type
  (`application/atom+xml; charset=utf-8`), feed path, and ETag discriminator
  differ. Feed `id`, `title`, `updated`, and `author/name` satisfy RFC 4287
  §4.1.1, entries carry `id` (the same `eventId` as the RSS `<guid>`), `title`,
  RFC 3339 `updated` (§3.3), `summary`, and an alternate cve.org link (§4.1.2),
  and `rel="self"` / `rel="alternate"` are omitted when the public origin is
  unknown, exactly like RSS. Docs: `docs/research/atom-feed.md`,
  `docs/api/radar.md`, `openapi/v1.yaml`, README, and the Radar subscribe
  control now offering both formats at 44px with the retention note. Tests:
  `tests/radar-feed.test.ts` (well-formedness, required elements, cross-format
  id equality, RFC 3339 dates, escaping, retention `400`, `304`) and
  `tests/e2e/radar.spec.ts` (both links and both routes at 360px).

- **Daily checkpoint writer (E5).** The worker now actually fills the
  `checkpoints` table the Change Radar, replay, and RSS feed read. After every
  ingestion cycle in which at least one source was accepted it freezes exactly
  one checkpoint for the current UTC date; a second cycle on that date writes
  none (checkpoints stay immutable), and a cycle where every source failed
  writes none. Source pins are the accepted versions already recorded in
  `sync_runs` (last succeeded run per source; for KEV the observed catalog date
  the accepted catalog wrote), the policy version is `RADAR_POLICY_VERSION`,
  and the per-view cap is the validated `CHECKPOINT_TOP_N` resolver, so the
  daily write stays bounded. The write is fail-soft: a missing accepted pin, a
  rejected bound, or a store error logs `checkpoint-write-failed` and the cycle
  still completes, so a checkpoint fault can never fail an import or block the
  next source. With no retained checkpoint the RSS channel `<description>` now
  states "No change checkpoints are retained yet; this feed fills as the daily
  checkpoint writer runs." instead of leaving an empty item list to read as
  "no changes"; the response stays `200` with a valid empty channel. Tests
  cover one write per UTC date, the repeat-cycle no-op, the all-failed cycle, a
  logged write failure, and the empty-feed wording.

- **Bulk CVE lookup route (E4).** `GET /api/v1/cves/batch?ids=CVE-…,CVE-…`
  returns up to 50 records in one bounded read. `ids` is required, trimmed,
  empties dropped, and deduped preserving first-seen order, so `data` is in
  requested order; every element must match `CVE-YYYY-NNNN+` and the cap is 50
  unique IDs. The envelope is `{ data, resolution: { requested, returned,
missingIds }, provenance }`: absent and not-publicly-visible IDs are listed
  in `resolution.missingIds` (requested order) instead of being fabricated or
  failing the whole request with a `404`. The route deliberately does **not**
  reuse the list route's `coverage` key, which keeps its single meaning
  (eligible cohort). Known list/search params (`cursor`, `limit`, `severity`,
  `kev`, `epss`, `exploit`, `publishedStart`, `publishedEnd`, `vendor`, `q`)
  are rejected with `400 BAD_REQUEST` naming the param; any other unknown
  parameter is ignored. Success responses carry the usual strong `ETag` seeded
  over the canonical sorted ID set plus the aggregate revision, so the same set
  in any order revalidates as `304`. Guardrails are the shared ones (`getDb`,
  rate limit, concurrency slot, request bounds, `preflightResponse`), and items
  are exactly the `CveItem` shape the list route serves, so a bulk item
  deep-equals the same record from `GET /api/v1/cves/{cveId}` minus the
  detail-only extras. `BAD_ID` joins the error catalog. Docs updated in
  `docs/api/cves.md`, `docs/api/README.md`, `openapi/v1.yaml`, and the
  `/api-docs` page. Playwright is out of scope for this API-only epic.

- **Unscored coverage counters and the secondary coverage detail block (E1).**
  `unscored` was one number for two different situations. The aggregate cache
  now splits it with two additive SQL counters over the same predicates the
  severity bands already use (never `raw_json`): `secondaryOnly` (PUBLISHED,
  no valid CNA metric, at least one valid ADP metric — context exists) and
  `noMetric` (no valid CNA and no valid ADP metric — nothing published). They
  are an exact partition of the unscored cohort, asserted in
  `tests/aggregates-coverage.test.ts`, and `AGGREGATE_VERSION` moves to 6 so an
  older snapshot is rejected instead of read with missing keys.
  `/api/v1/overview` exposes both in its `coverage` block; every existing field
  keeps its name and meaning (list endpoints are unchanged). The overview's
  "Unscored severity" stat gains the subnote `X with ADP secondary (context) ·
Y with no published metric` with the unscored cohort as denominator and a
  `HelpTip` stating secondary is context only and never used for ranking or
  eligibility — no band colour, no filter. The expanded Priority severity block
  gains a "Secondary (context only)" group listing each metric's origin/
  provider, version, base score, and vector, or the explicit line "No CNA or
  ADP metric published." Secondary never renders as a band, never appears in
  the compact signal line, and is never filterable. The api-docs CVE detail
  example now includes `cvssSecondary`, closing the drift left by the previous
  entry. Playwright covers the subnote numbers at 1280/360px and in dark theme,
  plus the detail block (words "context only", no `badge-*`/band class, absent
  from the compact signal line).

- **KEV ransomware tri-state and self-describing block (E2).**
  `kev_entries.ransomware_known` is an integer, and its three states now have
  one documented mapping (`kevRansomwareUseOf` in
  `app/api/v1/_lib/records.ts`): `1` → `"known"`, `0` → `"unknown"` (the
  catalog's own Unknown value), `NULL` → `"unstated"`. `0` and `NULL` are never
  collapsed, and no output renders a ransomware-free claim from either. Every
  `CveItem.kev` block gains `ransomwareUse` additively and keeps
  `ransomwareKnown` as a legacy boolean alias (`true`/`false`/`null`) so
  existing consumers are untouched. The block is self-describing: `listed`,
  `dateAdded`, `dueDate`, `requiredAction`, `vulnerabilityName`, `cwes`, with
  absent catalog text served as `null` (never `""`) and empty `cwes` as `[]`.
  OpenAPI, `docs/api/cves.md`, and `docs/DATA_WORKFLOW.md` document the mapping
  and that KEV dates/text are catalog facts, not first-exploit time or a
  universal SLA. `tests/kev-ransomware.test.ts` pins the 1/0/NULL matrix, the
  legacy alias, the all-missing null shape, and the absence of negated
  ransomware wording.

- **KEV block labels, tri-state copy, and Playwright coverage (E2).** The
  expanded Priority row's KEV block renders a labeled row per catalog fact
  instead of one sentence: membership `Listed` / `Not listed`, `Date added
(catalog)`, `Due date (catalog, federal context)`, `Required action`
  (catalog-supplied and wrapped), `Ransomware campaign use`, `Catalog name`, and
  `CWEs` as monospace ID chips. The block branches on `ransomwareUse`, so the
  three catalog states render distinctly — `Known (catalog)`, `Unknown
(catalog)` (the catalog's own value), `Not stated` (the field was absent) —
  and the legacy `ransomwareKnown` boolean is no longer read by the UI. No state
  is negated: "no ransomware", "not ransomware", and "no known ransomware"
  never render. Absent fields say `Not provided` (never blank), the block's
  HelpTip states that KEV is catalog membership evidence rather than
  first-exploitation time or a universal SLA, and the block holds at 360px/200%
  in both themes with a 44px keyboard-reachable HelpTip. Playwright seeds
  known/unknown/unstated KEV rows and pins the exact labels, the banned phrases,
  the focus-only HelpTip path, and the narrow dark layout.

- **Secondary CVSS projection (`cvssSecondary`).** Every preserved metric the
  primary selector did not pick is now exposed on `CveItem` as one bounded,
  labeled block instead of being dropped. The projection hides the shape
  decisions behind a single pure function (`src/lib/cvss-projection.ts`): it
  excludes the metric `cvssPrimary` selected, orders the rest ADP before CNA,
  then version preference 4.0 > 3.1 > 3.0 > 2.0, then base score descending on
  exact decimal text, then stored source order; it caps the block at four
  metrics, skips malformed scores instead of rendering them, and labels every
  entry `secondary (context only)`. `coverageNote` states in prose that the
  metrics are not used for ranking or eligibility. **Ranking and eligibility are
  untouched**: severity bands, ordering, filters, and the new-critical cohort
  still read the primary selection alone, and `cvssPrimary` keeps its exact
  previous shape. `hasAdp` stays on the record as a compatibility alias.
  Tests cover the ADP-only, CNA+ADP (primary excluded), multi-ADP ordering and
  cap, legacy-only, none, malformed-value, and determinism cases, plus an API
  shape assertion that `cvssSecondary` is additive and `cvssPrimary` unchanged.

### Documentation

- Reconciled the standards, the API docs, and the v3 plan with shipped behaviour: the `app/api/v1/_lib/shared.ts` split, the CWE ingest's own `parseCsvRows` (not `parseEpssCsv`), `hasAdp` kept as a deprecated alias, the `cvssSecondary` scope, and export-mode `q`/`vendor`. No behaviour change.

### Upgrade notes

- **Migration 009 applies on the next write open** of the database (the first
  boot or cycle after upgrading). There is no manual migration step and no
  downtime beyond a normal restart.
- **The aggregate cache version is now v6**, so the first cycle after upgrading
  performs one full refresh. Expect one slower first render; later page loads
  use the refreshed cached snapshot as before.
- **The CWE catalog is fetched once on the first cycle** — a ~644 KB download of
  the pinned MITRE `1000.csv.zip` — and is hash-conditional afterwards (one
  conditional request per 24 h). `CWE_REFRESH_ENABLED=false` skips the fetch, and
  the UI stays readable with ids only.
- **The checkpoint writer starts producing one row per UTC date**, so Change
  Radar, Replay, and the feed have no history before the first day of running
  3.0.0. History accumulates from that date forward.

## 2.0.2 — 2026-11-11

Two operational bugs found while verifying the 2.0.1 release on a running
instance. Both made the console degrade silently rather than fail loudly.

### Fixed

- **Scheduled cycles never refreshed the aggregate cache.** Only the boot cycle
  called the refresh, so after the first hourly cycle the cached snapshot no
  longer matched the accepted data; pages rejected it and every overview render
  fell back to live full-corpus queries (4.3 s instead of 0.28 s) until the next
  restart. The scheduler now reports every settled cycle through
  `onCycleComplete`, and the worker refreshes from there — including cycles where
  one source failed, because the sources that succeeded still moved the data.
- **The cache freshness check compared the wrong revision.** It used
  `MAX(source_revision)` over `cve_records`, which is a lexicographic coincidence
  after an incremental import (only touched rows carry the new revision), and the
  snapshot had the same flaw. Both now use the acceptance ledger (`sync_runs`),
  and the snapshot records the accepted CVE revision, KEV version, SSVC revision
  and EPSS score date. Aggregate cache version 5.
- **A stale `git` lock could freeze the CVE feed indefinitely.** A process killed
  mid-fetch (deploy, OOM) leaves `.git/*.lock` behind and every later fetch fails
  with "Another git process seems to be running". The importer now clears locks
  older than the fetch timeout before retrying, and reports it
  (`cve-cache-lock-cleared`). This is what left the corpus frozen for a day on
  2026-11-10.

### Notes

- The instance that exposed these had been running since 2.0.1: 402k → 405k
  records were waiting in the fetched git cache while the feed reported failures.

## 2.0.1 — 2026-11-08

Storage and operations follow-up to 2.0.0, plus the fixes found while rehearsing
the release.

### Changed

- **EPSS history is ~40% smaller and the window is a stated budget.** Migration
  008 rebuilds `epss_daily` as `WITHOUT ROWID` with the primary key ordered
  `(score_date, cve_id, model_version)`, so the clustered key replaces the
  separate covering index. Measured on the production data: 935 MB → 599 MB
  (62.3 → 39.9 MB per day), with identical query plans.
- **`EPSS_RETENTION_DAYS` default 90 → 45** (and the per-record history cap
  moves with it). Six weeks of trend with a month of margin over what the
  sparkline and the 7-day rising delta need; ~1.8 GB instead of ~5.6 GB.
- The methodology page, the environment reference and the backup runbook state
  the new arithmetic.

### Fixed

- The restore drill is now a documented command (`RUN_RESTORE_ONCE`,
  `RESTORE_DIR`) and was rehearsed end to end: a 639 MB verified backup restored
  into a throwaway volume (402,045 records, 5.6M EPSS rows), served every page,
  and `/api/v1/health` reported all four sources current.
- Nonce-based CSP for page HTML (from the 2.0.0 audit), with the watch-list write
  moved out of a React state updater so unwatching no longer restores the old
  list.

### Upgrade notes

- Migration 008 rebuilds the EPSS table once on the first write open (~20-30 s
  for 6M rows on the reference host). The file does not shrink; freed pages are
  reused by later imports, which is what keeps the steady state at ~40 MB/day.
- Nothing else changes shape: no API, no query, no ranking behaviour.

## 2.0.0 — 2026-11-08

Second product release. Four new evidence surfaces, a fourth upstream feed, and an
ingestion/operations overhaul measured on a 402k-record corpus.

### Added — data and evidence

- **CISA SSVC enrichment (fourth feed).** CISA Vulnrichment decision points are
  ingested verbatim (never merged into a composite) and exposed as an `ssvc`
  block on every record plus an `ssvc-active` priority view.
- **Exploit-tagged references.** The CVE record's own references tagged `exploit`
  (CNA _and_ the ADP array) become a first-class signal: a stored flag, corpus
  coverage on the overview (`46,463 tagged · 259 also KEV`), an
  `exploit ref` badge on Priority, Search and Watch rows with the linked
  references, an Explore filter (`?exploit=tagged`) and an API parameter.
  The label is explicit everywhere: a publisher classification, never a verified
  proof of exploitation.
- **Time-to-exploitation Sankey.** Publication cohort → days until KEV
  confirmation, with pinned selections, node drill-down, per-flow counts and
  shares, and a flow dialog that lists the records.
- **Publication volume by month, week and day**, each with its own honest window
  (12/24 months, 26/52 weeks, 30/90 days).
- **Relation graph rebuild:** bipartite CVE → attribute → records, deterministic
  layout, drill-down dialog with filter/sort/paging.
- **Fastest confirmations** card with the delay metric and both dates.
- **Browser-private watch list** (localStorage only, no accounts, no server
  record) and a **dark theme**.

### Changed — ingestion and operations

- **Upstream ref resolution fixed.** `git fetch` moves the remote-tracking ref,
  not the local branch; the importer now follows `refs/remotes/origin/<branch>`.
  Before this, the corpus sat 11 days behind while logging successful fetches.
- **Import cost:** content receipts are the git tree id (no 4.3 GB re-hash),
  FTS deletes go by rowid (an UNINDEXED `cve_id` delete scanned 396k documents
  per update, ~50 minutes for one 17.5k-record catch-up), KEV reads the corpus
  once per import instead of once per catalog entry, identical EPSS CSVs are not
  re-inserted, and every import logs `cve-import-phase` timings.
- **EPSS retention window** (`EPSS_RETENTION_DAYS`, default 90 days, matching the
  API's per-record history cap), pruned inside the import, with the window and
  the oldest retained date stated on the methodology page.
- **Aggregate cache freshness:** the worker refreshes when the accepted EPSS date
  or CVE revision moves, not only when the cache is empty (stale cache made every
  overview render fall back to live full-corpus queries: 4.2 s vs 0.26 s).
- **Restore drill as a command** (`RUN_RESTORE_ONCE` / `RESTORE_DIR`) and a
  rehearsed drill documented with its numbers.
- Dropped a redundant EPSS index (`idx_epss_daily_score_date`): identical query
  plans, ~180 MB and one index update per inserted row saved.

### Security

- **Nonce-based Content-Security-Policy** on page HTML
  (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`,
  `frame-ancestors 'none'`, `base-uri 'self'`); API responses keep their stricter
  `default-src 'none'` policy. `style-src` keeps `'unsafe-inline'` because React
  writes inline style attributes for chart geometry.
- API hardening carried over: rate limiting with headers, XFF handling, bounded
  parameters, parameterized SQL, `nosniff`/`DENY`/`no-referrer`/Permissions-Policy.

### Fixed

- Watch list could silently lose a change: the `localStorage` write lived inside
  a React state updater, so the double invocation restored the pre-toggle list.
- Exploit tags in `containers.adp` were dropped (the field is an array, and the
  extractor treated it as an object), so a badge could appear without its link.
- `dataDir: ":memory:"` created a literal `:memory:` directory instead of using
  SQLite's in-memory database.
- Test suite: the benchmark no longer rewrites a committed evidence file on every
  run; several order-dependent specs were made deterministic.

### Upgrade notes

- Migrations 005–007 apply automatically on the first write open. Migration 005
  rebuilds the full-text index once (≈400k documents); migration 007 drops the
  redundant EPSS index.
- New optional environment variables: `EPSS_RETENTION_DAYS` (default 90),
  `SSVC_REPO_DIR`.
- API: `/api/v1` unchanged in shape; additions are `ssvc`,
  `exploitReferenceStatus`/`exploitReferences` and the `?exploit=tagged` filter.

## 1.0.0 — 2026-10-28

First public release: CVE List V5 + CISA KEV + FIRST EPSS ingestion, explainable
priority lists (no composite score), Change Radar and retained-snapshot replay,
search with filters, a versioned read-only API with OpenAPI docs, nightly verified
backups, Apache-2.0 licence.
