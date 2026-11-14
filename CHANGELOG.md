# Changelog

All notable changes to Kevelry (package/image `cve-change-radar`). The public API
is versioned separately at `/api/v1`; every API change in 2.0.0 is additive.

## Unreleased (v3.0.0)

### Added

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
  maintenance that is *not* a scheduler source (it cannot contribute to
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
