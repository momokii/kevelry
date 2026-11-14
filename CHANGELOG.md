# Changelog

All notable changes to Kevelry (package/image `cve-change-radar`). The public API
is versioned separately at `/api/v1`; every API change in 2.0.0 is additive.

## Unreleased (v3.0.0)

### Added

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
