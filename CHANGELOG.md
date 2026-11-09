# Changelog

All notable changes to Kevelry (package/image `cve-change-radar`). The public API
is versioned separately at `/api/v1`; every API change in 2.0.0 is additive.

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
