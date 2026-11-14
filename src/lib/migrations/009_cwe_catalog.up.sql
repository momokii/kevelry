-- Local, versioned CWE taxonomy catalog (additive; no fact-table changes).
--
-- CWE labels are reference data: infrequently updated, versioned upstream, and
-- joined by ID onto records that already carry `cwe_id` strings. Keeping it in
-- its own tables means a taxonomy refresh never rewrites a fact row, and the
-- read path can state its provenance (version/hash/date) independently.
--
-- `cwe_catalog_meta` is a one-row pointer to the accepted catalog: id is
-- pinned to 1 so a re-load replaces the pointer atomically instead of leaving
-- two "current" rows. `status` is the read-path contract: only `ready` serves
-- entries; `stale`/`unavailable` are recorded by the importer when a refresh
-- fails and the previous accepted catalog must not be presented as current.
--
-- `cwe_entries` is keyed by the normalized `CWE-<n>` id, so a point lookup is
-- the primary-key seek and no extra index is needed. Row count is bounded by
-- the published taxonomy (tens of thousands at most).

CREATE TABLE cwe_catalog_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  source TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  retrieved_at TEXT NOT NULL,
  status TEXT NOT NULL,
  record_count INTEGER NOT NULL,
  notes TEXT NULL
) STRICT;

CREATE TABLE cwe_entries (
  cwe_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  abstraction TEXT NULL,
  status TEXT NULL,
  summary TEXT NULL,
  mitigation TEXT NULL,
  version TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
