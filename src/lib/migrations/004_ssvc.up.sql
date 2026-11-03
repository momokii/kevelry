-- 004_ssvc up: CISA Vulnrichment SSVC decision points.
--
-- Additive only: one new table, no column changes, no rewrites. Rows arrive
-- from the vulnrichment repository for KEV-listed CVE ids only; a record with
-- no published SSVC stays absent (missing), never defaulted to a value.
--
-- The three columns store CISA's published decision points verbatim:
--   exploitation: "none" | "poc" | "active"
--   automatable:  "yes" | "no"
--   technical_impact: "partial" | "total"
-- They are stored separately on purpose: this product never folds them into a
-- single score of its own.

CREATE TABLE IF NOT EXISTS ssvc_records (
  cve_id TEXT PRIMARY KEY,
  exploitation TEXT NOT NULL CHECK (exploitation IN ('none', 'poc', 'active')),
  automatable TEXT NOT NULL CHECK (automatable IN ('yes', 'no')),
  technical_impact TEXT NOT NULL CHECK (technical_impact IN ('partial', 'total')),
  ssvc_version TEXT NULL,
  source_timestamp TEXT NULL,
  catalog_date TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ssvc_exploitation
  ON ssvc_records (exploitation, technical_impact, cve_id);

-- `sync_runs.source` was constrained to the original three feeds. SQLite
-- cannot alter a CHECK constraint in place, so rebuild that small table with
-- the constraint widened. Rows are copied verbatim; nothing is dropped.
CREATE TABLE sync_runs_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('cve', 'kev', 'epss', 'ssvc')),
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  revision TEXT NULL,
  content_hash TEXT NULL,
  error TEXT NULL
) STRICT;

INSERT INTO sync_runs_new (id, source, started_at, finished_at, status, revision, content_hash, error)
  SELECT id, source, started_at, finished_at, status, revision, content_hash, error FROM sync_runs;

DROP TABLE sync_runs;
ALTER TABLE sync_runs_new RENAME TO sync_runs;
CREATE INDEX IF NOT EXISTS idx_sync_runs_source ON sync_runs (source, started_at);
