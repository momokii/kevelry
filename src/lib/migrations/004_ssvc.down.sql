-- 004_ssvc down: remove only what 004 created.
-- Dropping the table discards derived enrichment only; the next import
-- repopulates it from the same upstream repository.

DROP TABLE IF EXISTS ssvc_records;

-- Widen-then-narrow: rows for the added source are removed before the
-- original CHECK is restored, so the down migration cannot fail on them.
DELETE FROM sync_runs WHERE source = 'ssvc';
CREATE TABLE sync_runs_old (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('cve', 'kev', 'epss')),
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  revision TEXT NULL,
  content_hash TEXT NULL,
  error TEXT NULL
) STRICT;
INSERT INTO sync_runs_old (id, source, started_at, finished_at, status, revision, content_hash, error)
  SELECT id, source, started_at, finished_at, status, revision, content_hash, error FROM sync_runs;
DROP TABLE sync_runs;
ALTER TABLE sync_runs_old RENAME TO sync_runs;
CREATE INDEX IF NOT EXISTS idx_sync_runs_source ON sync_runs (source, started_at);
