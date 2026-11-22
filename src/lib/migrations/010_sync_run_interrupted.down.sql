-- 010_sync_run_interrupted down: restore the three-status CHECK.
--
-- The narrower CHECK cannot hold 'interrupted', and deleting those rows would
-- erase ledger history the sweep deliberately preserved. They are recorded as
-- 'failed' instead, keeping their note in `error`, then the table is rebuilt.

UPDATE sync_runs SET status = 'failed' WHERE status = 'interrupted';

CREATE TABLE sync_runs_old (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('cve', 'kev', 'epss', 'ssvc')),
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
