-- 010_sync_run_interrupted up: an abandoned run gets its own status.
--
-- A process killed mid-import never closes its `sync_runs` row, so the row stays
-- 'running' forever and a hung import reads exactly like a ledger nobody swept.
-- The boot sweep (src/lib/sync-run-sweep.ts) marks rows older than two hours
-- 'interrupted'; it never deletes them and never rewrites their timestamps.
--
-- SQLite cannot widen a CHECK in place, so the table is rebuilt with the status
-- list extended. Rows are copied verbatim and the source CHECK keeps 'ssvc' from
-- migration 004. Nothing is dropped or reinterpreted.

CREATE TABLE sync_runs_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('cve', 'kev', 'epss', 'ssvc')),
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
  revision TEXT NULL,
  content_hash TEXT NULL,
  error TEXT NULL
) STRICT;

INSERT INTO sync_runs_new (id, source, started_at, finished_at, status, revision, content_hash, error)
  SELECT id, source, started_at, finished_at, status, revision, content_hash, error FROM sync_runs;

DROP TABLE sync_runs;
ALTER TABLE sync_runs_new RENAME TO sync_runs;
CREATE INDEX IF NOT EXISTS idx_sync_runs_source ON sync_runs (source, started_at);
