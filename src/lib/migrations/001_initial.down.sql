-- 001_initial down: full reversal of the 001_initial up migration.
-- Drops the FTS triggers first, then the FTS table, then base tables in
-- reverse dependency order. schema_migrations bookkeeping is handled by
-- the runner, not by this script.

DROP TRIGGER IF EXISTS trg_cve_records_au;
DROP TRIGGER IF EXISTS trg_cve_records_ad;
DROP TRIGGER IF EXISTS trg_cve_records_ai;
DROP TABLE IF EXISTS cve_fts;
DROP TABLE IF EXISTS cve_tombstones;
DROP TABLE IF EXISTS checkpoint_baseline_refs;
DROP TABLE IF EXISTS checkpoints;
DROP TABLE IF EXISTS sync_runs;
DROP TABLE IF EXISTS kev_history;
DROP TABLE IF EXISTS kev_entries;
DROP TABLE IF EXISTS epss_daily;
DROP TABLE IF EXISTS cvss_metrics;
DROP TABLE IF EXISTS cve_records;
