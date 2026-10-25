-- 002_perf_cache down: remove only what 002 created.
-- Never touches 001 objects or user rows.

DROP TABLE IF EXISTS aggregate_cache;
DROP INDEX IF EXISTS idx_cve_records_published_date;
DROP INDEX IF EXISTS idx_epss_daily_score_cve;
DROP INDEX IF EXISTS idx_cvss_metrics_cve_origin_version;
DROP INDEX IF EXISTS idx_cve_records_source_revision;
DROP INDEX IF EXISTS idx_cve_records_state_published;
-- Superseded draft names from earlier 002 revisions (redundant with the
-- cve_records primary key or removed to protect the FTS-first plan);
-- harmless when absent.
DROP INDEX IF EXISTS idx_kev_entries_cve;
DROP INDEX IF EXISTS idx_cve_records_state_cve;
