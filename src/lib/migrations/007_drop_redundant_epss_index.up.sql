-- Drop a redundant index on the append-only EPSS history.
--
-- `idx_epss_daily_score_date (score_date, model_version)` was created in 001
-- before the covering index from 002 existed. `idx_epss_daily_score_cve
-- (score_date, cve_id, model_version, epss)` has the same leading column and
-- serves every query that filters by score date — measured on the production
-- volume (5.2M rows): identical query plans and identical timing (50 ms vs
-- 51 ms) for the aggregate and priority reads with and without this index.
--
-- Keeping it cost ~180 MB and one index update per inserted row, and the EPSS
-- importer writes ~400k rows a day.

DROP INDEX IF EXISTS idx_epss_daily_score_date;
