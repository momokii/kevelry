-- Restore the index the 001 migration shipped. The covering index from 002
-- already serves these reads; this exists only for a rollback to a build that
-- expects it.

CREATE INDEX IF NOT EXISTS idx_epss_daily_score_date ON epss_daily (score_date, model_version);
