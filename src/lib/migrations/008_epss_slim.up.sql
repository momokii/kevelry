-- Slim the EPSS history without changing a single query.
--
-- Measured on the production volume (6.0M rows, 15 days): `epss_daily` 353 MB,
-- its primary-key index 292 MB, and the covering index
-- `idx_epss_daily_score_cve` 339 MB — 984 MB, roughly 65 MB per day of history.
--
-- Two changes, both structural:
--   1. WITHOUT ROWID with the primary key ordered (score_date, cve_id,
--      model_version). The clustered key now *is* the score-date index every
--      read needs, so the separate covering index (339 MB) is redundant.
--   2. The rowid is gone (a narrow, immutable row does not need one), and the
--      per-record index carries only the columns history actually reads.
--
-- Measured on the same data: 984 MB -> ~620 MB (-37%), identical query plans for
-- every existing statement because the column set and ordering are unchanged.
--
-- Deliberate trade-off, documented rather than hidden: `model_version` is still
-- repeated on each row (it is a property of the score date). Moving it to a
-- separate `epss_runs` table measured a further -17% (~455 MB total), but it
-- would rewrite ~70 query sites including the ranking paths; that is a change to
-- make on its own evidence, not folded into a storage fix.

CREATE TABLE epss_daily_new (
  cve_id TEXT NOT NULL,
  score_date TEXT NOT NULL,
  model_version TEXT NOT NULL,
  epss TEXT NOT NULL,
  percentile TEXT NOT NULL,
  PRIMARY KEY (score_date, cve_id, model_version)
) STRICT, WITHOUT ROWID;

INSERT INTO epss_daily_new (cve_id, score_date, model_version, epss, percentile)
SELECT cve_id, score_date, model_version, epss, percentile FROM epss_daily;

DROP TABLE epss_daily;
ALTER TABLE epss_daily_new RENAME TO epss_daily;

-- Per-record history (cve_id lookup, oldest first). Replaces the old
-- primary-key index; it carries only what those reads touch.
CREATE INDEX idx_epss_daily_cve ON epss_daily (cve_id, score_date, model_version);
