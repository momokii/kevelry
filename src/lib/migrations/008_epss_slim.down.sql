-- Restore the 001 shape: rowid table, primary key on cve_id, covering index.

CREATE TABLE epss_daily_old (
  cve_id TEXT NOT NULL,
  score_date TEXT NOT NULL,
  model_version TEXT NOT NULL,
  epss TEXT NOT NULL,
  percentile TEXT NOT NULL,
  PRIMARY KEY (cve_id, score_date, model_version)
) STRICT;

INSERT INTO epss_daily_old (cve_id, score_date, model_version, epss, percentile)
SELECT cve_id, score_date, model_version, epss, percentile FROM epss_daily;

DROP INDEX IF EXISTS idx_epss_daily_cve;
DROP TABLE epss_daily;
ALTER TABLE epss_daily_old RENAME TO epss_daily;
CREATE INDEX idx_epss_daily_score_cve ON epss_daily (score_date, cve_id, model_version, epss);
