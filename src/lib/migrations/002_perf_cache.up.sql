-- 002_perf_cache up: additive read-path indexes and aggregate cache.
--
-- Safe on a live 4.3GB volume: only CREATE INDEX IF NOT EXISTS and one new
-- table. No column changes, no data rewrites, no trigger changes. Index
-- builds scan but never mutate user rows; writers keep working (brief lock
-- while each index commits).
--
-- The covering indexes below are the whole point: the hot paths scan
-- cve_records (which carries multi-KB raw_json blobs), epss_daily and
-- cvss_metrics once per request. Covering the queried columns keeps those
-- scans index-only so a warm request never touches heap blobs.

-- Column order invariant: date-first covering keeps GROUP BY scans
-- index-only without offering a (state AND cve_id) probe. A state-first
-- covering index flips FTS search to per-row FTS probes (minutes, not ms).
CREATE INDEX IF NOT EXISTS idx_cve_records_state_published
  ON cve_records (date_published, state, cve_id);

CREATE INDEX IF NOT EXISTS idx_cve_records_source_revision
  ON cve_records (source_revision);

CREATE INDEX IF NOT EXISTS idx_cvss_metrics_cve_origin_version
  ON cvss_metrics (cve_id, source_order, origin, version, base_score, vector);

CREATE INDEX IF NOT EXISTS idx_epss_daily_score_cve
  ON epss_daily (score_date, cve_id, model_version, epss);

-- Predicate-matched partial index for the hot published-corpus listings:
-- WHERE state = 'PUBLISHED' ORDER BY date DESC, cve_id scans in index
-- order with no sort and no heap touch. The general covering index above
-- cannot serve that ordering once the state filter breaks contiguity.
CREATE INDEX IF NOT EXISTS idx_cve_records_published_date
  ON cve_records (date_published DESC, cve_id ASC) WHERE state = 'PUBLISHED';

-- Precomputed read-model for the hot paths (overview page, /overview,
-- /status, /health). One row per cache key; writers only replace values via
-- refreshAggregates() after a successful import cycle. Readers fall back to
-- live queries when a key is absent, so an empty cache is never an outage.
CREATE TABLE IF NOT EXISTS aggregate_cache (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  source_revision TEXT NULL,
  epss_score_date TEXT NULL
) STRICT;
