-- 001_initial up: versioned CVE radar schema with FTS5.
--
-- Shapes persisted here follow src/lib/ingestion-types.ts (CVE record state,
-- dataVersion, KEV dateAdded, EPSS probability/percentile) and
-- src/lib/retention-types.ts (checkpoint manifests with source pins, cohort,
-- policy version, materialized results; reference-counted baseline retention).
-- Exact decimals (EPSS probability/percentile, CVSS base scores) are stored
-- as TEXT so no binary floating point rounding ever touches a comparison;
-- ordering code compares the stored decimal strings exactly.

-- CVE records: current accepted corpus. Only state = 'PUBLISHED' rows feed
-- default search and ranked views; 'REJECTED' rows are retained for
-- provenance and excluded from ordinary lists/counts.
CREATE TABLE cve_records (
  cve_id TEXT PRIMARY KEY,
  data_version TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('PUBLISHED', 'REJECTED')),
  date_published TEXT NULL,
  date_updated TEXT NULL,
  title TEXT NULL,
  description TEXT NOT NULL DEFAULT '',
  description_lang TEXT NULL,
  source_revision TEXT NULL,
  raw_json TEXT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

-- Every supplied CVSS metric is preserved; the primary-metric editorial
-- selection (CNA-only, version preference, worst scenario) is computed by
-- the ranking service, never by dropping rows here.
CREATE TABLE cvss_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL REFERENCES cve_records (cve_id) ON DELETE CASCADE,
  origin TEXT NOT NULL CHECK (origin IN ('CNA', 'ADP')),
  version TEXT NOT NULL,
  base_score TEXT NOT NULL,
  vector TEXT NOT NULL DEFAULT '',
  source_order INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX idx_cvss_metrics_cve_id ON cvss_metrics (cve_id);

-- Dated EPSS observations. A missing row for the accepted score date is
-- unknown, never zero; cross-model comparisons are ineligible, so the model
-- version is part of the key.
CREATE TABLE epss_daily (
  cve_id TEXT NOT NULL,
  score_date TEXT NOT NULL,
  model_version TEXT NOT NULL,
  epss TEXT NOT NULL,
  percentile TEXT NOT NULL,
  PRIMARY KEY (cve_id, score_date, model_version)
) STRICT;

CREATE INDEX idx_epss_daily_score_date ON epss_daily (score_date, model_version);

-- Current KEV membership: one row per listed CVE, replaced atomically on
-- each validated catalog snapshot. Removal means "not in the new catalog",
-- never "never exploited"; history lives in kev_history.
CREATE TABLE kev_entries (
  cve_id TEXT PRIMARY KEY,
  date_added TEXT NOT NULL,
  catalog_date TEXT NOT NULL,
  vendor_project TEXT NULL,
  product TEXT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

-- KEV membership history, kept separate from the current flag.
CREATE TABLE kev_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  date_added TEXT NOT NULL,
  catalog_date TEXT NOT NULL,
  removed_in_catalog TEXT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_kev_history_cve_id ON kev_history (cve_id);

-- Per-source import attempts. A successful import is the only event that
-- advances an import checkpoint; failures keep last-known-good data.
CREATE TABLE sync_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('cve', 'kev', 'epss')),
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  revision TEXT NULL,
  content_hash TEXT NULL,
  error TEXT NULL
) STRICT;

CREATE INDEX idx_sync_runs_source ON sync_runs (source, started_at);

-- Daily observed checkpoints: the retained manifest that Radar diffs and
-- snapshot replay reproduce from. Replay reuses these pins plus the pinned
-- policy implementation; it never substitutes current data.
CREATE TABLE checkpoints (
  checkpoint_date TEXT PRIMARY KEY,
  observed_at TEXT NOT NULL,
  cve_revision TEXT NOT NULL,
  kev_catalog_date TEXT NOT NULL,
  epss_score_date TEXT NOT NULL,
  epss_model_version TEXT NOT NULL,
  cohort_id TEXT NOT NULL,
  cohort_count INTEGER NOT NULL,
  policy_version TEXT NOT NULL,
  materialized_results_json TEXT NOT NULL DEFAULT '[]',
  manifest_hash TEXT NULL,
  created_at TEXT NOT NULL
) STRICT;

-- Reference-counted baseline retention: a baseline row survives while at
-- least one retained checkpoint references it.
CREATE TABLE checkpoint_baseline_refs (
  baseline_id TEXT NOT NULL,
  checkpoint_date TEXT NOT NULL REFERENCES checkpoints (checkpoint_date) ON DELETE CASCADE,
  retained_at TEXT NOT NULL,
  PRIMARY KEY (baseline_id, checkpoint_date)
) STRICT;

CREATE INDEX idx_baseline_refs_checkpoint ON checkpoint_baseline_refs (checkpoint_date);

-- Provenance tombstones for deleted/changed-away records so Radar can
-- explain removals instead of silently dropping them.
CREATE TABLE cve_tombstones (
  cve_id TEXT PRIMARY KEY,
  last_state TEXT NOT NULL,
  removed_in_revision TEXT NULL,
  reason TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

-- Full-text index over supplied titles and descriptions. CVE IDs, vendor
-- labels, and nicknames are NOT promised here; this index covers record
-- text only. UNINDEXED cve_id keeps the ID out of the token stream while
-- still storing it for result mapping.
CREATE VIRTUAL TABLE cve_fts USING fts5(
  cve_id UNINDEXED,
  title,
  description,
  tokenize = 'porter'
);

-- Keep the FTS index in lockstep with the records table. Triggers use the
-- new/old row values directly; no query text is ever interpolated.
CREATE TRIGGER trg_cve_records_ai AFTER INSERT ON cve_records BEGIN
  INSERT INTO cve_fts (cve_id, title, description)
  VALUES (NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;

CREATE TRIGGER trg_cve_records_ad AFTER DELETE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE cve_id = OLD.cve_id;
END;

CREATE TRIGGER trg_cve_records_au AFTER UPDATE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE cve_id = OLD.cve_id;
  INSERT INTO cve_fts (cve_id, title, description)
  VALUES (NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;
