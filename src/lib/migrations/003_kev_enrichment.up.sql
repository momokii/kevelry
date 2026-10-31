-- 003_kev_enrichment up: additive KEV evidence columns + CWE link table.
--
-- Safe on a live volume: only ADD COLUMN (nullable, no backfill) and one new
-- table. Existing rows read NULLs until the next hourly KEV import fills
-- them; nothing is rewritten, no trigger changes. kev_history keeps its
-- append-only shape (current-table evidence only; replay reads checkpoints,
-- never these columns).

ALTER TABLE kev_entries ADD COLUMN due_date TEXT NULL;
ALTER TABLE kev_entries ADD COLUMN required_action TEXT NULL;
ALTER TABLE kev_entries ADD COLUMN vulnerability_name TEXT NULL;
ALTER TABLE kev_entries ADD COLUMN ransomware_known INTEGER NULL;

-- KEV-advertised CWE identifiers per entry (from the catalog `cwes` array).
-- Separate table (not a packed string) so the future weakness lens can join
-- it; capped at import time (see kev-import.ts).
CREATE TABLE IF NOT EXISTS kev_cwes (
  cve_id TEXT NOT NULL,
  cwe_id TEXT NOT NULL,
  PRIMARY KEY (cve_id, cwe_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_kev_cwes_cwe ON kev_cwes (cwe_id, cve_id);
CREATE INDEX IF NOT EXISTS idx_kev_entries_due ON kev_entries (due_date, cve_id);
