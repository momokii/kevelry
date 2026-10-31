-- 003_kev_enrichment down: remove only what 003 created.
-- Never touches 001/002 objects or user rows. Dropping the enrichment
-- columns loses only derived KEV evidence (re-imported on next cycle).

DROP TABLE IF EXISTS kev_cwes;
DROP INDEX IF EXISTS idx_kev_cwes_cwe;
DROP INDEX IF EXISTS idx_kev_entries_due;
ALTER TABLE kev_entries DROP COLUMN ransomware_known;
ALTER TABLE kev_entries DROP COLUMN vulnerability_name;
ALTER TABLE kev_entries DROP COLUMN required_action;
ALTER TABLE kev_entries DROP COLUMN due_date;
