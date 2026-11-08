-- Restore the 001 shape: cve_id-keyed triggers that delete by scanning.
-- Only useful for a rollback to a build that expects the old predicates.

DROP TRIGGER IF EXISTS trg_cve_records_ai;
DROP TRIGGER IF EXISTS trg_cve_records_ad;
DROP TRIGGER IF EXISTS trg_cve_records_au;
DROP TABLE IF EXISTS cve_fts;

CREATE VIRTUAL TABLE cve_fts USING fts5(
  cve_id UNINDEXED,
  title,
  description,
  tokenize = 'porter'
);

CREATE TRIGGER trg_cve_records_ai AFTER INSERT ON cve_records BEGIN
  INSERT INTO cve_fts (cve_id, title, description)
  VALUES (NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;

CREATE TRIGGER trg_cve_records_ad AFTER DELETE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE rowid = OLD.rowid;
END;

CREATE TRIGGER trg_cve_records_au AFTER UPDATE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE rowid = OLD.rowid;
  INSERT INTO cve_fts (cve_id, title, description)
  VALUES (NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;

INSERT INTO cve_fts (cve_id, title, description)
SELECT cve_id, COALESCE(title, ''), description FROM cve_records;
