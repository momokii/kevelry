-- Align the FTS index with cve_records.rowid and delete through the FTS5
-- 'delete' command.
--
-- The original triggers ran `DELETE FROM cve_fts WHERE cve_id = OLD.cve_id`.
-- cve_id is an UNINDEXED FTS5 column, so that predicate cannot use an index:
-- SQLite scans every document in the virtual table. Measured on the production
-- volume: one such lookup took 175 ms at 396k documents, so a 17.5k-record
-- incremental import spent ~50 minutes deleting index entries. The FTS5
-- rowid lookup removes a document in time proportional to the document, which
-- is what the triggers below use. (The FTS5 'delete' command would be the
-- alternative, but it only exists for contentless/external-content tables; this
-- table stores its own text so search keeps offering snippets.)
--
-- This requires the FTS rowid to equal cve_records.rowid, so the table is
-- rebuilt from the records table once here.

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
  INSERT INTO cve_fts (rowid, cve_id, title, description)
  VALUES (NEW.rowid, NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;

CREATE TRIGGER trg_cve_records_ad AFTER DELETE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE rowid = OLD.rowid;
END;

CREATE TRIGGER trg_cve_records_au AFTER UPDATE ON cve_records BEGIN
  DELETE FROM cve_fts WHERE rowid = OLD.rowid;
  INSERT INTO cve_fts (rowid, cve_id, title, description)
  VALUES (NEW.rowid, NEW.cve_id, COALESCE(NEW.title, ''), NEW.description);
END;

INSERT INTO cve_fts (rowid, cve_id, title, description)
SELECT rowid, cve_id, COALESCE(title, ''), description FROM cve_records;
