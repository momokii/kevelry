-- Revert 009: remove the local CWE catalog. Fact tables were never touched, so
-- dropping both catalog tables restores the 008 schema exactly.

DROP TABLE cwe_entries;
DROP TABLE cwe_catalog_meta;
