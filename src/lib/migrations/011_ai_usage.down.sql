-- Revert 011: the assistant's spend ledger was additive, so dropping the table
-- restores the 010 schema exactly. No fact table was touched.

DROP TABLE ai_usage;
