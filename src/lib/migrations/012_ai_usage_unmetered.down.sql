-- Revert 012: drop the unpriced-turn counter.
--
-- The counter records "this turn's cost was unknown"; dropping it re-states 011's
-- behaviour of recording such a turn as 0 USD. Known spend in `list_cost` is
-- untouched, so no money fact is lost or invented.

ALTER TABLE ai_usage DROP COLUMN unmetered_requests;
