-- 012_ai_usage_unmetered: an unpriced turn is unknown spend, not free spend.
--
-- 011 recorded a turn whose gateway usage block omitted `list_cost` as 0 USD. A
-- zero is indistinguishable from a genuinely free turn, so a gateway that
-- silently stopped reporting cost made the daily money cap unreachable: the
-- ledger read "spent nothing" while the provider billed every request.
--
-- This migration adds the counter that makes the two cases distinguishable.
-- `list_cost` keeps its meaning (known spend, summed as before) and
-- `unmetered_requests` counts the turns whose cost was unknown. The ledger fails
-- closed on that count: after ten unpriced turns in one UTC day the daily budget
-- reads exhausted, because a budget that cannot be totalled is not a budget.
--
-- Additive: one column, default 0, no backfill, no fact-table change. Existing
-- rows are known-cost rows by construction, so 0 is the correct default for them.

ALTER TABLE ai_usage
  ADD COLUMN unmetered_requests INTEGER NOT NULL DEFAULT 0 CHECK (unmetered_requests >= 0);
