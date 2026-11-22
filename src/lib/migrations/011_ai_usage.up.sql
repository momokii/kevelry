-- 011_ai_usage: the assistant's spend ledger.
--
-- A budget that lives only in process memory resets on every restart, deploy
-- and crash, which makes it a lie: a loop of restarts would be a loop of free
-- tokens. One row per UTC day is enough to answer the only two questions the
-- guardrails ask — "how much has today cost?" and "has the daily cap been
-- reached?" — and it is small enough to rewrite on every turn.
--
-- `day` is the UTC date (`YYYY-MM-DD`), the same bucket basis as checkpoints.
-- `created_at` is the first write for the day; the aggregate columns are
-- incremented in place. Nothing here stores a prompt, an answer, an IP or a
-- session: the ledger is spend, not telemetry.
--
-- `list_cost` is USD from the gateway's `usage.opencode.list_cost`. A gateway
-- that omits the field records 0 rather than failing the turn; the plan's
-- "unknown cost" column is deliberately not part of this phase's schema.
--
-- Additive: no backfill, no fact-table change, no read-contract change.

CREATE TABLE ai_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  day TEXT NOT NULL UNIQUE,
  requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
  prompt_tokens INTEGER NOT NULL DEFAULT 0 CHECK (prompt_tokens >= 0),
  completion_tokens INTEGER NOT NULL DEFAULT 0 CHECK (completion_tokens >= 0),
  reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_tokens >= 0),
  cache_read_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
  list_cost REAL NOT NULL DEFAULT 0 CHECK (list_cost >= 0),
  created_at TEXT NOT NULL
) STRICT;
