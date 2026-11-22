// The assistant's spend ledger: one aggregate row per UTC day in SQLite.
//
// Two budgets read it. The session budget is a token count carried by the
// current turn loop, so it is a pure comparison; the daily budget is money and
// must be read from storage, not from a module-level counter, because a
// counter resets on restart and a restart must not buy fresh tokens. `day` is
// UTC `YYYY-MM-DD`, the same bucket basis as the checkpoints.
//
// Cost is read from the gateway's `usage.opencode.list_cost` extension field.
// A gateway change can drop it without changing the status code; the research
// note argued an absent cost should be recorded as "unknown", but this phase's
// schema (and task) records it as 0 instead so a missing field never fails a
// completed turn. That is a deliberate, documented deviation.
//
// Nothing here stores prompt text, answers, IPs or session ids.

import type { CveDatabase } from "../db";

/** Token and cost counters from one gateway response. */
export interface AiUsage {
  promptTokens: number;
  completionTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  /** USD list price for the turn; 0 when the gateway omitted `list_cost`. */
  listCostUsd: number;
}

/** One UTC day's aggregate, as stored. */
export interface AiUsageDay {
  day: string;
  requests: number;
  promptTokens: number;
  completionTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  listCostUsd: number;
  createdAt: string;
}

export interface AiUsageBudget {
  sessionBudgetTokens: number;
  dailyBudgetUsd: number;
}

export interface AiUsageLedgerOptions {
  db: CveDatabase;
  budget: AiUsageBudget;
  now?: () => Date;
}

export interface AiUsageLedger {
  /** Records one completed turn against the current UTC day. */
  recordUsage(input: { usage: AiUsage; at?: Date }): AiUsageDay;
  /** Spend for a UTC day; 0 before the first recorded turn. */
  dailyCost(day?: string): number;
  /** True once the day's recorded spend reaches the configured cap. */
  dailyBudgetExceeded(): boolean;
  /** True once this session's tokens reach the configured cap. */
  sessionBudgetExceeded(input: { sessionTokens: number }): boolean;
  /** The stored aggregate for a UTC day, or null when nothing was recorded. */
  readDay(day?: string): AiUsageDay | null;
}

interface AiUsageRow {
  day: string;
  requests: number;
  prompt_tokens: number;
  completion_tokens: number;
  reasoning_tokens: number;
  cache_read_tokens: number;
  list_cost: number;
  created_at: string;
}

/** UTC `YYYY-MM-DD`; the ledger and the checkpoints share this bucket basis. */
export function utcDay(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonNegativeNumber(value: unknown): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return parsed;
}

function nonNegativeInteger(value: unknown): number {
  return Math.trunc(nonNegativeNumber(value));
}

function toUsageDay(row: AiUsageRow): AiUsageDay {
  return {
    day: row.day,
    requests: row.requests,
    promptTokens: row.prompt_tokens,
    completionTokens: row.completion_tokens,
    reasoningTokens: row.reasoning_tokens,
    cacheReadTokens: row.cache_read_tokens,
    listCostUsd: row.list_cost,
    createdAt: row.created_at,
  };
}

/**
 * Reads the gateway `usage` block defensively. It is an OpenAI-shaped object
 * with a gateway-owned `opencode` extension, so every field is optional and an
 * absent or malformed value reads as 0 — never as NaN, which would poison the
 * daily sum.
 */
export function parseUsage(raw: unknown): AiUsage {
  const usage = asRecord(raw) ?? {};
  const completionDetails = asRecord(usage["completion_tokens_details"]);
  const promptDetails = asRecord(usage["prompt_tokens_details"]);
  const opencode = asRecord(usage["opencode"]);
  return {
    promptTokens: nonNegativeInteger(usage["prompt_tokens"]),
    completionTokens: nonNegativeInteger(usage["completion_tokens"]),
    // Observed top-level in probes; the details object is the OpenAI spelling.
    reasoningTokens: nonNegativeInteger(
      usage["reasoning_tokens"] ?? completionDetails?.["reasoning_tokens"],
    ),
    cacheReadTokens: nonNegativeInteger(
      usage["cache_read_tokens"] ?? promptDetails?.["cached_tokens"],
    ),
    // `cost` is 0 on this gateway; only `list_cost` is the billable figure.
    listCostUsd: nonNegativeNumber(opencode?.["list_cost"]),
  };
}

/**
 * Builds the ledger over a database handle. `budget` is captured at
 * construction so the chat path cannot read a different cap per call site.
 */
export function createAiUsageLedger(options: AiUsageLedgerOptions): AiUsageLedger {
  const { db, budget } = options;
  const now = options.now ?? (() => new Date());

  function dayOf(at?: Date): string {
    return utcDay(at ?? now());
  }

  function readDay(day: string): AiUsageDay | null {
    const row = db.handle
      .prepare(
        "SELECT day, requests, prompt_tokens, completion_tokens, reasoning_tokens, " +
          "cache_read_tokens, list_cost, created_at FROM ai_usage WHERE day = ?",
      )
      .get(day) as AiUsageRow | undefined;
    return row === undefined ? null : toUsageDay(row);
  }

  function recordUsage(input: { usage: AiUsage; at?: Date }): AiUsageDay {
    const day = dayOf(input.at);
    const usage = input.usage;
    const createdAt = now().toISOString();
    const recorded = db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO ai_usage (day, requests, prompt_tokens, completion_tokens, " +
            "reasoning_tokens, cache_read_tokens, list_cost, created_at) " +
            "VALUES (@day, 1, @promptTokens, @completionTokens, @reasoningTokens, " +
            "@cacheReadTokens, @listCostUsd, @createdAt) " +
            "ON CONFLICT(day) DO UPDATE SET " +
            "requests = ai_usage.requests + 1, " +
            "prompt_tokens = ai_usage.prompt_tokens + excluded.prompt_tokens, " +
            "completion_tokens = ai_usage.completion_tokens + excluded.completion_tokens, " +
            "reasoning_tokens = ai_usage.reasoning_tokens + excluded.reasoning_tokens, " +
            "cache_read_tokens = ai_usage.cache_read_tokens + excluded.cache_read_tokens, " +
            "list_cost = ai_usage.list_cost + excluded.list_cost",
        )
        .run({
          day,
          promptTokens: nonNegativeInteger(usage.promptTokens),
          completionTokens: nonNegativeInteger(usage.completionTokens),
          reasoningTokens: nonNegativeInteger(usage.reasoningTokens),
          cacheReadTokens: nonNegativeInteger(usage.cacheReadTokens),
          listCostUsd: nonNegativeNumber(usage.listCostUsd),
          createdAt,
        });
      return readDay(day);
    });
    if (recorded === null) {
      throw new Error("ai_usage write succeeded but the day's row could not be read back.");
    }
    return recorded;
  }

  function dailyCost(day?: string): number {
    return readDay(day ?? dayOf())?.listCostUsd ?? 0;
  }

  return {
    recordUsage,
    dailyCost,
    readDay: (day?: string) => readDay(day ?? dayOf()),
    dailyBudgetExceeded: () => dailyCost() >= budget.dailyBudgetUsd,
    sessionBudgetExceeded: ({ sessionTokens }) => sessionTokens >= budget.sessionBudgetTokens,
  };
}
