// The assistant's spend ledger: one aggregate row per UTC day in SQLite.
//
// Two budgets read it. The session budget is a token count carried by the
// current turn loop, so it is a pure comparison; the daily budget is money and
// must be read from storage, not from a module-level counter, because a
// counter resets on restart and a restart must not buy fresh tokens. `day` is
// UTC `YYYY-MM-DD`, the same bucket basis as the checkpoints.
//
// Cost is read from the gateway's `usage.opencode.list_cost` extension field.
// A gateway change can drop it without changing the status code, so "absent" is
// a state this ledger has to carry rather than round away: a missing cost stored
// as 0 is indistinguishable from a free turn, and a run of them would make the
// daily money cap unreachable while the provider billed every request. So an
// unpriced turn adds no spend and increments `unmetered_requests` instead, and
// the daily budget fails closed on that count (see `AI_MAX_UNMETERED_TURNS_PER_DAY`).
//
// Nothing here stores prompt text, answers, IPs or session ids.

import type { CveDatabase } from "../db";
import { asRecord } from "../json";

/** Token and cost counters from one gateway response. */
export interface AiUsage {
  promptTokens: number;
  completionTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  /**
   * USD list price for the turn, or `null` when the gateway omitted
   * `list_cost`. A known zero (a free model) and an unknown cost are different
   * facts and are never merged.
   */
  listCostUsd: number | null;
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
  /** Turns today whose cost the gateway did not report; never summed as money. */
  unmeteredRequests: number;
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

/**
 * Turns in one UTC day that may go unpriced before the daily budget fails
 * closed. Ten is not a bill estimate: it is the point where "the gateway
 * stopped reporting cost" is an incident rather than a blip, and the cap a
 * deployment cannot compute stops being a cap.
 */
export const AI_MAX_UNMETERED_TURNS_PER_DAY = 10;

/** Why the daily cap reads exhausted. `unmetered` means it could not be totalled. */
export type AiDailyBudgetReason = "daily" | "unmetered";

export interface AiDailyBudgetState {
  exceeded: boolean;
  /** Which rule decided it; `null` while the day has headroom. */
  reason: AiDailyBudgetReason | null;
  /** Unpriced turns recorded today, for the sentence the UI shows. */
  unmeteredTurns: number;
}

export interface AiUsageLedger {
  /** Records one completed turn against the current UTC day. */
  recordUsage(input: { usage: AiUsage; at?: Date }): AiUsageDay;
  /** Spend for a UTC day; 0 before the first recorded turn. */
  dailyCost(day?: string): number;
  /** The daily budget and the reason it was decided; the UI shows the reason. */
  dailyBudget(day?: string): AiDailyBudgetState;
  /** True once the day's spend or its unpriced-turn count reaches its cap. */
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
  unmetered_requests: number;
  created_at: string;
}

/** UTC `YYYY-MM-DD`; the ledger and the checkpoints share this bucket basis. */
export function utcDay(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
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
    unmeteredRequests: row.unmetered_requests,
    createdAt: row.created_at,
  };
}

/**
 * The gateway's cost for one turn, or `null` when it did not report one.
 *
 * `opencode.cost` is 0 on this gateway; only `list_cost` is billable. A number
 * (or a numeric string) is a known cost — including an explicit `0`, which is a
 * free model rather than a missing field. Anything else is unknown: coercing it
 * to 0 would make the money cap silently unreachable.
 */
function readListCost(value: unknown): number | null {
  const numeric = typeof value === "number" || (typeof value === "string" && value.trim() !== "");
  if (!numeric) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return parsed;
}

/**
 * Reads the gateway `usage` block defensively. It is an OpenAI-shaped object
 * with a gateway-owned `opencode` extension, so every token field is optional
 * and an absent or malformed count reads as 0 — never as NaN, which would
 * poison the daily sum. Cost is the one field where 0 is not a safe fallback.
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
    listCostUsd: readListCost(opencode?.["list_cost"]),
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
          "cache_read_tokens, list_cost, unmetered_requests, created_at FROM ai_usage WHERE day = ?",
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
            "reasoning_tokens, cache_read_tokens, list_cost, unmetered_requests, " +
            "created_at) " +
            "VALUES (@day, 1, @promptTokens, @completionTokens, @reasoningTokens, " +
            "@cacheReadTokens, @listCostUsd, @unmeteredRequests, @createdAt) " +
            "ON CONFLICT(day) DO UPDATE SET " +
            "requests = ai_usage.requests + 1, " +
            "prompt_tokens = ai_usage.prompt_tokens + excluded.prompt_tokens, " +
            "completion_tokens = ai_usage.completion_tokens + excluded.completion_tokens, " +
            "reasoning_tokens = ai_usage.reasoning_tokens + excluded.reasoning_tokens, " +
            "cache_read_tokens = ai_usage.cache_read_tokens + excluded.cache_read_tokens, " +
            "list_cost = ai_usage.list_cost + excluded.list_cost, " +
            "unmetered_requests = ai_usage.unmetered_requests + excluded.unmetered_requests",
        )
        .run({
          day,
          promptTokens: nonNegativeInteger(usage.promptTokens),
          completionTokens: nonNegativeInteger(usage.completionTokens),
          reasoningTokens: nonNegativeInteger(usage.reasoningTokens),
          cacheReadTokens: nonNegativeInteger(usage.cacheReadTokens),
          // An unpriced turn adds no spend: it is counted, not summed.
          listCostUsd: usage.listCostUsd === null ? 0 : nonNegativeNumber(usage.listCostUsd),
          unmeteredRequests: usage.listCostUsd === null ? 1 : 0,
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

  /**
   * The daily cap, and which rule decided it. Spend is the money the gateway
   * reported; an unpriced-turn count past the limit means the total cannot be
   * trusted, so the cap reads exhausted rather than absent.
   */
  function dailyBudget(day?: string): AiDailyBudgetState {
    const row = readDay(day ?? dayOf());
    const cost = row?.listCostUsd ?? 0;
    const unmeteredTurns = row?.unmeteredRequests ?? 0;
    // Known spend first: it is the fact the cap was written for.
    if (cost >= budget.dailyBudgetUsd) {
      return { exceeded: true, reason: "daily", unmeteredTurns };
    }
    if (unmeteredTurns >= AI_MAX_UNMETERED_TURNS_PER_DAY) {
      return { exceeded: true, reason: "unmetered", unmeteredTurns };
    }
    return { exceeded: false, reason: null, unmeteredTurns };
  }

  return {
    recordUsage,
    dailyCost,
    dailyBudget,
    readDay: (day?: string) => readDay(day ?? dayOf()),
    dailyBudgetExceeded: () => dailyBudget().exceeded,
    sessionBudgetExceeded: ({ sessionTokens }) => sessionTokens >= budget.sessionBudgetTokens,
  };
}
