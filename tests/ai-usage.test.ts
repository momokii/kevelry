import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { CveDatabase } from "../src/lib/db";
import { openDatabase } from "../src/lib/db";
import {
  AI_MAX_UNMETERED_TURNS_PER_DAY,
  createAiUsageLedger,
  parseUsage,
  utcDay,
  type AiUsage,
} from "../src/lib/ai/usage";

const NOW = new Date("2026-11-22T10:00:00.000Z");
const DAY = "2026-11-22";
const BUDGET = { sessionBudgetTokens: 60_000, dailyBudgetUsd: 5 };

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ai-usage-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return db;
}

function ledgerFor(db: CveDatabase) {
  return createAiUsageLedger({ db, budget: BUDGET, now: () => NOW });
}

function usage(overrides: Partial<AiUsage> = {}): AiUsage {
  return {
    promptTokens: 100,
    completionTokens: 20,
    reasoningTokens: 5,
    cacheReadTokens: 0,
    listCostUsd: 0.25,
    ...overrides,
  };
}

afterEach(() => {
  while (openDbs.length > 0) {
    try {
      (openDbs.pop() as CveDatabase).close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

describe("utcDay", () => {
  it("buckets instants by their UTC date", () => {
    expect(utcDay(new Date("2026-11-22T00:00:00.000Z"))).toBe("2026-11-22");
    expect(utcDay(new Date("2026-11-22T23:59:59.999Z"))).toBe("2026-11-22");
    expect(utcDay(new Date("2026-11-23T00:00:00.000Z"))).toBe("2026-11-23");
  });
});

describe("parseUsage", () => {
  it("reads list_cost, reasoning and cache tokens from the gateway usage block", () => {
    expect(
      parseUsage({
        prompt_tokens: 298,
        completion_tokens: 42,
        reasoning_tokens: 12,
        prompt_tokens_details: { cached_tokens: 7 },
        opencode: { list_cost: 0.0000639 },
      }),
    ).toEqual({
      promptTokens: 298,
      completionTokens: 42,
      reasoningTokens: 12,
      cacheReadTokens: 7,
      listCostUsd: 0.0000639,
    });
  });

  it("reads a missing list_cost as unknown, never as a free turn", () => {
    // Coercing this to 0 is what made the daily money cap unreachable: every
    // unpriced turn read as "spent nothing" while the provider billed it.
    expect(parseUsage({ prompt_tokens: 1, completion_tokens: 1 })).toEqual({
      promptTokens: 1,
      completionTokens: 1,
      reasoningTokens: 0,
      cacheReadTokens: 0,
      listCostUsd: null,
    });
    expect(parseUsage({ opencode: {} }).listCostUsd).toBeNull();
    expect(parseUsage(null).listCostUsd).toBeNull();
    // A known zero is a different fact: a free model really did cost nothing.
    expect(parseUsage({ opencode: { list_cost: 0 } }).listCostUsd).toBe(0);
  });

  it("never lets a malformed counter become NaN", () => {
    expect(
      parseUsage({
        prompt_tokens: "not-a-number",
        completion_tokens: -5,
        opencode: { list_cost: "free" },
      }),
    ).toEqual({
      promptTokens: 0,
      completionTokens: 0,
      reasoningTokens: 0,
      cacheReadTokens: 0,
      // Not a number, so not a cost: unknown, and counted as such below.
      listCostUsd: null,
    });
  });
});

describe("ai usage ledger", () => {
  it("adds no spend for a turn the gateway did not price, and counts it instead", () => {
    const ledger = ledgerFor(makeDb());
    const day = ledger.recordUsage({ usage: usage({ listCostUsd: null }) });

    expect(day.listCostUsd).toBe(0);
    expect(day.unmeteredRequests).toBe(1);
    expect(ledger.dailyCost()).toBe(0);
    expect(ledger.dailyBudgetExceeded()).toBe(false);
    expect(ledger.dailyBudget()).toEqual({ exceeded: false, reason: null, unmeteredTurns: 1 });
  });

  it("fails closed once the day has too many unpriced turns", () => {
    const ledger = ledgerFor(makeDb());
    for (let turn = 1; turn < AI_MAX_UNMETERED_TURNS_PER_DAY; turn += 1) {
      ledger.recordUsage({ usage: usage({ listCostUsd: null }) });
    }
    // One short of the limit: the budget still has headroom, and says how much
    // of the day it could not price.
    expect(ledger.dailyBudgetExceeded()).toBe(false);
    expect(ledger.dailyBudget().unmeteredTurns).toBe(AI_MAX_UNMETERED_TURNS_PER_DAY - 1);

    ledger.recordUsage({ usage: usage({ listCostUsd: null }) });

    // The day cannot be totalled, so it reads exhausted — with the reason, so
    // the UI can say "unmetered" instead of "spent".
    expect(ledger.dailyCost()).toBe(0);
    expect(ledger.dailyBudgetExceeded()).toBe(true);
    expect(ledger.dailyBudget()).toEqual({
      exceeded: true,
      reason: "unmetered",
      unmeteredTurns: AI_MAX_UNMETERED_TURNS_PER_DAY,
    });
  });

  it("still trips on known spend, and unmetered turns do not mask it", () => {
    const ledger = ledgerFor(makeDb());
    ledger.recordUsage({ usage: usage({ listCostUsd: null }) });
    ledger.recordUsage({ usage: usage({ listCostUsd: 2.5 }) });
    ledger.recordUsage({ usage: usage({ listCostUsd: 2.5 }) });

    expect(ledger.dailyCost()).toBe(5);
    expect(ledger.dailyBudget()).toEqual({ exceeded: true, reason: "daily", unmeteredTurns: 1 });
  });

  it("returns 0 spend and no row before the first turn", () => {
    const ledger = ledgerFor(makeDb());
    expect(ledger.dailyCost()).toBe(0);
    expect(ledger.readDay()).toBeNull();
    expect(ledger.dailyBudgetExceeded()).toBe(false);
  });

  it("upserts two turns on the same UTC day into one aggregate row", () => {
    const db = makeDb();
    const ledger = ledgerFor(db);
    ledger.recordUsage({ usage: usage() });
    const aggregate = ledger.recordUsage({
      usage: usage({
        promptTokens: 50,
        completionTokens: 10,
        reasoningTokens: 1,
        listCostUsd: 0.5,
      }),
    });

    expect(aggregate).toEqual({
      day: DAY,
      requests: 2,
      promptTokens: 150,
      completionTokens: 30,
      reasoningTokens: 6,
      cacheReadTokens: 0,
      listCostUsd: 0.75,
      unmeteredRequests: 0,
      createdAt: NOW.toISOString(),
    });
    const rows = db.handle.prepare("SELECT COUNT(*) AS count FROM ai_usage").get() as {
      count: number;
    };
    expect(rows.count).toBe(1);
    expect(ledger.dailyCost()).toBe(0.75);
  });

  it("keeps separate rows for separate UTC days", () => {
    const ledger = ledgerFor(makeDb());
    ledger.recordUsage({ usage: usage({ listCostUsd: 1 }), at: new Date("2026-11-22T23:59:59Z") });
    ledger.recordUsage({ usage: usage({ listCostUsd: 2 }), at: new Date("2026-11-23T00:00:00Z") });
    expect(ledger.dailyCost("2026-11-22")).toBe(1);
    expect(ledger.dailyCost("2026-11-23")).toBe(2);
    expect(ledger.readDay("2026-11-22")?.requests).toBe(1);
    expect(ledger.readDay("2026-11-23")?.requests).toBe(1);
  });

  it("reports the daily budget exceeded at the cap", () => {
    const ledger = ledgerFor(makeDb());
    ledger.recordUsage({ usage: usage({ listCostUsd: 4 }) });
    expect(ledger.dailyBudgetExceeded()).toBe(false);
    ledger.recordUsage({ usage: usage({ listCostUsd: 1 }) });
    expect(ledger.dailyCost()).toBe(5);
    expect(ledger.dailyBudgetExceeded()).toBe(true);
  });

  it("reports the session budget exceeded at the cap", () => {
    const ledger = ledgerFor(makeDb());
    expect(ledger.sessionBudgetExceeded({ sessionTokens: 59_999 })).toBe(false);
    expect(ledger.sessionBudgetExceeded({ sessionTokens: 60_000 })).toBe(true);
    expect(ledger.sessionBudgetExceeded({ sessionTokens: 60_001 })).toBe(true);
  });

  it("keeps today's spend across a fresh database handle, so a restart cannot reset it", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "cve-ai-usage-restart-"));
    let reopened: CveDatabase | null = null;
    try {
      const first = openDatabase({ dataDir: dir });
      ledgerFor(first).recordUsage({ usage: usage({ listCostUsd: 5 }) });
      first.close();

      reopened = openDatabase({ dataDir: dir });
      const ledger = createAiUsageLedger({ db: reopened, budget: BUDGET, now: () => NOW });
      expect(ledger.dailyCost(DAY)).toBe(5);
      expect(ledger.dailyBudgetExceeded()).toBe(true);
      expect(ledger.readDay(DAY)?.requests).toBe(1);
    } finally {
      reopened?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
