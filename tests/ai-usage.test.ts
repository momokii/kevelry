import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { CveDatabase } from "../src/lib/db";
import { openDatabase } from "../src/lib/db";
import { createAiUsageLedger, parseUsage, utcDay, type AiUsage } from "../src/lib/ai/usage";

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

  it("treats a missing list_cost as 0 rather than failing the turn", () => {
    expect(parseUsage({ prompt_tokens: 1, completion_tokens: 1 })).toEqual({
      promptTokens: 1,
      completionTokens: 1,
      reasoningTokens: 0,
      cacheReadTokens: 0,
      listCostUsd: 0,
    });
    expect(parseUsage({ opencode: {} }).listCostUsd).toBe(0);
    expect(parseUsage(null).listCostUsd).toBe(0);
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
      listCostUsd: 0,
    });
  });
});

describe("ai usage ledger", () => {
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
