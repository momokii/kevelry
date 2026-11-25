// The desk's six states, as pure functions of a typed failure.
//
// Every state a reader can meet has to be constructible without a network, a
// provider or a browser: that is what makes the copy reviewable. This file pins
// the mapping from a typed code to the sentence the desk shows, and the wording
// helpers that keep numbers honest (`43 s`, `5 h 41 m`, `00:00 UTC`).

import { describe, expect, it } from "vitest";

import {
  ELAPSED_TICK_MS,
  MAX_QUESTION_CHARS,
  QUESTION_COUNTER_VISIBLE_AT,
  budgetFault,
  counterVisible,
  disabledFault,
  faultFromCode,
  faultFromHttp,
  faultFromStreamError,
  formatCount,
  formatElapsed,
  formatRemaining,
  formatResetInstant,
  formatToolArgs,
  rateLimitedFault,
  secondsUntil,
  toolActivity,
  workingStage,
} from "../src/components/assistant/assistant-state";
import { buildHistory } from "../src/components/assistant/AssistantDesk";
import type { AssistantTurn } from "../src/components/assistant/assistant-state";

function turn(overrides: Partial<AssistantTurn> = {}): AssistantTurn {
  return {
    id: "turn-1",
    question: "Which KEV entries are due?",
    answer: "Two.",
    settled: true,
    stopped: false,
    citations: [],
    unverified: [],
    tools: [],
    aboutCve: null,
    ...overrides,
  };
}

describe("fault: the three provider failures", () => {
  it("AI_TIMEOUT says the question was not answered", () => {
    const fault = faultFromCode("AI_TIMEOUT");
    expect(fault.kind).toBe("error");
    expect(fault.headline).toBe("The model took too long; the question was not answered.");
    expect(fault.next).toContain("Ask again");
    expect(fault.retryable).toBe(true);
  });

  it("AI_UPSTREAM_ERROR names the provider, not the corpus", () => {
    const fault = faultFromCode("AI_UPSTREAM_ERROR");
    expect(fault.headline).toBe("The provider failed before the answer finished.");
    expect(fault.next).toContain("provider is the problem, not this corpus");
  });

  it("AI_TRUNCATED asks for a narrower question", () => {
    const fault = faultFromCode("AI_TRUNCATED");
    expect(fault.headline).toBe("The answer was cut off; ask a narrower question.");
    expect(fault.next).toContain("one record");
  });

  it("an unknown code still gets copy, never a raw code for prose", () => {
    const fault = faultFromCode("AI_SOMETHING_NEW");
    expect(fault.headline).toBe("The answer stopped unexpectedly.");
    expect(fault.headline).not.toContain("AI_SOMETHING_NEW");
  });

  it("a stream error maps through the same table", () => {
    expect(faultFromStreamError("AI_TRUNCATED").headline).toBe(
      faultFromCode("AI_TRUNCATED").headline,
    );
  });
});

describe("fault: feature disabled", () => {
  it("names the reason and the exact variable, for each reason", () => {
    const cases = [
      ["off", "AI_ENABLED"],
      ["no-key", "AI_API_KEY"],
      ["over-budget", "AI_DAILY_BUDGET_USD"],
      ["invalid-config", "AI_ENABLED"],
    ] as const;
    for (const [reason, variable] of cases) {
      const fault = disabledFault(reason);
      expect(fault.kind).toBe("disabled");
      expect(fault.disabledReason).toBe(reason);
      expect(fault.envVar).toBe(variable);
      expect(fault.retryable).toBe(false);
      expect(fault.next).toContain("operator");
    }
  });

  it("reads a typed 503 with its reason from the route's envelope", () => {
    const fault = faultFromHttp({
      status: 503,
      snapshot: {
        code: "AI_DISABLED",
        message: "The AI assistant is disabled because no gateway key is configured (AI_API_KEY).",
        details: { reason: "no-key" },
      },
      retryAfterSeconds: null,
    });
    expect(fault.kind).toBe("disabled");
    expect(fault.disabledReason).toBe("no-key");
    expect(fault.envVar).toBe("AI_API_KEY");
    expect(fault.detail).toContain("no gateway key");
  });
});

describe("fault: budgets", () => {
  it("the daily cap names the reset instant it was given", () => {
    const fault = budgetFault({ reason: "daily", resetAt: "2026-11-23T00:00:00.000Z" });
    expect(fault.kind).toBe("budget");
    expect(fault.headline).toBe("The assistant has spent today's AI budget.");
    expect(fault.envVar).toBe("AI_DAILY_BUDGET_USD");
    expect(fault.resetAt).toBe("2026-11-23T00:00:00.000Z");
    expect(formatResetInstant(fault.resetAt)).toBe("00:00 UTC");
  });

  it("the session cap is a different sentence, not the same one with a new number", () => {
    const fault = budgetFault({ reason: "session", resetAt: null });
    expect(fault.headline).toBe("This transcript has reached its token budget.");
    expect(fault.envVar).toBe("AI_SESSION_BUDGET_TOKENS");
    expect(fault.resetAt).toBeNull();
  });

  it("a 429 budget body keeps its reason and reset", () => {
    const fault = faultFromHttp({
      status: 429,
      snapshot: {
        code: "AI_BUDGET_EXHAUSTED",
        message: "The daily AI budget for this deployment is spent. It resets at 00:00 UTC.",
        details: { reason: "daily", resetAt: "2026-11-23T00:00:00.000Z" },
      },
      retryAfterSeconds: 3600,
    });
    expect(fault.kind).toBe("budget");
    expect(fault.budgetReason).toBe("daily");
    expect(fault.resetAt).toBe("2026-11-23T00:00:00.000Z");
  });
});

describe("fault: rate limited", () => {
  it("carries the wait the server reported", () => {
    const fault = rateLimitedFault(43);
    expect(fault.kind).toBe("rate-limited");
    expect(fault.retryAfterSeconds).toBe(43);
    expect(fault.retryable).toBe(false);
  });

  it("a 429 with no Retry-After still becomes a rate limit, not a generic error", () => {
    const fault = faultFromHttp({ status: 429, snapshot: null, retryAfterSeconds: null });
    expect(fault.kind).toBe("rate-limited");
    expect(fault.retryAfterSeconds).toBe(1);
  });
});

describe("wording helpers", () => {
  it("names the tool in words and states its row count", () => {
    expect(toolActivity("kev_window", 4)).toBe("checking the KEV window · 4 records…");
    expect(toolActivity("get_cve", 1)).toBe("reading the record · 1 record…");
    expect(toolActivity("search_cves", 0)).toBe("searching the corpus · no rows yet…");
    expect(toolActivity("unknown_tool", 2)).toBe("running a tool · 2 records…");
  });

  it("renders arguments on one line", () => {
    expect(formatToolArgs({ days: 30 })).toBe("days=30");
    expect(formatToolArgs({ id: "CVE-2021-44228", kev: "listed" })).toBe(
      "id=CVE-2021-44228 · kev=listed",
    );
    expect(formatToolArgs({ q: "log4j exploit" })).toBe('q="log4j exploit"');
    expect(formatToolArgs({})).toBe("no arguments");
    expect(formatToolArgs(null)).toBe("no arguments");
  });

  it("formats a remaining duration at three scales", () => {
    expect(formatRemaining(9)).toBe("9 s");
    expect(formatRemaining(43)).toBe("43 s");
    expect(formatRemaining(125)).toBe("2 m 05 s");
    expect(formatRemaining(3600 + 41 * 60)).toBe("1 h 41 m");
    expect(formatRemaining(-5)).toBe("0 s");
  });

  it("counts down to an instant without inventing one", () => {
    const base = Date.parse("2026-11-22T12:00:00.000Z");
    expect(secondsUntil("2026-11-22T12:00:30.000Z", base)).toBe(30);
    expect(secondsUntil("2026-11-22T11:00:00.000Z", base)).toBe(0);
    expect(secondsUntil(null, base)).toBeNull();
    expect(secondsUntil("not-a-date", base)).toBeNull();
    expect(formatResetInstant("nonsense")).toBeNull();
  });

  it("shows the character counter only near the limit", () => {
    expect(counterVisible(0)).toBe(false);
    expect(counterVisible(QUESTION_COUNTER_VISIBLE_AT - 1)).toBe(false);
    expect(counterVisible(QUESTION_COUNTER_VISIBLE_AT)).toBe(true);
    expect(MAX_QUESTION_CHARS).toBe(2000);
  });

  it("groups a count and never prints a bare one", () => {
    expect(formatCount(4)).toBe("4");
    expect(formatCount(12045)).toBe("12,045");
  });

  it("states the stage from the tool, then from the answer, then from the wait", () => {
    // The server's own words win while a call is running.
    expect(workingStage(turn({ answer: "", tools: [] }), "reading the record · 1 record…")).toBe(
      "reading the record · 1 record…",
    );
    // First delta: the activity is cleared, the prose is the stage.
    expect(workingStage(turn({ answer: "Four records " }), null)).toBe("writing…");
    // Between calls: the ledger says what just came back.
    expect(
      workingStage(
        turn({
          answer: "",
          tools: [
            {
              id: "tool-1",
              name: "kev_window",
              args: "days=30",
              rows: 4,
              ok: true,
              ids: [],
            },
          ],
        }),
        null,
      ),
    ).toBe("reading what the last call returned…");
    // Before anything has arrived, the wait is named rather than left blank.
    expect(workingStage(turn({ answer: "", tools: [] }), null)).toBe(
      "the model is deciding what to look up…",
    );
  });

  it("counts elapsed seconds in tenths under ten and whole seconds after", () => {
    expect(ELAPSED_TICK_MS).toBe(250);
    expect(formatElapsed(0)).toBe("0.0s");
    expect(formatElapsed(250)).toBe("0.2s");
    expect(formatElapsed(400)).toBe("0.4s");
    expect(formatElapsed(9999)).toBe("9.9s");
    expect(formatElapsed(10_000)).toBe("10s");
    expect(formatElapsed(12_000)).toBe("12s");
    // A clock that goes backwards never prints a negative wait.
    expect(formatElapsed(-20)).toBe("0.0s");
    expect(formatElapsed(Number.NaN)).toBe("0.0s");
  });
});

describe("request history", () => {
  it("sends settled turns plus the new question, and skips an empty answer", () => {
    const messages = buildHistory(
      [turn(), turn({ id: "turn-2", question: "And EPSS?", answer: "" })],
      "Which are listed?",
    );
    expect(messages).toEqual([
      { role: "user", content: "Which KEV entries are due?" },
      { role: "assistant", content: "Two." },
      { role: "user", content: "Which are listed?" },
    ]);
  });

  it("bounds the history the stateless server has to accept", () => {
    const many = Array.from({ length: 9 }, (_, index) =>
      turn({
        id: `turn-${String(index)}`,
        question: `question ${String(index)}`,
        answer: "answer",
      }),
    );
    const messages = buildHistory(many, "last");
    expect(messages.length).toBeLessThanOrEqual(10);
    expect(messages[messages.length - 1]).toEqual({ role: "user", content: "last" });
  });
});
