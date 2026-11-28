// The desk's six states, as pure functions of a typed failure.
//
// Every state a reader can meet has to be constructible without a network, a
// provider or a browser: that is what makes the copy reviewable. This file pins
// the mapping from a typed code to the sentence the desk shows, and the wording
// helpers that keep numbers honest (`43 s`, `5 h 41 m`, `00:00 UTC`).

import { describe, expect, it } from "vitest";

import {
  ELAPSED_TICK_MS,
  QUESTION_COUNTER_VISIBLE_AT,
  budgetFault,
  counterVisible,
  disabledFault,
  faultFromCode,
  faultFromHttp,
  formatCount,
  formatElapsed,
  formatRemaining,
  formatResetInstant,
  formatToolArgs,
  rateLimitedFault,
  retryStage,
  secondsUntil,
  toolActivity,
  webSources,
  workingStage,
} from "../src/components/assistant/assistant-state";
import { buildHistory, buildHistoryForTurn } from "../src/components/assistant/AssistantDesk";
import type { AssistantTurn } from "../src/components/assistant/assistant-state";
import { HISTORY_TRIMMED_NOTE } from "../src/components/assistant/assistant-state";
// The caps come from their one home; the route's body module re-exports the
// same bindings, so importing both is how "no second literal" is observed.
import {
  ASSISTANT_MAX_MESSAGE_CHARS,
  ASSISTANT_MAX_MESSAGES,
  ASSISTANT_MAX_TOTAL_CHARS,
  MAX_QUESTION_CHARS,
} from "../src/lib/ai/limits";
import {
  ASSISTANT_MAX_MESSAGE_CHARS as BODY_MAX_MESSAGE_CHARS,
  ASSISTANT_MAX_MESSAGES as BODY_MAX_MESSAGES,
  ASSISTANT_MAX_TOTAL_CHARS as BODY_MAX_TOTAL_CHARS,
} from "../app/api/assistant/_lib/body";

function turn(overrides: Partial<AssistantTurn> = {}): AssistantTurn {
  return {
    id: "turn-1",
    question: "Which KEV entries are due?",
    answer: "Two.",
    settled: true,
    stopped: false,
    failed: false,
    citations: [],
    unverified: [],
    unverifiedNumbers: [],
    tools: [],
    aboutCve: null,
    sendImage: false,
    image: null,
    contextTrimmed: false,
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
    // An in-stream error event is mapped by `faultFromCode` itself: the desk no
    // longer keeps a forwarder that only restated the call.
    expect(faultFromCode("AI_TRUNCATED").headline).toBe(
      "The answer was cut off; ask a narrower question.",
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

  it("the unmetered case is not a spend claim, and says what it is", () => {
    // The gateway stopped reporting cost: the budget cannot be totalled, so the
    // copy must not claim the money was spent. The server's own sentence (with
    // its count) rides in `detail`, so the desk never invents the number.
    const fault = faultFromHttp({
      status: 429,
      snapshot: {
        code: "AI_BUDGET_EXHAUSTED",
        message:
          "The gateway reported no cost for 10 AI turns today, so the daily budget cannot be measured. It resets at 00:00 UTC.",
        details: {
          reason: "unmetered",
          unmeteredTurns: 10,
          resetAt: "2026-11-23T00:00:00.000Z",
        },
      },
      retryAfterSeconds: 3600,
    });
    expect(fault.kind).toBe("budget");
    expect(fault.budgetReason).toBe("unmetered");
    expect(fault.headline).toContain("cannot measure");
    expect(fault.envVar).toBe("AI_DAILY_BUDGET_USD");
    expect(fault.resetAt).toBe("2026-11-23T00:00:00.000Z");
    expect(fault.detail).toContain("10 AI turns");
    expect(fault.retryable).toBe(false);
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

  it("names which re-run the turn is on, and lets it win the progress line", () => {
    // Two different facts, two sentences: a round cut by its cap, and a round
    // that came back clean with nothing in it.
    expect(retryStage("AI_EMPTY_ANSWER")).toBe("the first attempt came back empty — retrying");
    expect(retryStage("AI_TRUNCATED")).toBe("the first attempt was cut off — retrying");
    // While the retry is running the stage is the retry's own words, not the
    // derived sentence about what the model is deciding.
    expect(workingStage(turn({ answer: "", tools: [] }), retryStage("AI_EMPTY_ANSWER"))).toBe(
      "the first attempt came back empty — retrying",
    );
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

describe("web evidence", () => {
  const URL = "https://nvd.nist.gov/vuln/detail/CVE-2099-0001";

  function fetched(overrides: Partial<AssistantTurn["tools"][number]> = {}): AssistantTurn {
    return turn({
      citations: [],
      tools: [
        {
          id: "tool-web",
          name: "fetch_authoritative",
          args: `url=${URL}`,
          rows: 1,
          ok: true,
          ids: [],
          web: { url: URL, host: "nvd.nist.gov" },
          ...overrides,
        },
      ],
    });
  }

  it("keeps the one host a successful fetch read", () => {
    expect(webSources(fetched())).toEqual([{ url: URL, host: "nvd.nist.gov" }]);
  });

  it("contributes nothing from a failed call, a plain tool or a non-https URL", () => {
    expect(webSources(fetched({ ok: false }))).toEqual([]);
    expect(webSources(turn())).toEqual([]);
    expect(
      webSources(fetched({ web: { url: "http://nvd.nist.gov/x", host: "nvd.nist.gov" } })),
    ).toEqual([]);
    expect(webSources(fetched({ web: null }))).toEqual([]);
  });

  it("collapses a repeated URL to one chip", () => {
    const twice = turn({ tools: [...fetched().tools, ...fetched({ id: "tool-web-2" }).tools] });
    expect(webSources(twice)).toHaveLength(1);
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
    expect(messages.length).toBeLessThanOrEqual(ASSISTANT_MAX_MESSAGES);
    expect(messages[messages.length - 1]).toEqual({ role: "user", content: "last" });
  });

  it("never replays a refusal as something the model answered", () => {
    // The refusal sentence is the desk declining, not an answer about the
    // records. Sending it back as assistant history would put a canned line in
    // the model's mouth and invite it to continue from it.
    const messages = buildHistory(
      [turn({ refusal: true, answer: "I can't help with that." })],
      "Which are listed?",
    );
    expect(messages).toEqual([{ role: "user", content: "Which are listed?" }]);
  });

  it("never replays a failed turn as a claim the answer made", () => {
    // The prose of a failed turn is what the reader saw, not something the model
    // finished saying. Sending it back would present half an answer as history.
    const messages = buildHistory(
      [
        turn({ id: "turn-1", question: "Which are due?", answer: "Two records ", failed: true }),
        turn({ id: "turn-2", question: "And EPSS?", answer: "Three." }),
      ],
      "Which are listed?",
    );
    expect(messages).toEqual([
      { role: "user", content: "And EPSS?" },
      { role: "assistant", content: "Three." },
      { role: "user", content: "Which are listed?" },
    ]);
  });
});

describe("request history limits", () => {
  /** Twenty messages: ten settled turns, each one short question + long answer. */
  function twentyMessages(): AssistantTurn[] {
    return Array.from({ length: 10 }, (_, index) =>
      turn({
        id: `turn-${String(index)}`,
        question: `Question ${String(index)}: ${"q".repeat(180)}`,
        answer: `Answer ${String(index)}: ${"a".repeat(980)}`,
      }),
    );
  }

  const NEXT_QUESTION = "Which of those are also on the KEV list?";

  it("keeps the newest question intact and sends the newest turns that fit", () => {
    const turns = twentyMessages();
    const { messages, droppedTurns } = buildHistoryForTurn(turns, NEXT_QUESTION);
    const totalChars = messages.reduce((sum, message) => sum + message.content.length, 0);

    // The one message that must never be trimmed: the question being answered.
    expect(messages[messages.length - 1]).toEqual({ role: "user", content: NEXT_QUESTION });
    // Inside every cap the route enforces, with room to spare.
    expect(totalChars).toBeLessThanOrEqual(ASSISTANT_MAX_TOTAL_CHARS);
    expect(messages.length).toBeLessThanOrEqual(ASSISTANT_MAX_MESSAGES);
    for (const message of messages) {
      expect(message.content.length).toBeLessThanOrEqual(ASSISTANT_MAX_MESSAGE_CHARS);
    }
    // The oldest went first, and what is left is a contiguous tail: a gap in the
    // middle of a transcript is worse than one that simply starts later.
    const keptTurns = (messages.length - 1) / 2;
    expect(droppedTurns).toBe(turns.length - keptTurns);
    expect(messages.slice(0, keptTurns * 2)).toEqual(
      turns.slice(droppedTurns).flatMap((entry) => [
        { role: "user", content: entry.question },
        { role: "assistant", content: entry.answer },
      ]),
    );
  });

  it("drops a turn whose answer is over the per-message cap instead of splitting it", () => {
    // This was the production 400: the total fit, one answer did not, and the
    // old code kept re-sending it. Half an answer was never an option, so the
    // turn goes whole.
    const { messages, droppedTurns } = buildHistoryForTurn(
      [
        turn({ id: "turn-1", question: "First?", answer: "b".repeat(2_400) }),
        turn({ id: "turn-2", question: "Second?", answer: "Two." }),
      ],
      NEXT_QUESTION,
    );

    expect(messages).toEqual([
      { role: "user", content: "Second?" },
      { role: "assistant", content: "Two." },
      { role: "user", content: NEXT_QUESTION },
    ]);
    expect(droppedTurns).toBe(1);
  });

  it("reports no drop when the whole transcript fits", () => {
    const { messages, droppedTurns } = buildHistoryForTurn(
      [turn({ id: "turn-1", question: "First?" }), turn({ id: "turn-2", question: "Second?" })],
      NEXT_QUESTION,
    );
    expect(droppedTurns).toBe(0);
    expect(messages).toHaveLength(5);
  });

  it("reads the route's caps rather than keeping a second copy of them", () => {
    // The client's only job is to build a body the route accepts. A cap that
    // drifts upward here makes every later turn a 400 that no reader can fix,
    // and a stricter one silently withholds history the route would have taken —
    // so the desk and the route read the same three numbers, and the route's
    // body module re-exports those very bindings rather than restating them.
    expect(ASSISTANT_MAX_MESSAGE_CHARS).toBe(BODY_MAX_MESSAGE_CHARS);
    expect(ASSISTANT_MAX_MESSAGES).toBe(BODY_MAX_MESSAGES);
    expect(ASSISTANT_MAX_TOTAL_CHARS).toBe(BODY_MAX_TOTAL_CHARS);
    // A question is one message, so its cap is the per-message cap.
    expect(MAX_QUESTION_CHARS).toBe(ASSISTANT_MAX_MESSAGE_CHARS);
  });

  it("says it trimmed in one quiet line", () => {
    expect(HISTORY_TRIMMED_NOTE).toBe(
      "Earlier turns were trimmed from context to stay within limits.",
    );
  });
});
