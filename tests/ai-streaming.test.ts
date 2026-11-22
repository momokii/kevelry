// True token streaming, tested against a canned SSE body split at hostile
// boundaries: no socket, no provider, and every frame boundary is chosen to
// break the parser if it buffered the wrong thing.
//
// What this file proves (mechanical):
//   - a `delta` per provider chunk, in order, across splits mid-frame,
//     mid-JSON and mid-UTF-8 code point;
//   - tool-call fragments across frames reassemble into the exact
//     `{ id, type, function }` shape the tool loop already consumes;
//   - `finish_reason: "length"` becomes `AI_TRUNCATED`, usage from the final
//     chunk reaches `done`, and reasoning deltas never become prose;
//   - the idle guard and the whole-stream budget both abort with `AI_TIMEOUT`;
//   - a cut-off frame or an upstream abort yields exactly one `error` event
//     and still bills the usage the provider reported.
//
// What it does not prove: that the real gateway shape matches these fixtures
// byte for byte. The credential probes are the evidence for that.

import { describe, expect, it } from "vitest";

import { AI_BASE_URL_DEFAULT, AI_MODEL_DEFAULT, type AiConfig } from "../src/lib/ai/config";
import {
  AiClientError,
  createAiClient,
  type AiTransport,
  type ChatStreamReader,
  type ChatStreamResult,
} from "../src/lib/ai/client";
import {
  createGatewayStreamAccumulator,
  parseGatewayStream,
  type GatewayStreamParse,
} from "../src/lib/ai/gateway-stream";
import { runAssistantTurn, type AssistantEvent } from "../src/lib/ai/turn";
import type { AiUsage, AiUsageLedger } from "../src/lib/ai/usage";
import type { CveDatabase } from "../src/lib/db";

const KEY = "sentinel-key-streaming-4b7c";
const MESSAGES = [{ role: "user" as const, content: "which record is this?" }];

const USAGE_FRAME = {
  choices: [],
  usage: {
    prompt_tokens: 120,
    completion_tokens: 40,
    reasoning_tokens: 17,
    cache_read_tokens: 8,
    opencode: { list_cost: 0.125 },
  },
};

function makeConfig(overrides: Partial<AiConfig> = {}): AiConfig {
  return {
    enabled: true,
    apiKey: KEY,
    baseUrl: AI_BASE_URL_DEFAULT,
    model: AI_MODEL_DEFAULT,
    webFetchEnabled: false,
    sessionBudgetTokens: 60_000,
    dailyBudgetUsd: 5,
    maxTurns: 12,
    maxInputChars: 2000,
    requestTimeoutMs: 45_000,
    streamIdleTimeoutMs: 20_000,
    ...overrides,
  };
}

/** One SSE frame, exactly as the gateway writes it. */
function frame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function contentFrame(text: string): string {
  return frame({
    model: AI_MODEL_DEFAULT,
    choices: [{ delta: { content: text }, finish_reason: null }],
  });
}

function stopFrame(reason: string): string {
  return frame({ choices: [{ delta: {}, finish_reason: reason }] });
}

const DONE = "data: [DONE]\n\n";

function byteLengthOfPrefix(raw: string, charIndex: number): number {
  return new TextEncoder().encode(raw.slice(0, charIndex)).length;
}

/** Splits a body at byte offsets, so a cut can land inside a UTF-8 sequence. */
function splitAtBytes(raw: string, cuts: readonly number[]): Uint8Array[] {
  const bytes = new TextEncoder().encode(raw);
  const ordered = [...cuts].sort((left, right) => left - right);
  const parts: Uint8Array[] = [];
  let start = 0;
  for (const cut of ordered) {
    if (cut <= start || cut >= bytes.length) continue;
    parts.push(bytes.slice(start, cut));
    start = cut;
  }
  parts.push(bytes.slice(start));
  return parts;
}

function streamOf(parts: readonly Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const part of parts) controller.enqueue(part);
      controller.close();
    },
  });
}

function transportOfParts(parts: readonly Uint8Array[]): AiTransport {
  return async () => ({ status: 200, body: "", stream: streamOf(parts) });
}

function transportOfBody(body: string): AiTransport {
  return transportOfParts([new TextEncoder().encode(body)]);
}

function clientWith(transport: AiTransport, config: AiConfig = makeConfig()) {
  return createAiClient({ config, transport });
}

async function readAll(
  reader: ChatStreamReader,
): Promise<{ deltas: string[]; error: unknown; result: ChatStreamResult }> {
  const deltas: string[] = [];
  try {
    for (;;) {
      const text = await reader.read();
      if (text === null) break;
      deltas.push(text);
    }
    return { deltas, error: null, result: reader.result() };
  } catch (error) {
    return { deltas, error, result: reader.result() };
  }
}

interface TurnOutcome {
  events: AssistantEvent[];
  recorded: AiUsage[];
}

function ledgerInto(recorded: AiUsage[]): AiUsageLedger {
  return {
    recordUsage: ({ usage }) => {
      recorded.push(usage);
      return {
        day: "2026-01-01",
        requests: 1,
        promptTokens: usage.promptTokens,
        completionTokens: usage.completionTokens,
        reasoningTokens: usage.reasoningTokens,
        cacheReadTokens: usage.cacheReadTokens,
        listCostUsd: usage.listCostUsd,
        createdAt: "2026-01-01T00:00:00.000Z",
      };
    },
    dailyCost: () => 0,
    dailyBudgetExceeded: () => false,
    sessionBudgetExceeded: () => false,
    readDay: () => null,
  };
}

async function runTurn(
  transport: AiTransport,
  overrides: Partial<AiConfig> = {},
): Promise<TurnOutcome> {
  const config = makeConfig(overrides);
  const recorded: AiUsage[] = [];
  const events: AssistantEvent[] = [];
  const turn = runAssistantTurn({
    config,
    db: {} as CveDatabase,
    client: clientWith(transport, config),
    ledger: ledgerInto(recorded),
    messages: MESSAGES,
  });
  for await (const event of turn) events.push(event);
  return { events, recorded };
}

function errorCodes(events: readonly AssistantEvent[]): string[] {
  return events.flatMap((event) => (event.type === "error" ? [event.code] : []));
}

const TEXT_PARTS = ["Grüße, ", "naïve ✓", " — 100 %"] as const;

function textBody(): string {
  return [
    ...TEXT_PARTS.map((part) => contentFrame(part)),
    stopFrame("stop"),
    frame(USAGE_FRAME),
    DONE,
  ].join("");
}

describe("gateway stream parser: line buffering", () => {
  it("agrees with the one-shot parse at every split point", () => {
    const raw = textBody();
    const expected = parseGatewayStream(raw);
    expect(expected.chunks).toEqual([...TEXT_PARTS]);
    expect(expected.text).toBe(TEXT_PARTS.join(""));
    expect(expected.complete).toBe(true);
    expect(expected.done).toBe(true);

    for (let cut = 0; cut <= raw.length; cut += 1) {
      const accumulator = createGatewayStreamAccumulator();
      const seen: string[] = [];
      seen.push(...accumulator.push(raw.slice(0, cut)));
      seen.push(...accumulator.push(raw.slice(cut)));
      seen.push(...accumulator.end());
      const parsed: GatewayStreamParse = accumulator.snapshot();
      expect(parsed, `split at char ${String(cut)}`).toEqual(expected);
      expect(seen).toEqual([...TEXT_PARTS]);
    }
  });

  it("handles CRLF frames and a final frame with no trailing blank line", () => {
    const raw = [
      `data: ${JSON.stringify({ choices: [{ delta: { content: "a" } }] })}\r\n\r\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: "b" }, finish_reason: "stop" }] })}`,
    ].join("");
    const parsed = parseGatewayStream(raw);
    expect(parsed.chunks).toEqual(["a", "b"]);
    expect(parsed.complete).toBe(true);
    expect(parsed.done).toBe(false);
  });
});

describe("streaming client: text and framing", () => {
  it("forwards one delta per provider chunk, in order, across split frames and a split code point", async () => {
    const raw = textBody();
    const firstFrame = contentFrame(TEXT_PARTS[0]);
    const cuts = [
      // Mid-frame: inside the `data:` keyword of the first frame.
      4,
      // Mid-JSON: inside the first frame's `"content"` key.
      raw.indexOf('"content"') + 5,
      // Mid-UTF-8: between the two bytes of the "ü" in "Grüße".
      byteLengthOfPrefix(raw, raw.indexOf("Grüße") + 2) + 1,
      // Mid-frame again, inside the finish frame.
      raw.indexOf(firstFrame) + firstFrame.length + 6,
    ];
    const parts = splitAtBytes(raw, cuts);
    expect(parts).toHaveLength(cuts.length + 1);

    const reader = clientWith(transportOfParts(parts)).streamChatCompletion({
      messages: MESSAGES,
    });
    const { deltas, error, result } = await readAll(reader);

    expect(error).toBeNull();
    expect(deltas).toEqual([...TEXT_PARTS]);
    expect(deltas).toHaveLength(TEXT_PARTS.length);
    expect(result.content).toBe(TEXT_PARTS.join(""));
    expect(result.finishReason).toBe("stop");
    expect(result.complete).toBe(true);
    expect(result.malformed).toBe(false);
    expect(result.model).toBe(AI_MODEL_DEFAULT);
    expect(result.usage).toMatchObject({
      promptTokens: 120,
      completionTokens: 40,
      reasoningTokens: 17,
      cacheReadTokens: 8,
      listCostUsd: 0.125,
    });
  });

  it("reassembles tool-call fragments split across three frames into one JSON call", async () => {
    const raw = [
      frame({
        choices: [
          {
            delta: {
              tool_calls: [
                {
                  index: 0,
                  id: "call_7",
                  type: "function",
                  function: { name: "get_cve", arguments: '{"id":' },
                },
              ],
            },
          },
        ],
      }),
      frame({
        choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '"CVE-2099-' } }] } }],
      }),
      frame({
        choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '0001"}' } }] } }],
      }),
      stopFrame("tool_calls"),
      frame(USAGE_FRAME),
      DONE,
    ].join("");
    // The body is also split mid-frame, so fragment boundaries and transport
    // boundaries are independent.
    const parts = splitAtBytes(raw, [9, 71, 133, raw.length - 11]);

    const reader = clientWith(transportOfParts(parts)).streamChatCompletion({
      messages: MESSAGES,
    });
    const { deltas, error, result } = await readAll(reader);

    expect(error).toBeNull();
    expect(deltas).toEqual([]);
    expect(result.toolCalls).toEqual([
      {
        id: "call_7",
        type: "function",
        function: { name: "get_cve", arguments: '{"id":"CVE-2099-0001"}' },
      },
    ]);
    const call = result.toolCalls[0];
    expect(call).toBeDefined();
    expect(JSON.parse(String(call?.function.arguments))).toEqual({ id: "CVE-2099-0001" });
    expect(result.finishReason).toBe("tool_calls");
  });

  it("refuses a 200 that is not an event stream instead of reading it as an empty answer", async () => {
    const transport: AiTransport = async () => ({
      status: 200,
      body: JSON.stringify({ choices: [{ message: { content: "json, not SSE" } }] }),
      contentType: "application/json",
    });
    const reader = clientWith(transport).streamChatCompletion({ messages: MESSAGES });
    const { deltas, error } = await readAll(reader);

    expect(deltas).toEqual([]);
    expect(error).toMatchObject({ code: "AI_UPSTREAM_ERROR", status: 200 });
    expect(String((error as Error).message)).toContain("event stream");
  });

  it("never forwards reasoning deltas as answer text", async () => {
    const body = [
      frame({ choices: [{ delta: { reasoning_content: "let me think about this" } }] }),
      frame({ choices: [{ delta: { reasoning: "still thinking" } }] }),
      contentFrame("The record is CVE-2099-0001."),
      stopFrame("stop"),
      frame(USAGE_FRAME),
      DONE,
    ].join("");

    const reader = clientWith(transportOfBody(body)).streamChatCompletion({ messages: MESSAGES });
    const { deltas, error } = await readAll(reader);

    expect(error).toBeNull();
    expect(deltas).toEqual(["The record is CVE-2099-0001."]);
  });
});

describe("streaming turn: unverified ids in the prose", () => {
  function unverifiedOf(events: readonly AssistantEvent[]): string[][] {
    return events.flatMap((event) => (event.type === "unverified" ? [event.ids] : []));
  }

  function answerBody(text: string): string {
    return [contentFrame(text), stopFrame("stop"), frame(USAGE_FRAME), DONE].join("");
  }

  it("emits no unverified frame when the answer names no id", async () => {
    const { events } = await runTurn(
      transportOfBody(answerBody("No record matched that question.")),
    );

    expect(events.map((event) => event.type)).toEqual(["delta", "citations", "done"]);
    expect(events.some((event) => event.type === "unverified")).toBe(false);
    expect(events[events.length - 1]).toMatchObject({ type: "done", unverified: [] });
  });

  it("lists an id the prose named and no tool returned, and reports it in done", async () => {
    const { events } = await runTurn(transportOfBody(answerBody("See CVE-2099-9999 for context.")));

    expect(events.map((event) => event.type)).toEqual(["delta", "citations", "unverified", "done"]);
    expect(unverifiedOf(events)).toEqual([["CVE-2099-9999"]]);
    expect(events[events.length - 1]).toMatchObject({
      type: "done",
      unverified: ["CVE-2099-9999"],
    });
    // The tool-backed set is untouched: prose never becomes a citation.
    expect(events.find((event) => event.type === "citations")).toEqual({
      type: "citations",
      records: [],
    });
  });

  it("lists a repeated unverified id once", async () => {
    const { events } = await runTurn(
      transportOfBody(answerBody("CVE-2099-9999 is not in the data. CVE-2099-9999 may be a typo.")),
    );

    expect(unverifiedOf(events)).toEqual([["CVE-2099-9999"]]);
    expect(events[events.length - 1]).toMatchObject({
      type: "done",
      unverified: ["CVE-2099-9999"],
    });
  });

  it("normalises a lowercase cve id before classifying it", async () => {
    const { events } = await runTurn(
      transportOfBody(answerBody("The id cve-2021-44228 is famous.")),
    );

    expect(unverifiedOf(events)).toEqual([["CVE-2021-44228"]]);
  });
});

describe("streaming turn: usage, truncation and failures", () => {
  it("carries the final usage chunk into done", async () => {
    const { events, recorded } = await runTurn(transportOfBody(textBody()));

    expect(events.map((event) => event.type)).toEqual([
      "delta",
      "delta",
      "delta",
      "citations",
      "done",
    ]);
    const done = events[events.length - 1];
    expect(done).toMatchObject({
      type: "done",
      rounds: 0,
      usage: { prompt: 120, completion: 40, reasoning: 17, cacheRead: 8 },
      costUsd: 0.125,
    });
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ promptTokens: 120, listCostUsd: 0.125 });
  });

  it('maps finish_reason "length" to AI_TRUNCATED and bills the reported usage', async () => {
    const body = [
      contentFrame("The answer is"),
      stopFrame("length"),
      frame(USAGE_FRAME),
      DONE,
    ].join("");
    const { events, recorded } = await runTurn(transportOfBody(body));

    expect(events.map((event) => event.type)).toEqual(["delta", "error"]);
    expect(errorCodes(events)).toEqual(["AI_TRUNCATED"]);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ promptTokens: 120, completionTokens: 40 });
  });

  it("aborts with AI_TIMEOUT when the stream is idle past the configured gap", async () => {
    // One chunk, then silence with the socket open: a stall, not thinking.
    const first = new TextEncoder().encode(contentFrame("partial "));
    const transport: AiTransport = async () => ({
      status: 200,
      body: "",
      stream: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(first);
        },
      }),
    });
    const reader = clientWith(
      transport,
      makeConfig({ streamIdleTimeoutMs: 25 }),
    ).streamChatCompletion({ messages: MESSAGES });

    const startedAt = Date.now();
    const { deltas, error, result } = await readAll(reader);
    const elapsed = Date.now() - startedAt;

    expect(deltas).toEqual(["partial "]);
    expect(error).toBeInstanceOf(AiClientError);
    expect(error).toMatchObject({ code: "AI_TIMEOUT", retryable: false });
    expect(result.content).toBe("partial ");
    expect(elapsed).toBeLessThan(1000);
  });

  it("aborts with AI_TIMEOUT when the whole-stream budget expires", async () => {
    // Idle guard effectively off; only the total budget can stop this stream.
    const transport: AiTransport = async () => ({
      status: 200,
      body: "",
      stream: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(contentFrame("started ")));
        },
      }),
    });
    const config = makeConfig({ requestTimeoutMs: 40, streamIdleTimeoutMs: 60_000 });
    const reader = clientWith(transport, config).streamChatCompletion({ messages: MESSAGES });

    const { deltas, error } = await readAll(reader);

    expect(deltas).toEqual(["started "]);
    expect(error).toMatchObject({ code: "AI_TIMEOUT" });
    expect(String((error as Error).message)).toContain("did not finish streaming");
  });

  it("emits one error and no partial JSON when a frame is cut off", async () => {
    // A complete frame, then a frame that dies mid-JSON and a closed body.
    const body = [
      contentFrame("safe "),
      'data: {"choices":[{"delta":{"content":"never delivered"',
    ].join("");
    const { events, recorded } = await runTurn(transportOfBody(body));

    expect(events.map((event) => event.type)).toEqual(["delta", "error"]);
    expect(errorCodes(events)).toEqual(["AI_UPSTREAM_ERROR"]);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("never delivered");
    expect(serialized).not.toContain("choices");
    expect(recorded).toHaveLength(0);
  });

  it("emits one error and still bills usage when the upstream aborts mid-stream", async () => {
    const first = new TextEncoder().encode(
      [contentFrame("half an ans"), frame(USAGE_FRAME)].join(""),
    );
    let step = 0;
    const transport: AiTransport = async () => ({
      status: 200,
      body: "",
      stream: new ReadableStream<Uint8Array>({
        pull(controller) {
          if (step === 0) {
            step = 1;
            controller.enqueue(first);
            return;
          }
          controller.error(new Error("socket reset"));
        },
      }),
    });
    const { events, recorded } = await runTurn(transport);

    expect(events.map((event) => event.type)).toEqual(["delta", "error"]);
    expect(errorCodes(events)).toEqual(["AI_UPSTREAM_ERROR"]);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ promptTokens: 120, reasoningTokens: 17 });
  });
});
