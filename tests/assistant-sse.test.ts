// The client's half of the assistant's wire format.
//
// `EventSource` cannot POST, so the desk parses `response.body` itself. Two
// failure modes make that dangerous, and both are pinned here:
//
//  1. a frame boundary landing inside a chunk (mid-frame, mid-`data:` line,
//     mid-JSON, or between the two newlines that end a frame);
//  2. a frame whose payload is not an event this build understands — which must
//     be dropped, never coerced into a state change.
//
// The reference behaviour is the server-side parser in `src/lib/ai/gateway-stream.ts`:
// buffer the tail, dispatch only on the blank line, and never invent a frame.

import { describe, expect, it } from "vitest";

import {
  createAssistantSseParser,
  framePayload,
  parseAssistantEvent,
} from "../src/components/assistant/assistant-sse";

const TOOL_FRAME = `data: ${JSON.stringify({
  type: "tool",
  name: "kev_window",
  args: { days: 30 },
  ok: true,
  rows: 4,
  ids: ["CVE-2099-0001"],
})}\n\n`;

const DELTA_FRAME = `data: ${JSON.stringify({ type: "delta", text: "Twelve " })}\n\n`;

function feed(parser: ReturnType<typeof createAssistantSseParser>, chunks: string[]): string[] {
  return chunks.flatMap((chunk) => parser.push(chunk));
}

describe("assistant SSE parser: frame boundaries", () => {
  it("emits one payload per complete frame and none for a partial one", () => {
    const parser = createAssistantSseParser();
    expect(parser.push(TOOL_FRAME)).toHaveLength(1);
    // Half a frame is not an event yet.
    expect(parser.push(`data: {"type":"delta"`)).toEqual([]);
    expect(parser.push(`,"text":"hi"}\n`)).toEqual([]);
    expect(parser.push("\n")).toEqual([`{"type":"delta","text":"hi"}`]);
  });

  it("reassembles a stream split at every possible boundary", () => {
    const whole = TOOL_FRAME + DELTA_FRAME;
    for (let cut = 1; cut < whole.length; cut += 1) {
      const parser = createAssistantSseParser();
      const seen = feed(parser, [whole.slice(0, cut), whole.slice(cut)]);
      expect(seen, `split at ${String(cut)}`).toHaveLength(2);
    }
  });

  it("reassembles a stream delivered one byte at a time", () => {
    const parser = createAssistantSseParser();
    const whole = TOOL_FRAME + DELTA_FRAME;
    const seen = feed(parser, [...whole]);
    expect(seen).toHaveLength(2);
    expect(seen[1]).toBe(`{"type":"delta","text":"Twelve "}`);
  });

  it("handles CRLF terminators, including a \\r\\n split across chunks", () => {
    const whole = DELTA_FRAME.replace(/\n/g, "\r\n");
    const boundary = whole.indexOf("\r\n");
    const parser = createAssistantSseParser();
    // The first chunk ends on the `\r` and the second begins with its `\n`, so a
    // parser that normalises each chunk in isolation never sees the pair.
    const seen = feed(parser, [whole.slice(0, boundary + 1), whole.slice(boundary + 1)]);
    expect(seen).toHaveLength(1);
    expect(JSON.parse(seen[0] ?? "")).toEqual({ type: "delta", text: "Twelve " });
  });

  it("joins multiple data lines and ignores comments and other fields", () => {
    const block = ": keep-alive\nevent: message\nid: 4\ndata: first\ndata: second";
    expect(framePayload(block)).toBe("first\nsecond");
    expect(framePayload(": only a comment")).toBeNull();
  });

  it("keeps several frames that arrived in one chunk, in order", () => {
    const parser = createAssistantSseParser();
    const seen = parser.push(TOOL_FRAME + DELTA_FRAME + DELTA_FRAME);
    expect(seen.map((payload) => (JSON.parse(payload) as { type: string }).type)).toEqual([
      "tool",
      "delta",
      "delta",
    ]);
  });

  it("discards an unterminated trailing frame at the end of the stream", () => {
    const parser = createAssistantSseParser();
    expect(parser.push(TOOL_FRAME + `data: {"type":"delta","text":"cut"`)).toHaveLength(1);
    expect(parser.flush()).toEqual([]);
  });
});

describe("assistant SSE parser: event validation", () => {
  it("accepts each of the six contract events", () => {
    const payloads = [
      {
        type: "tool",
        name: "get_cve",
        args: { id: "CVE-2099-0001" },
        ok: true,
        rows: 1,
        ids: ["CVE-2099-0001"],
      },
      { type: "delta", text: "text" },
      { type: "retry", code: "AI_TRUNCATED", maxTokens: 4096 },
      { type: "citations", records: ["CVE-2099-0001"] },
      { type: "unverified", ids: ["CVE-2099-9999"] },
      {
        type: "done",
        usage: { prompt: 1, completion: 2, reasoning: 0, cacheRead: 0 },
        costUsd: 0.1,
        rounds: 1,
        unverified: ["CVE-2099-9999"],
      },
      { type: "error", code: "AI_TIMEOUT", message: "too slow" },
    ];
    for (const payload of payloads) {
      expect(parseAssistantEvent(JSON.stringify(payload))).toEqual(payload);
    }
  });

  it("drops malformed JSON, unknown types, non-objects and the done marker", () => {
    expect(parseAssistantEvent("{not json")).toBeNull();
    expect(parseAssistantEvent("[1,2,3]")).toBeNull();
    expect(parseAssistantEvent(JSON.stringify({ type: "usage" }))).toBeNull();
    expect(parseAssistantEvent("[DONE]")).toBeNull();
    expect(parseAssistantEvent("   ")).toBeNull();
  });

  it("does not act on a payload the server never sent", () => {
    const parser = createAssistantSseParser();
    // A citation is only ever produced by a `citations` event; prose that looks
    // like an id is not a chip.
    const prose = `data: ${JSON.stringify({ type: "delta", text: "see CVE-2099-0001" })}\n\n`;
    const events = parser.push(prose).map(parseAssistantEvent);
    expect(events).toEqual([{ type: "delta", text: "see CVE-2099-0001" }]);
  });
});
