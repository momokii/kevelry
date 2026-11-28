// The gateway's SSE body, parsed into something the turn loop can reason about.
//
// `client.ts` deliberately returns a streamed response *unparsed*: the transport
// is a single request/response function, and keeping the parser here means the
// loop owns the event shapes and the client stays a thin bytes mover.
//
// Three facts from the credential probes drive this file:
//
//  1. A streamed turn is `data: {...}` frames, then a terminal `data: [DONE]`.
//     A body without that terminal marker is an aborted stream, not a short
//     answer — the caller maps `complete: false` to `AI_UPSTREAM_ERROR`.
//  2. `stream_options.include_usage` puts the only usage block on a second-to-
//     last frame whose `choices` is empty. Reading usage only from
//     `choices[0]` would silently bill every streamed turn at zero.
//  3. Tool arguments stream in fragments across frames, indexed by
//     `delta.tool_calls[].index`. Concatenating by index is the only way to
//     reassemble them; parsing each frame alone yields broken JSON.
//
// Parsing is incremental, not all-at-once: `createGatewayStreamAccumulator`
// takes text fragments (a chunk boundary can land anywhere — mid-frame,
// mid-JSON, mid-UTF-8 code point, which the caller's `TextDecoder` has already
// handled) and returns the assistant text fragments each fragment completed. A
// line buffer is the whole strategy: split on `\n`, keep the tail, dispatch on
// the blank line that ends a frame. The buffered `parseGatewayStream` is the
// same accumulator fed one whole body, so the two can never disagree.
//
// The parser is total: hostile or malformed upstream text can never throw, it
// only marks the parse `malformed` (an upstream failure the loop reports as a
// typed error event).

import { asRecord } from "../json";
import type { ChatToolCall } from "./client";
import { parseUsage, type AiUsage } from "./usage";

/** Terminal frame the OpenAI-compatible gateway sends. */
export const STREAM_DONE_MARKER = "[DONE]";

export interface GatewayStreamParse {
  /** Text fragments in arrival order; concatenated they are `text`. */
  chunks: string[];
  text: string;
  toolCalls: ChatToolCall[];
  /** Last non-null `finish_reason` observed. */
  finishReason: string | null;
  usage: AiUsage | null;
  model: string | null;
  /**
   * True when the provider signalled the end of the stream (`[DONE]` or a
   * `finish_reason`). A body without either is a cut-off response.
   */
  complete: boolean;
  /** True exactly when the terminal `[DONE]` marker was seen. */
  done: boolean;
  /** True when a `data:` frame was not valid JSON. */
  malformed: boolean;
}

interface PartialToolCall {
  id: string;
  type: string;
  name: string;
  args: string;
}

interface AccumulatorState {
  result: GatewayStreamParse;
  toolCalls: Map<number, PartialToolCall>;
}

function mergeToolCalls(raw: unknown, into: Map<number, PartialToolCall>): void {
  if (!Array.isArray(raw)) return;
  for (const entry of raw) {
    const call = asRecord(entry);
    if (call === null) continue;
    const index = typeof call["index"] === "number" ? call["index"] : 0;
    const current = into.get(index) ?? { id: "", type: "function", name: "", args: "" };
    const id = call["id"];
    const type = call["type"];
    if (typeof id === "string" && id !== "") current.id = id;
    if (typeof type === "string" && type !== "") current.type = type;
    const fn = asRecord(call["function"]);
    if (fn !== null) {
      const name = fn["name"];
      if (typeof name === "string" && name !== "") current.name = name;
      const args = fn["arguments"];
      // Fragments are appended, never replaced: a later frame carries the tail.
      if (typeof args === "string") current.args += args;
    }
    into.set(index, current);
  }
}

/** One `data:` payload. Returns the assistant text fragments it carried. */
function dispatchPayload(payload: string, state: AccumulatorState): string[] {
  const added: string[] = [];
  if (payload.trim() === STREAM_DONE_MARKER) {
    state.result.done = true;
    state.result.complete = true;
    return added;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    state.result.malformed = true;
    return added;
  }
  const root = asRecord(parsed);
  if (root === null) {
    state.result.malformed = true;
    return added;
  }
  const model = root["model"];
  if (typeof model === "string" && model !== "") state.result.model = model;
  const usage = root["usage"];
  if (asRecord(usage) !== null) state.result.usage = parseUsage(usage);
  const choices = Array.isArray(root["choices"]) ? root["choices"] : [];
  const choice = asRecord(choices[0]);
  if (choice === null) return added;
  const finishReason = choice["finish_reason"];
  if (typeof finishReason === "string" && finishReason !== "") {
    state.result.finishReason = finishReason;
    state.result.complete = true;
  }
  const delta = asRecord(choice["delta"]);
  if (delta === null) return added;
  const content = delta["content"];
  // Only `content` is answer text. `reasoning_content` (and the provider's
  // spellings of it) is thinking: it must never reach the reader as prose.
  // Thinking tokens are billed through `usage.reasoning_tokens` instead.
  if (typeof content === "string" && content !== "") {
    added.push(content);
    state.result.chunks.push(content);
  }
  mergeToolCalls(delta["tool_calls"], state.toolCalls);
  return added;
}

function finalize(state: AccumulatorState): GatewayStreamParse {
  state.result.text = state.result.chunks.join("");
  state.result.toolCalls = [...state.toolCalls.entries()]
    .sort(([left], [right]) => left - right)
    .map(([, call]) => ({
      id: call.id,
      type: call.type,
      function: { name: call.name, arguments: call.args },
    }))
    .filter((call) => call.function.name !== "");
  return { ...state.result, chunks: [...state.result.chunks] };
}

/**
 * A line-buffered SSE parser. `push` may be called with any slice of the
 * body — one byte, half a frame, several frames — and never withholds a
 * completed frame.
 */
export interface GatewayStreamAccumulator {
  /** Feeds one decoded text fragment; returns the text fragments it completed. */
  push(fragment: string): string[];
  /** Flushes the trailing line/frame of a body that did not end in a blank line. */
  end(): string[];
  /** The round as it stands; safe to call at any point, including mid-stream. */
  snapshot(): GatewayStreamParse;
}

export function createGatewayStreamAccumulator(): GatewayStreamAccumulator {
  const state: AccumulatorState = {
    result: {
      chunks: [],
      text: "",
      toolCalls: [],
      finishReason: null,
      usage: null,
      model: null,
      complete: false,
      done: false,
      malformed: false,
    },
    toolCalls: new Map<number, PartialToolCall>(),
  };
  let lineBuffer = "";
  let dataLines: string[] = [];

  const consumeLine = (line: string, added: string[]): void => {
    if (line === "") {
      // A blank line is the frame terminator. An empty frame dispatches nothing.
      if (dataLines.length === 0) return;
      const payload = dataLines.join("\n");
      dataLines = [];
      added.push(...dispatchPayload(payload, state));
      return;
    }
    // `:` comment, `event:`, `id:` and `retry:` carry nothing we consume.
    if (!line.startsWith("data:")) return;
    const value = line.slice("data:".length);
    dataLines.push(value.startsWith(" ") ? value.slice(1) : value);
  };

  return {
    push(fragment: string): string[] {
      const added: string[] = [];
      if (typeof fragment !== "string" || fragment === "") return added;
      lineBuffer += fragment;
      let newline = lineBuffer.indexOf("\n");
      while (newline !== -1) {
        let line = lineBuffer.slice(0, newline);
        lineBuffer = lineBuffer.slice(newline + 1);
        // `\r\n` is legal SSE; the `\r` never belongs to the line.
        if (line.endsWith("\r")) line = line.slice(0, -1);
        consumeLine(line, added);
        newline = lineBuffer.indexOf("\n");
      }
      return added;
    },
    end(): string[] {
      const added: string[] = [];
      if (lineBuffer !== "") {
        let line = lineBuffer;
        lineBuffer = "";
        if (line.endsWith("\r")) line = line.slice(0, -1);
        consumeLine(line, added);
      }
      // A body whose last frame has no trailing blank line still dispatches.
      if (dataLines.length > 0) {
        const payload = dataLines.join("\n");
        dataLines = [];
        added.push(...dispatchPayload(payload, state));
      }
      return added;
    },
    snapshot(): GatewayStreamParse {
      return finalize(state);
    },
  };
}

/**
 * Parses a buffered gateway SSE body. Kept for callers that have the whole
 * body (and for tests that want a deterministic one-shot view); it is the same
 * accumulator, fed once.
 */
export function parseGatewayStream(raw: string): GatewayStreamParse {
  const accumulator = createGatewayStreamAccumulator();
  if (typeof raw === "string" && raw !== "") {
    accumulator.push(raw);
    accumulator.end();
  }
  return accumulator.snapshot();
}
