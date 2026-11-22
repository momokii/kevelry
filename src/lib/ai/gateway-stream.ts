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
// The parser is total: hostile or malformed upstream text can never throw, it
// only marks the parse `malformed` (an upstream failure the loop reports as a
// typed error event).

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
  /**
   * True when the provider signalled the end of the stream (`[DONE]` or a
   * `finish_reason`). A body without either is a cut-off response.
   */
  complete: boolean;
  /** True when a `data:` frame was not valid JSON. */
  malformed: boolean;
}

interface PartialToolCall {
  id: string;
  type: string;
  name: string;
  args: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** One SSE frame's payload lines, joined the way the SSE spec defines them. */
function frameData(frame: string): string | null {
  const lines = frame.split("\n");
  const data: string[] = [];
  for (const line of lines) {
    // `:` comment, `event:`, `id:` and `retry:` carry nothing we consume.
    if (!line.startsWith("data:")) continue;
    const value = line.slice("data:".length);
    data.push(value.startsWith(" ") ? value.slice(1) : value);
  }
  return data.length === 0 ? null : data.join("\n");
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

/**
 * Parses a buffered gateway SSE body.
 *
 * A buffered parse still preserves frame order, which is what the route's
 * `delta` events promise; a streaming transport would hand the same frames
 * over earlier, and the shape here is what it would produce.
 */
export function parseGatewayStream(raw: string): GatewayStreamParse {
  const result: GatewayStreamParse = {
    chunks: [],
    text: "",
    toolCalls: [],
    finishReason: null,
    usage: null,
    complete: false,
    malformed: false,
  };
  if (typeof raw !== "string" || raw.trim() === "") return result;

  const toolCalls = new Map<number, PartialToolCall>();
  // `\r\n` is legal SSE; normalising keeps one frame separator.
  const frames = raw.replace(/\r\n/gu, "\n").split("\n\n");
  for (const frame of frames) {
    const payload = frameData(frame);
    if (payload === null) continue;
    if (payload.trim() === STREAM_DONE_MARKER) {
      result.complete = true;
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      result.malformed = true;
      continue;
    }
    const root = asRecord(parsed);
    if (root === null) {
      result.malformed = true;
      continue;
    }
    const usage = root["usage"];
    if (asRecord(usage) !== null) result.usage = parseUsage(usage);
    const choices = Array.isArray(root["choices"]) ? root["choices"] : [];
    const choice = asRecord(choices[0]);
    if (choice === null) continue;
    const finishReason = choice["finish_reason"];
    if (typeof finishReason === "string" && finishReason !== "") {
      result.finishReason = finishReason;
      result.complete = true;
    }
    const delta = asRecord(choice["delta"]);
    if (delta === null) continue;
    const content = delta["content"];
    if (typeof content === "string" && content !== "") {
      result.chunks.push(content);
    }
    mergeToolCalls(delta["tool_calls"], toolCalls);
  }

  result.text = result.chunks.join("");
  result.toolCalls = [...toolCalls.entries()]
    .sort(([left], [right]) => left - right)
    .map(([, call]) => ({
      id: call.id,
      type: call.type,
      function: { name: call.name, arguments: call.args },
    }))
    .filter((call) => call.function.name !== "");
  return result;
}
