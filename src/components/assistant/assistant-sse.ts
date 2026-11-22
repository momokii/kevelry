// The client half of the assistant's event stream.
//
// `EventSource` cannot POST, so the desk reads `response.body` itself and parses
// frames as they arrive. That is the same job `gateway-stream.ts` does
// server-side, and it has the same two hazards:
//
//  1. **A frame boundary can land anywhere.** A chunk may end mid-frame,
//     mid-`data:` line, mid-JSON, or between the two newlines that end a frame.
//     So the parser holds a buffer and only emits a frame once its terminating
//     blank line has actually arrived; the tail stays buffered.
//  2. **A character can be split across chunks.** The caller decodes with
//     `TextDecoder({ stream: true })`, so a multi-byte code point is held until
//     its remaining bytes arrive — the parser never sees a mangled string.
//
// The parser is total: an unterminated frame at the end of the stream is
// discarded (`flush()`), because a half frame is an interruption, not an event.
// A frame the server never sends is never invented.

import type { AssistantEvent } from "@/lib/ai/turn";

/** One frame's payload: the `data:` lines joined by newline. */
const CRLF = /\r\n/g;

/** Payloads the desk acts on. Anything else is not part of the contract. */
const EVENT_TYPES = ["tool", "delta", "citations", "done", "error"] as const;

export interface AssistantSseParser {
  /** Feeds one decoded chunk; returns every frame that is now complete. */
  push(chunk: string): string[];
  /**
   * Ends the stream. Returns nothing: a trailing partial frame is a truncated
   * response, and the caller reports that as a fault rather than parsing half
   * an event.
   */
  flush(): string[];
}

/**
 * Parses one SSE block into its `data` payload, or `null` when the block carries
 * no data (a comment block, or a keep-alive blank).
 */
export function framePayload(block: string): string | null {
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line === "" || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    if (field !== "data") continue;
    // One optional space is part of the encoding, not of the payload.
    const value = colon === -1 ? "" : line.slice(colon + 1);
    data.push(value.startsWith(" ") ? value.slice(1) : value);
  }
  return data.length === 0 ? null : data.join("\n");
}

export function createAssistantSseParser(): AssistantSseParser {
  let buffer = "";
  return {
    push(chunk: string): string[] {
      // Normalising the whole buffer (not the chunk) keeps a `\r\n` that
      // straddles two chunks a single terminator.
      buffer = (buffer + chunk).replace(CRLF, "\n");
      const payloads: string[] = [];
      for (;;) {
        const end = buffer.indexOf("\n\n");
        if (end === -1) break;
        const block = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        const payload = framePayload(block);
        if (payload !== null) payloads.push(payload);
      }
      return payloads;
    },
    flush(): string[] {
      buffer = "";
      return [];
    },
  };
}

/** Validates one payload into an event. Unknown shapes are dropped, not guessed. */
export function parseAssistantEvent(payload: string): AssistantEvent | null {
  const text = payload.trim();
  if (text === "" || text === "[DONE]") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const type = (parsed as { type?: unknown }).type;
  if (typeof type !== "string" || !(EVENT_TYPES as readonly string[]).includes(type)) return null;
  return parsed as AssistantEvent;
}
