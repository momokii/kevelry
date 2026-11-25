// The fake transport reads the question it is answering.
//
// The browser suite depends on that: `as a table`, `with a heading` and the
// unsupported id are all markers in the question text, and a question that has
// an image attached reaches the provider as an array of content parts rather
// than a string. While `latestUserMessage` returned `""` for an array, every
// marker after an attach was silently dropped — three journeys would have failed
// for a reason that has nothing to do with images.
//
// What this file proves: the array form is read as its text parts concatenated,
// the string form still works, and an image-only message is simply empty. What
// it does not prove: that the real gateway sends the same shapes. The fixtures
// are the evidence for that.

import { describe, expect, it } from "vitest";

import {
  AI_FAKE_HEADING_MARKER,
  AI_FAKE_TABLE_MARKER,
  createFakeAssistantTransport,
} from "../app/api/assistant/_lib/fake-transport";

const SIGNAL = new AbortController().signal;

async function readBody(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value !== undefined) text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/** Round one is the tool call; round two is the prose the answer is read from. */
async function answerFor(content: unknown): Promise<string> {
  const transport = createFakeAssistantTransport(0, 0);
  await transport({
    url: "https://gateway.invalid/chat/completions",
    headers: {},
    body: JSON.stringify({ messages: [{ role: "user", content: "Warm the round." }] }),
    signal: SIGNAL,
  });
  const answer = await transport({
    url: "https://gateway.invalid/chat/completions",
    headers: {},
    body: JSON.stringify({ messages: [{ role: "user", content }] }),
    signal: SIGNAL,
  });
  if (answer.stream === undefined || answer.stream === null) {
    throw new Error("the fake answers with a stream");
  }
  return readBody(answer.stream);
}

describe("the fake transport reads the latest user message", () => {
  it("[CODE] finds the markers in a question sent as content parts", async () => {
    const body = await answerFor([
      { type: "text", text: `Which KEV entries were added? Answer ${AI_FAKE_TABLE_MARKER}.` },
      { type: "image_url", image_url: { url: "data:image/png;base64,iVBORw0KGgo=" } },
      { type: "text", text: `Also ${AI_FAKE_HEADING_MARKER}.` },
    ]);
    expect(body).toContain("| Metric | Value | Note |");
    expect(body).toContain("### Canned answer");
  });

  it("[CODE] still reads a question sent as a plain string", async () => {
    const body = await answerFor(`Which KEV entries were added? Answer ${AI_FAKE_TABLE_MARKER}.`);
    expect(body).toContain("| Metric | Value | Note |");
    expect(body).not.toContain("### Canned answer");
  });

  it("[CODE] treats an image-only message as no question rather than inventing one", async () => {
    const body = await answerFor([
      { type: "image_url", image_url: { url: "data:image/png;base64," } },
    ]);
    expect(body).toContain("canned answer of the test transport");
    expect(body).not.toContain("| Metric | Value | Note |");
    expect(body).not.toContain("### Canned answer");
  });
});
