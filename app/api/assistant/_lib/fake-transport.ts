// A canned provider for the browser suite.
//
// The e2e journey needs a turn that streams a tool call and then prose, and it
// must run with no socket and no key. `AI_FAKE_TRANSPORT=1` swaps the transport
// for the stream below; every other frame in the app — the route's guards, the
// tool loop, the real tool against the real database, the SSE encoding — is the
// production path.
//
// It is a test hook, and it behaves like one: it refuses to activate under
// `APP_ENV=production`, so a deployment cannot be talked into serving invented
// answers. `resolveAssistantTransport()` is the only caller.
//
// The stream deliberately yields between writes so the browser can paint an
// intermediate state (a mid-stream screenshot), and it terminates with the same
// `[DONE]` marker a real gateway sends.

import type { AiTransport, AiTransportResponse } from "../../../../src/lib/ai/client";

/** The switch itself, spelled once so the docs and the tests cannot drift. */
export const AI_FAKE_TRANSPORT_ENV = "AI_FAKE_TRANSPORT";

/**
 * An id the fake names in prose but no tool ever returns.
 *
 * The browser suite needs one answer that contains an id the dataset never
 * returned, and the fake is the only provider it has. Asking a question that
 * contains this id makes the canned answer repeat it: exactly the model failure
 * the `unverified` frame exists to catch, and no other journey is touched.
 */
export const AI_FAKE_UNSUPPORTED_ID = "CVE-2099-9999";

/**
 * A question naming this phrase gets a canned Markdown table back.
 *
 * Same trigger shape as the unsupported id above, and for the same reason: the
 * browser suite has no live model, and a rendered table is a property of the
 * desk the audit has to see. The table carries no record ids, so it cannot
 * disturb the citation or unverified accounting of the other journeys.
 */
export const AI_FAKE_TABLE_MARKER = "as a table";

/**
 * A question naming this phrase gets a canned Markdown heading back.
 *
 * Same shape and same reason as the table marker: the desk clamps a model
 * heading to `h3`/`h4`, so the answer's first heading is the level that would
 * skip under the page `h1` if the transcript region had no heading of its own.
 * The browser suite needs an answer that really carries one to audit that.
 */
export const AI_FAKE_HEADING_MARKER = "with a heading";

/**
 * A question naming this phrase gets an answer whose stream dies mid-sentence.
 *
 * Same trigger shape as the markers above, and for the same reason: the browser
 * suite has no provider that can fail on demand, and "the connection dropped"
 * is the failure a reader meets most often. The body carries one delta and then
 * the source errors — no finish reason, no usage block, no `[DONE]`, exactly the
 * shape of a socket that dies while the model is still writing. The route's own
 * turn loop turns that into an `error` frame, so everything under test from the
 * provider inwards is the production path.
 */
export const AI_FAKE_ABORT_MARKER = "drop the connection";

/**
 * How many times the marker above may break a stream in this process.
 *
 * One, deliberately. A retry re-sends the same question, so a marker that broke
 * every attempt could never prove the half of the journey that matters most —
 * that asking again works. The first attempt dies; every later one is answered
 * in full.
 */
let abortBudget = 1;

/** One pause between frames; long enough to paint, short enough for a suite. */
export const AI_FAKE_FRAME_DELAY_MS = 45;

/**
 * The gap between the tool frame and the first answer token.
 *
 * A real reasoning turn thinks for seconds between "reading the records" and
 * the first word of prose, so the fake pauses too: it keeps the streaming state
 * on screen long enough for a reader — or a browser test — to see it, and it is
 * the honest shape of the thing being imitated rather than a faster fiction.
 */
export const AI_FAKE_ANSWER_DELAY_MS = 800;

/**
 * True only when the caller asked for the fake *and* this is not production.
 * `APP_ENV` is the app's own environment marker, not `NODE_ENV`.
 */
export function fakeAssistantTransportEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[AI_FAKE_TRANSPORT_ENV] === "1" && env.APP_ENV !== "production";
}

function frame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

const USAGE = {
  prompt_tokens: 420,
  completion_tokens: 60,
  reasoning_tokens: 0,
  cache_read_tokens: 0,
  opencode: { list_cost: 0.02 },
};

/** Round one: ask for the KEV window, which the real tool resolves. */
function toolRound(): string {
  return [
    frame({
      choices: [
        {
          delta: {
            tool_calls: [
              { index: 0, id: "call_fake_1", type: "function", function: { name: "kev_window" } },
            ],
          },
        },
      ],
    }),
    frame({
      choices: [
        {
          delta: {
            tool_calls: [{ index: 0, function: { arguments: '{"days":30}' } }],
          },
        },
      ],
    }),
    frame({ choices: [{ delta: {}, finish_reason: "tool_calls" }] }),
    frame({ choices: [], usage: USAGE }),
    "data: [DONE]\n\n",
  ].join("");
}

const ANSWER_LINES = [
  "This is the canned answer of the test transport, not a model's reply. ",
  "The rows above are real: the tool call ran against the instance's own database. ",
  "A live deployment never reaches this text.",
];

/**
 * The table the fake appends when the question asks for one. It is written the
 * way a model writes one — header row, dash separator, body rows — so the desk's
 * renderer, not a fixture, is what turns it into a `<table>`.
 */
const TABLE_LINES = [
  "\n\n| Metric | Value | Note |\n",
  "| --- | --- | --- |\n",
  "| Transport | fake | no socket, no key |\n",
  "| Answer | canned | a live deployment never reaches this text |\n",
];

/**
 * Round two: prose, then the terminal usage frame.
 *
 * `abortAfterFirstDelta` cuts the body down to its opening delta, for the
 * journey that has to survive a provider dying mid-answer.
 */
function answerRound(
  unsupportedId: boolean,
  table: boolean,
  heading: boolean,
  abortAfterFirstDelta: boolean,
): string {
  const lines = unsupportedId
    ? [
        ...ANSWER_LINES,
        `The id ${AI_FAKE_UNSUPPORTED_ID} was named in the question, and no tool above returned it. `,
      ]
    : [...ANSWER_LINES];
  if (heading) lines.unshift("### Canned answer\n\n");
  if (table) lines.push(...TABLE_LINES);
  const frames: string[] = [];
  for (const line of lines) {
    frames.push(frame({ choices: [{ delta: { content: line }, finish_reason: null }] }));
  }
  if (abortAfterFirstDelta) {
    // One delta, and then the source dies: the body ends without the frames
    // that would make it a complete round. The pause before this frame is the
    // answer delay, so the reader sees prose on screen before it breaks.
    return frames[0] ?? "";
  }
  frames.push(frame({ choices: [{ delta: {}, finish_reason: "stop" }] }));
  frames.push(frame({ choices: [], usage: USAGE }));
  frames.push("data: [DONE]\n\n");
  return frames.join("");
}

/**
 * One message's text, whether the provider was sent a string or content parts.
 *
 * A user message carrying an image is an array of parts (`{ type: "text" }` plus
 * `{ type: "image_url" }`), and reading only the string form silently drops the
 * question — which would disable this fake's markers on every turn after an
 * attach for a reason that has nothing to do with images.
 */
function messageText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      parts.push(part);
      continue;
    }
    if (typeof part !== "object" || part === null) continue;
    const candidate = part as { type?: unknown; text?: unknown };
    if (candidate.type === "text" && typeof candidate.text === "string") {
      parts.push(candidate.text);
    }
  }
  return parts.join("");
}

/**
 * The latest user message in the body the route built. Round two's body ends with
 * a tool result, so the last *user* message is the one to read.
 */
function latestUserMessage(body: string): string {
  try {
    const parsed = JSON.parse(body) as { messages?: Array<{ role?: unknown; content?: unknown }> };
    const messages = parsed.messages ?? [];
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index];
      if (message?.role !== "user") continue;
      return messageText(message.content);
    }
    return "";
  } catch {
    return "";
  }
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * A transport that answers the first round with a tool call and every later
 * round with canned prose. The body is written in slices, so the consumer sees
 * the same split-frame reality a network produces.
 */
export function createFakeAssistantTransport(
  delayMs: number = AI_FAKE_FRAME_DELAY_MS,
  answerDelayMs: number = AI_FAKE_ANSWER_DELAY_MS,
): AiTransport {
  let round = 0;
  const transport: AiTransport = async (request): Promise<AiTransportResponse> => {
    const answering = round > 0;
    const question = answering ? latestUserMessage(request.body) : "";
    // Only an answering round can die: the tool round has to run for the desk to
    // have anything to show, and the one-shot budget is spent by the first
    // answer that asks for it.
    const aborts =
      answering && abortBudget > 0 && question.toLowerCase().includes(AI_FAKE_ABORT_MARKER);
    if (aborts) abortBudget -= 1;
    const body = answering
      ? answerRound(
          question.includes(AI_FAKE_UNSUPPORTED_ID),
          question.toLowerCase().includes(AI_FAKE_TABLE_MARKER),
          question.toLowerCase().includes(AI_FAKE_HEADING_MARKER),
          aborts,
        )
      : toolRound();
    round += 1;
    const encoder = new TextEncoder();
    const bytes = encoder.encode(body);
    // Slice mid-frame on purpose: a parser that only works on whole frames is
    // the bug the real SSE parser is written to survive.
    const step = Math.max(1, Math.ceil(bytes.byteLength / 6));
    let cursor = 0;
    // A pull source, not a start-loop: the error below must arrive *after* the
    // delta has been consumed, and a stream that queues ahead would drop queued
    // chunks when it errored — the reader would lose the very frame the abort
    // journey asserts on. One chunk in flight at a time fixes the order.
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (cursor >= bytes.byteLength) {
          if (aborts) {
            controller.error(new Error("The provider's connection dropped mid-answer."));
            return;
          }
          controller.close();
          return;
        }
        if (cursor === 0 && answering) await pause(answerDelayMs);
        else if (cursor > 0) await pause(delayMs);
        controller.enqueue(bytes.slice(cursor, Math.min(cursor + step, bytes.byteLength)));
        cursor += step;
      },
    });
    return { status: 200, body: "", contentType: "text/event-stream", stream };
  };
  return transport;
}
