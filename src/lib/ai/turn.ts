// The assistant's turn loop: one guarded POST body in, one ordered SSE stream
// out. Stateless — the client holds the transcript, the server holds nothing.
//
// The loop is an async generator so the route can pump frames as they happen
// and a test can consume the same generator without an HTTP hop. Every event is
// a fact the UI needs:
//
//   tool       emitted *before* the result is fed back, so the reader sees
//              "reading 1 record…" while the model is still working, and carrying
//              the ids *that call* returned so the ledger can chip them — the
//              terminal `citations` event is the whole turn and cannot be
//              attributed back to one call.
//   delta      assistant text, in arrival order.
//   retry      a round ended with no text and no tool calls — cut by its
//              completion cap, stopped with nothing in it at all, or the final
//              answer round came back empty — so it is re-run once. Emitted
//              before the second attempt, so the stream states the escalation
//              instead of silently billing a second round. The retry of an
//              empty answer round re-sends trimmed history, never the whole
//              transcript: a full re-send cost 42.7 s of a 45 s deadline.
//   citations  ids the *server* read from tool payloads this turn — never ids
//              the model claimed. A model-hallucinated id cannot become a chip.
//   unverified ids the *prose* named that no tool payload contained. Emitted
//              only when the list is non-empty, and never used to edit the
//              answer: the reader sees the doubt instead of losing the sentence.
//   done       token totals, cost, how many tool rounds the turn spent, and the
//              unverified list again so a downloaded brief can carry it.
//   error      a typed, redacted failure. Once the stream is open there is no
//              second HTTP status; this event is the status.
//
// Budgets enforced here, not in the prompt: the tool-round cap (4), the whole
// turn's wall-clock deadline, and one ledger write per turn (including a turn
// that failed after the provider reported usage). Nothing here logs or stores
// prompt or answer text.
//
// The cap is spent on prose, not on tools: the last permitted round is sent
// with no tool definitions at all, so a provider that keeps calling tools
// cannot end the turn with an empty answer. See `answerOnlyRound` below.

import type { CveDatabase } from "../db";
import type {
  AiClient,
  ChatMessage,
  ChatStreamReader,
  ChatStreamResult,
  ChatToolCall,
} from "./client";
import { AI_MAX_TOKENS_DEFAULT, type AiConfig } from "./config";
import {
  renderAnswerRoundInstruction,
  renderRecordContext,
  renderSystemPrompt,
  renderVisionInstruction,
} from "./prompt";
import { executeTool, toolDefinitions, type ToolContext, type ToolOutcome } from "./tools";
import type { AiUsage, AiUsageLedger } from "./usage";

/**
 * Hard cap on rounds in one turn. The plan allowed six; four is what this phase
 * ships because each round re-bills eight tool definitions and a turn that
 * needs six is a question that should be split. The last permitted round is
 * reserved for the answer — it is sent with no tools at all — so the cap can no
 * longer end a turn that never wrote one.
 */
export const ASSISTANT_MAX_TOOL_ROUNDS = 4;

/** Upper bound on citation ids one turn may report. */
export const ASSISTANT_CITATION_CAP = 200;

/**
 * Record ids a single `tool` frame carries for the provenance ledger.
 *
 * The ledger chips the records a tool call actually returned, so the ids have to
 * travel on the frame that names the call — the terminal `citations` event is the
 * whole turn and cannot be attributed back to one call. Twenty-five is a display
 * sample, not a result cap: it is the row cap of `search_cves` and `list_priority`,
 * so the common call states one number and the honest `rows · ids available` form
 * is reserved for a tool that really returns more (`kev_window` caps at 50).
 * `rows` still reports the real row count and the `citations` event still carries
 * the full set (up to the citation cap).
 */
export const ASSISTANT_TOOL_ID_SAMPLE = 25;

/** CVE id shape. The same pattern the tools validate against. */
const CVE_ID_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,}$/;

/**
 * CVE ids as they appear in prose: case-insensitive, so a model that writes
 * `cve-2021-44228` is still checked rather than slipping past the classifier.
 */
const ANSWER_ID_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

export interface AssistantMessage {
  role: "user" | "assistant";
  content: string;
}

export interface AssistantUsageFrame {
  prompt: number;
  completion: number;
  reasoning: number;
  cacheRead: number;
}

/** Error codes an SSE `error` event may carry. */
export type AssistantStreamErrorCode =
  | "AI_TIMEOUT"
  | "AI_UPSTREAM_ERROR"
  | "AI_TRUNCATED"
  | "AI_EMPTY_ANSWER"
  | "AI_BUDGET_EXHAUSTED"
  | "AI_DISABLED";

export type AssistantEvent =
  | {
      type: "tool";
      name: string;
      args: unknown;
      ok: boolean;
      rows: number;
      /** First ids the call returned, for the ledger's chips. Display sample only. */
      ids: string[];
      /**
       * The host a successful `fetch_authoritative` call read, for the citation
       * area's web chip. Absent for every other call and for a failed fetch:
       * a chip that named a host nobody read would be web evidence with no
       * evidence behind it.
       */
      web?: { url: string; host: string };
    }
  | { type: "delta"; text: string }
  | {
      type: "retry";
      /**
       * Why the round is being re-run: cut by its completion cap
       * (`AI_TRUNCATED`), or it came back with nothing to show
       * (`AI_EMPTY_ANSWER`).
       */
      code: "AI_TRUNCATED" | "AI_EMPTY_ANSWER";
      /** Completion budget the retried round is given. */
      maxTokens: number;
      /**
       * True when the retry re-sends a trimmed conversation — base system
       * prompt, the last question, an index of the tool results — instead of
       * the whole history. A full re-send of a 37k-token turn took 42.7 s of a
       * 45 s deadline, so the trimmed shape is the only one that fits.
       */
      trimmed: boolean;
    }
  | { type: "citations"; records: string[] }
  | { type: "unverified"; ids: string[] }
  | {
      type: "done";
      /**
       * What kind of answer this was. `refusal` is set by the pre-inference
       * scope filter: the desk prints a quiet label and offers no brief or
       * follow-ups, because the question was declined, not answered and not
       * failed. Absent means an ordinary answer.
       */
      kind?: "refusal";
      usage: AssistantUsageFrame;
      costUsd: number;
      rounds: number;
      /** Ids the prose named without a tool behind them; empty when none. */
      unverified: string[];
    }
  | { type: "error"; code: AssistantStreamErrorCode; message: string };

export interface AssistantTurnInput {
  config: AiConfig;
  db: CveDatabase;
  client: AiClient;
  ledger: AiUsageLedger;
  messages: readonly AssistantMessage[];
  image?: { dataUrl: string };
  cveContext?: string;
  /** Client disconnect. Aborting ends the loop and the turn's stream. */
  signal?: AbortSignal;
  /** Injected clock, so the deadline is testable without waiting. */
  now?: () => Date;
  /** Tool-layer overrides (the suite passes a short `timeoutMs`). */
  toolContext?: Partial<ToolContext>;
  /** Whole-turn budget; defaults to `config.requestTimeoutMs`. */
  turnTimeoutMs?: number;
}

/** One SSE frame. `data:`-only, so any SSE client or a plain text reader works. */
export function encodeAssistantEvent(event: AssistantEvent): string {
  return `data: ${JSON.stringify(event)}\n\n`;
}

/**
 * Ids the server actually read, from any tool payload shape.
 *
 * Deliberately generic: every tool nests ids differently (`items[].cveId`,
 * `record.cveId`, `points[]` for history), and a per-tool extractor would be a
 * second place to forget when a tool is added. Only strings matching the id
 * shape are collected, depth- and count-bounded so a hostile payload cannot
 * turn this into a walk of a huge object graph.
 */
export function collectRecordIds(value: unknown): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const walk = (node: unknown, depth: number): void => {
    if (found.length >= ASSISTANT_CITATION_CAP || depth > 6) return;
    if (typeof node === "string") {
      if (CVE_ID_PATTERN.test(node) && !seen.has(node)) {
        seen.add(node);
        found.push(node);
      }
      return;
    }
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry, depth + 1);
      return;
    }
    if (typeof node === "object" && node !== null) {
      for (const entry of Object.values(node)) walk(entry, depth + 1);
    }
  };
  walk(value, 0);
  return found;
}

/**
 * Every record id the answer text names, deduplicated and case-normalised.
 *
 * This is the prose side of the provenance rule: `collectRecordIds` walks what a
 * tool returned, this walks what the reader was told. It is a separate walk on
 * purpose — the answer is a string, not a payload, and a single regex is the
 * whole extraction rule.
 */
export function extractAnswerIds(text: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(ANSWER_ID_PATTERN)) {
    const id = match[0].toUpperCase();
    if (seen.has(id)) continue;
    seen.add(id);
    found.push(id);
  }
  return found;
}

/**
 * Ids in the prose that no tool payload in this turn contained.
 *
 * `verified` is the set the turn already collected from tool results — the same
 * set `citations` reports — so a citation and a verified id cannot disagree.
 * The list is complete rather than sampled: the answer is bounded by the model's
 * token cap, and a dropped id would be exactly the silent omission this check
 * exists to prevent.
 */
export function unverifiedAnswerIds(text: string, verified: ReadonlySet<string>): string[] {
  return extractAnswerIds(text).filter((id) => !verified.has(id));
}

/** `{ ok: true, value }` or `{ ok: false }`: the model's JSON was not an object. */
function parseToolArguments(raw: string): { ok: true; value: unknown } | { ok: false } {
  const text = raw.trim();
  if (text === "") return { ok: true, value: {} };
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? { ok: true, value: parsed }
      : { ok: false };
  } catch {
    return { ok: false };
  }
}

/** The message list sent on round one: prompt, image rule, then the history. */
export function buildConversation(input: AssistantTurnInput): ChatMessage[] {
  const conversation: ChatMessage[] = [
    {
      role: "system",
      content: renderSystemPrompt({ webFetchEnabled: input.config.webFetchEnabled }),
    },
  ];
  if (input.image !== undefined) {
    conversation.push({ role: "system", content: renderVisionInstruction() });
  }
  if (input.cveContext !== undefined) {
    conversation.push({ role: "system", content: renderRecordContext(input.cveContext) });
  }
  const lastIndex = input.messages.length - 1;
  for (const [index, message] of input.messages.entries()) {
    if (index === lastIndex && input.image !== undefined) {
      // One image part, on the last user message only; never a second copy.
      conversation.push({
        role: "user",
        content: [
          { type: "text", text: message.content },
          { type: "image_url", image_url: { url: input.image.dataUrl } },
        ],
      });
      continue;
    }
    conversation.push({ role: message.role, content: message.content });
  }
  return conversation;
}

interface Totals extends AssistantUsageFrame {
  costUsd: number;
}

function addUsage(totals: Totals, usage: AiUsage | null): boolean {
  if (usage === null) return false;
  totals.prompt += usage.promptTokens;
  totals.completion += usage.completionTokens;
  totals.reasoning += usage.reasoningTokens;
  totals.cacheRead += usage.cacheReadTokens;
  totals.costUsd += usage.listCostUsd;
  return true;
}

/**
 * A tool failure fed back to the model. Shape-identical to `ToolFailure` minus
 * the free text, so a malformed argument list reads the same as a rejected one.
 */
function malformedArguments(name: string): ToolOutcome {
  return {
    ok: false,
    tool: name,
    reason: "BAD_ARGUMENT",
    error: "Tool arguments were not a JSON object.",
  };
}

/**
 * The host a successful web fetch read, for the citation area's chip.
 *
 * The server, not the client, is the authority on which host answered: the URL
 * the model asked for can differ from the one that was read when a single
 * allow-listed redirect was followed. Anything but a successful fetch yields
 * nothing, so a refused URL never becomes a chip.
 */
function webEvidence(name: string, outcome: ToolOutcome): { url: string; host: string } | null {
  if (name !== "fetch_authoritative" || !outcome.ok) return null;
  const data: unknown = outcome.data;
  if (typeof data !== "object" || data === null) return null;
  const { url, host } = data as { url?: unknown; host?: unknown };
  if (typeof url !== "string" || typeof host !== "string") return null;
  return { url, host };
}

function toolMessage(call: ChatToolCall, outcome: ToolOutcome): ChatMessage {
  return {
    role: "tool",
    tool_call_id: call.id,
    name: call.function.name,
    content: JSON.stringify(outcome),
  };
}

/**
 * One completed tool call, kept compact for the trimmed retry.
 *
 * Ids, a row count and the arguments that asked for them — never the payload.
 * The answer is written from the evidence, so the retry needs an index of it,
 * not a second copy of it.
 */
interface GatheredCall {
  name: string;
  args: string;
  ok: boolean;
  rows: number;
  ids: string[];
}

/** Caps that keep the trimmed retry an index of the evidence, not a payload. */
const SUMMARY_ARGS_CHARS = 120;
const SUMMARY_IDS_PER_CALL = 5;
const SUMMARY_MAX_CALLS = 12;

/** Bounded JSON, for one call's arguments in the compact summary. */
function compactJson(value: unknown, limit: number): string {
  let text: string;
  try {
    text = JSON.stringify(value) ?? "";
  } catch {
    // A value that cannot be serialised contributes no arguments, not a throw.
    text = "";
  }
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

/**
 * The compact index of what the tools returned, sent with the trimmed retry.
 *
 * Bounded on every axis — calls, ids per call, argument length — because the
 * retry exists to be cheap: the measured turn spent 42.7 s of its 45 s deadline
 * re-sending a 37k-token transcript, so a retry that is merely "smaller" would
 * turn an empty turn into a timeout.
 */
function summariseGathered(calls: readonly GatheredCall[]): string {
  const header =
    "[tool evidence] The tools already ran this turn. Their full results are not repeated here; this is what they returned:";
  if (calls.length === 0) return `${header} nothing.`;
  const lines = calls.slice(0, SUMMARY_MAX_CALLS).map((call, index) => {
    const shown = call.ids.slice(0, SUMMARY_IDS_PER_CALL);
    const rest = call.ids.length - shown.length;
    const outcome = call.ok ? `${String(call.rows)} row(s)` : "failed";
    const ids =
      shown.length === 0
        ? ""
        : `; ids ${shown.join(", ")}${rest > 0 ? ` (+${String(rest)} more)` : ""}`;
    return `${String(index + 1)}. ${call.name}(${call.args}) → ${outcome}${ids}`;
  });
  const omitted = calls.length - lines.length;
  if (omitted > 0) lines.push(`(${String(omitted)} further call(s) omitted.)`);
  return [header, ...lines].join("\n");
}

/**
 * The conversation as the answer round sends it: the same messages, with the
 * final-round rule appended to the leading system prompt.
 *
 * A copy, not a mutation: the rule belongs to that one round, and a transcript
 * that carries it would keep telling a later turn that no tools exist.
 */
function withAnswerRoundRule(conversation: readonly ChatMessage[]): ChatMessage[] {
  const [first, ...rest] = conversation;
  if (first === undefined || first.role !== "system" || typeof first.content !== "string") {
    return [{ role: "system", content: renderAnswerRoundInstruction() }, ...conversation];
  }
  return [{ ...first, content: `${first.content}\n\n${renderAnswerRoundInstruction()}` }, ...rest];
}

/**
 * The one retry of an empty answer round: base prompt, last question, and the
 * compact index of what the tools returned.
 *
 * Everything else — assistant tool-call turns, tool messages, the record-scope
 * note that asks for a call this round cannot make — is dropped. The reader's
 * question keeps its content parts, so an image turn still carries its image.
 */
function buildTrimmedConversation(
  conversation: readonly ChatMessage[],
  calls: readonly GatheredCall[],
): ChatMessage[] {
  const [first] = conversation;
  const lastUser = [...conversation].reverse().find((message) => message.role === "user");
  const head: ChatMessage = {
    role: "system",
    content: [
      first !== undefined && typeof first.content === "string" ? first.content : "",
      summariseGathered(calls),
    ]
      .filter((part) => part !== "")
      .join("\n\n"),
  };
  return lastUser === undefined ? [head] : [head, lastUser];
}

/** Maps a client failure to a stream event. Never echoes an upstream body. */
function failureEvent(error: unknown): AssistantEvent {
  if (error instanceof Error && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (
      code === "AI_TIMEOUT" ||
      code === "AI_UPSTREAM_ERROR" ||
      code === "AI_TRUNCATED" ||
      code === "AI_DISABLED"
    ) {
      // `error.message` is written in this repo; `upstreamMessage` (an excerpt
      // of the provider's own body) is deliberately never read here.
      return { type: "error", code, message: error.message };
    }
  }
  return {
    type: "error",
    code: "AI_UPSTREAM_ERROR",
    message: "The AI provider could not complete the answer.",
  };
}

/**
 * Runs one turn. Yields events in the order the contract fixes; the terminal
 * `done` or `error` is always the last frame. Usage is recorded exactly once,
 * in the `finally`, so an early `return()` from the consumer (stream cancel)
 * still bills what the provider reported.
 */
export async function* runAssistantTurn(input: AssistantTurnInput): AsyncGenerator<AssistantEvent> {
  const now = input.now ?? (() => new Date());
  const startedAt = now().getTime();
  const turnTimeoutMs = input.turnTimeoutMs ?? input.config.requestTimeoutMs;
  const deadline = startedAt + Math.max(1, turnTimeoutMs);
  const totals: Totals = { prompt: 0, completion: 0, reasoning: 0, cacheRead: 0, costUsd: 0 };
  const citationIds = new Set<string>();
  // The prose exactly as the reader received it: every delta, in order. The
  // answer the model wrote in an earlier round that ended in tool calls is on
  // screen too, so it is classified too.
  let answerText = "";
  let usageSeen = false;
  let rounds = 0;
  let answered = false;
  /** One empty round may be re-run at the answer budget, never two. */
  let retriedEmptyRound = false;
  let activeStream: ChatStreamReader | null = null;

  // The turn's single web-fetch allowance. Created here, spent by the tool
  // dispatcher: the prompt says one fetch per turn, and this makes a second one
  // impossible without trusting the model to obey a sentence.
  const webFetchBudget = { used: false };
  const toolCtx: ToolContext = {
    db: input.db,
    webFetchEnabled: input.config.webFetchEnabled,
    now,
    ...input.toolContext,
    webFetchBudget,
  };
  const tools = toolDefinitions(input.config.webFetchEnabled);
  let conversation = buildConversation(input);
  // Every tool call this turn ran, as the compact index the retry re-sends.
  const gathered: GatheredCall[] = [];
  // The answer round gets the larger budget; a tool round does not need it.
  const answerMaxTokens = Math.max(1, Math.trunc(input.config.maxAnswerTokens));

  /**
   * The terminal frames. `citations` stays the tool-backed set, unchanged; the
   * `unverified` frame exists only when the prose named something that set does
   * not hold, and `done` carries the same list for the brief's export.
   *
   * A turn with no prose is a failure, never a settled turn. `done` with an empty
   * answer is what told the reader "the turn ended before it wrote an answer"
   * while the ledger billed a success, so this returns whether it really
   * settled: `false` means only the error frame went out.
   */
  function* settle(totals: Totals, rounds: number): Generator<AssistantEvent, boolean> {
    if (answerText.trim() === "") {
      yield {
        type: "error",
        code: "AI_EMPTY_ANSWER",
        message: `The model used all ${String(ASSISTANT_MAX_TOOL_ROUNDS)} rounds of this turn without writing an answer.`,
      };
      return false;
    }
    const unverified = unverifiedAnswerIds(answerText, citationIds);
    yield { type: "citations", records: [...citationIds] };
    if (unverified.length > 0) yield { type: "unverified", ids: unverified };
    yield {
      type: "done",
      usage: usageFrame(totals),
      costUsd: totals.costUsd,
      rounds,
      unverified,
    };
    return true;
  }

  try {
    while (true) {
      if (input.signal?.aborted === true) {
        yield { type: "error", code: "AI_TIMEOUT", message: "The AI request was cancelled." };
        return;
      }
      const remaining = deadline - now().getTime();
      if (remaining <= 0) {
        yield {
          type: "error",
          code: "AI_TIMEOUT",
          message: "The turn did not finish within its time budget.",
        };
        return;
      }
      // The last permitted round is the answer round. It is sent with no tools
      // at all and with the final-round rule, so no tool call can be requested
      // in it and the turn always ends with prose or an honest error. Before
      // this, a model that was still calling tools when the cap fired settled
      // `done` with no text — the measured failure, 2 of 8 plain questions.
      const answerOnlyRound = rounds >= ASSISTANT_MAX_TOOL_ROUNDS - 1;

      // Round one is tool discovery: the prompt requires a call before any
      // claim, so its completion is a call and 1024 tokens cover it. From then
      // on the model is writing prose, and a table needs the larger budget.
      const roundMaxTokens =
        rounds === 0 && !retriedEmptyRound ? AI_MAX_TOKENS_DEFAULT : answerMaxTokens;
      const completion = input.client.streamChatCompletion({
        messages: answerOnlyRound ? withAnswerRoundRule(conversation) : conversation,
        tools: answerOnlyRound ? [] : tools,
        maxTokens: roundMaxTokens,
        timeoutMs: remaining,
        signal: input.signal,
      });
      activeStream = completion;
      let round: ChatStreamResult;
      try {
        // Text goes out the moment the provider emits it. A round that ends in
        // tool calls carries no prose, so a tool-only round emits no `delta`.
        for (;;) {
          const text = await completion.read();
          if (text === null) break;
          answerText += text;
          yield { type: "delta", text };
        }
        round = completion.result();
      } catch (error) {
        // The partial round still carries any usage the provider reported
        // before the stream broke; the ledger bills it in the `finally`.
        if (addUsage(totals, completion.result().usage)) usageSeen = true;
        yield failureEvent(error);
        return;
      }
      activeStream = null;
      if (addUsage(totals, round.usage)) usageSeen = true;

      if (round.malformed || !round.complete) {
        // Deltas already went out; the stream now says why it stopped. That is
        // the only honest shape once the 200 has been sent.
        yield {
          type: "error",
          code: "AI_UPSTREAM_ERROR",
          message: "The AI provider's stream ended before the answer was complete.",
        };
        return;
      }

      const wroteText = (round.content ?? "").trim() !== "";

      if (round.finishReason === "length") {
        // A round that produced nothing — no tool call, no text — is the cap
        // being too small for the reasoning preamble, not an answer that was
        // cut. Re-run that round once at the answer budget, and say so in the
        // stream. Bounded by the flag: a provider that truncates twice still
        // ends with an honest error rather than a retry loop.
        const silent = round.toolCalls.length === 0 && !wroteText;
        if (silent && !retriedEmptyRound && roundMaxTokens < answerMaxTokens) {
          retriedEmptyRound = true;
          yield { type: "retry", code: "AI_TRUNCATED", maxTokens: answerMaxTokens, trimmed: false };
          continue;
        }
        yield {
          type: "error",
          code: "AI_TRUNCATED",
          message:
            "The AI response hit its token limit and was discarded. Ask a narrower question.",
        };
        return;
      }

      if (answerOnlyRound) {
        // No tools were offered, so a tool call here is ignored rather than run:
        // there is no round left to feed its result back into. What matters is
        // whether the round wrote the answer.
        if (!wroteText && answerText.trim() === "" && !retriedEmptyRound) {
          // The answer round came back with nothing, on a turn that has no prose
          // at all. Retry it exactly once, trimmed: the base prompt, the last
          // question and an index of what the tools returned. Never a second
          // retry — the flag is shared with the truncated path, so a turn can
          // escalate once and then has to fail honestly.
          retriedEmptyRound = true;
          yield {
            type: "retry",
            code: "AI_EMPTY_ANSWER",
            maxTokens: answerMaxTokens,
            trimmed: true,
          };
          conversation = buildTrimmedConversation(conversation, gathered);
          continue;
        }
        answered = yield* settle(totals, rounds);
        return;
      }

      if (round.toolCalls.length === 0 && !wroteText) {
        // A round that ends cleanly with nothing in it — no prose, no tool call,
        // no truncation — is a provider that stopped without saying anything.
        // It is not an answer, so it is not settled as one: the same round is
        // re-run once at the answer budget, announced on the stream, and a
        // second empty round is reported as the failure it is. Before this, the
        // turn settled empty and the reader was told it "ended before it wrote
        // an answer" — true, but silent about a retry that would have worked.
        if (!retriedEmptyRound && roundMaxTokens < answerMaxTokens) {
          retriedEmptyRound = true;
          // Nothing was cut — the round ended cleanly with nothing in it — so
          // this is `AI_EMPTY_ANSWER`, the code the retry union reserves for a
          // round that came back with nothing to show.
          yield {
            type: "retry",
            code: "AI_EMPTY_ANSWER",
            maxTokens: answerMaxTokens,
            trimmed: false,
          };
          continue;
        }
        yield {
          type: "error",
          code: "AI_UPSTREAM_ERROR",
          message:
            "The AI provider returned no answer and asked for no tools. Ask again, or narrow the question.",
        };
        return;
      }

      if (round.toolCalls.length === 0) {
        answered = yield* settle(totals, rounds);
        return;
      }

      conversation.push({
        role: "assistant",
        content: round.content ?? "",
        tool_calls: round.toolCalls,
      });
      for (const call of round.toolCalls) {
        const args = parseToolArguments(call.function.arguments);
        const outcome = args.ok
          ? await executeTool(call.function.name, args.value, toolCtx)
          : malformedArguments(call.function.name);
        // Emitted before the result is appended: the UI can name the tool and
        // its row count while the model is still reading.
        const returnedIds = outcome.ok ? collectRecordIds(outcome.data) : [];
        for (const id of returnedIds) citationIds.add(id);
        gathered.push({
          name: call.function.name,
          args: compactJson(args.ok ? args.value : null, SUMMARY_ARGS_CHARS),
          ok: outcome.ok,
          rows: outcome.ok ? outcome.rows : 0,
          ids: returnedIds,
        });
        const web = webEvidence(call.function.name, outcome);
        yield {
          type: "tool",
          name: call.function.name,
          args: args.ok ? args.value : null,
          ok: outcome.ok,
          rows: outcome.ok ? outcome.rows : 0,
          ids: returnedIds.slice(0, ASSISTANT_TOOL_ID_SAMPLE),
          ...(web === null ? {} : { web }),
        };
        conversation.push(toolMessage(call, outcome));
      }
      rounds += 1;
    }
  } catch (error) {
    yield failureEvent(error);
  } finally {
    // A consumer that stops reading mid-stream must not leave a socket, a
    // timer or a provider request behind. A settled reader ignores this.
    activeStream?.cancel();
    // Partial and failed turns are billed too: the provider reported them, so
    // they cost money. A ledger write that throws must not lose the answer the
    // reader already has, so it is swallowed after the frame is out.
    if (usageSeen || answered) {
      try {
        input.ledger.recordUsage({
          usage: {
            promptTokens: totals.prompt,
            completionTokens: totals.completion,
            reasoningTokens: totals.reasoning,
            cacheReadTokens: totals.cacheRead,
            listCostUsd: totals.costUsd,
          },
          at: now(),
        });
      } catch {
        // No prompt or answer text is involved; the next turn's budget probe
        // simply reads the previous row.
      }
    }
  }
}

function usageFrame(totals: Totals): AssistantUsageFrame {
  return {
    prompt: totals.prompt,
    completion: totals.completion,
    reasoning: totals.reasoning,
    cacheRead: totals.cacheRead,
  };
}
