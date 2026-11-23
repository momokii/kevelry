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
//   retry      a round ended on its completion cap with no text and no tool
//              calls, so it is re-run once at the answer budget. Emitted before
//              the second attempt, so the stream states the escalation instead
//              of silently billing a second round.
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

import type { CveDatabase } from "../db";
import type {
  AiClient,
  ChatMessage,
  ChatStreamReader,
  ChatStreamResult,
  ChatToolCall,
} from "./client";
import { AI_MAX_TOKENS_DEFAULT, type AiConfig } from "./config";
import { renderRecordContext, renderSystemPrompt, renderVisionInstruction } from "./prompt";
import { executeTool, toolDefinitions, type ToolContext, type ToolOutcome } from "./tools";
import type { AiUsage, AiUsageLedger } from "./usage";

/**
 * Hard cap on tool rounds in one turn. The plan allowed six; four is what this
 * phase ships because each round re-bills eight tool definitions and a turn
 * that needs six is a question that should be split. Reaching the cap ends the
 * turn with `done` — it never loops, and it never pretends the answer is whole.
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
  "AI_TIMEOUT" | "AI_UPSTREAM_ERROR" | "AI_TRUNCATED" | "AI_BUDGET_EXHAUSTED" | "AI_DISABLED";

export type AssistantEvent =
  | {
      type: "tool";
      name: string;
      args: unknown;
      ok: boolean;
      rows: number;
      /** First ids the call returned, for the ledger's chips. Display sample only. */
      ids: string[];
    }
  | { type: "delta"; text: string }
  | {
      type: "retry";
      /** The round that is being re-run was cut by its completion cap. */
      code: "AI_TRUNCATED";
      /** Completion budget the retried round is given. */
      maxTokens: number;
    }
  | { type: "citations"; records: string[] }
  | { type: "unverified"; ids: string[] }
  | {
      type: "done";
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

function toolMessage(call: ChatToolCall, outcome: ToolOutcome): ChatMessage {
  return {
    role: "tool",
    tool_call_id: call.id,
    name: call.function.name,
    content: JSON.stringify(outcome),
  };
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
  /** One empty truncated round may be re-run at the answer budget, never two. */
  let retriedTruncatedRound = false;
  let activeStream: ChatStreamReader | null = null;

  const toolCtx: ToolContext = {
    db: input.db,
    webFetchEnabled: input.config.webFetchEnabled,
    now,
    ...input.toolContext,
  };
  const tools = toolDefinitions(input.config.webFetchEnabled);
  const conversation = buildConversation(input);
  // The answer round gets the larger budget; a tool round does not need it.
  const answerMaxTokens = Math.max(1, Math.trunc(input.config.maxAnswerTokens));

  /**
   * The terminal frames. `citations` stays the tool-backed set, unchanged; the
   * `unverified` frame exists only when the prose named something that set does
   * not hold, and `done` carries the same list for the brief's export.
   */
  function* settle(totals: Totals, rounds: number): Generator<AssistantEvent> {
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
      if (rounds >= ASSISTANT_MAX_TOOL_ROUNDS) {
        // The cap is a budget, not a failure: the turn ends with the evidence
        // it gathered and says so, instead of looping on a model that keeps
        // asking for tools.
        yield* settle(totals, rounds);
        answered = true;
        return;
      }

      // Round one is tool discovery: the prompt requires a call before any
      // claim, so its completion is a call and 1024 tokens cover it. From then
      // on the model is writing prose, and a table needs the larger budget.
      const roundMaxTokens =
        rounds === 0 && !retriedTruncatedRound ? AI_MAX_TOKENS_DEFAULT : answerMaxTokens;
      const completion = input.client.streamChatCompletion({
        messages: conversation,
        tools,
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

      if (round.finishReason === "length") {
        // A round that produced nothing — no tool call, no text — is the cap
        // being too small for the reasoning preamble, not an answer that was
        // cut. Re-run that round once at the answer budget, and say so in the
        // stream. Bounded by the flag: a provider that truncates twice still
        // ends with an honest error rather than a retry loop.
        const silent = round.toolCalls.length === 0 && (round.content ?? "").trim() === "";
        if (silent && !retriedTruncatedRound && roundMaxTokens < answerMaxTokens) {
          retriedTruncatedRound = true;
          yield { type: "retry", code: "AI_TRUNCATED", maxTokens: answerMaxTokens };
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

      if (round.toolCalls.length === 0) {
        yield* settle(totals, rounds);
        answered = true;
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
        yield {
          type: "tool",
          name: call.function.name,
          args: args.ok ? args.value : null,
          ok: outcome.ok,
          rows: outcome.ok ? outcome.rows : 0,
          ids: returnedIds.slice(0, ASSISTANT_TOOL_ID_SAMPLE),
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
