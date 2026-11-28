// Thin OpenAI-compatible client for the OpenCode Go gateway.
//
// Two facts from the credential probes shape this file:
//
//  1. `x-opencode-session: <uuid>` is mandatory. Without it every request is a
//     `400 MissingSessionID`, which reads like an auth bug when auth is fine.
//  2. `max_tokens` below 512 truncates a reasoning-first model into empty tool
//     arguments or empty content, with `finish_reason: "length"`. The floor is
//     applied here so no caller can reintroduce the bug, and a truncated
//     response is a typed failure rather than a shorter answer.
//
// The transport is injectable so the entire suite runs without a socket. The
// key is only ever placed in the outbound Authorization header; error messages
// and typed errors carry a redacted upstream excerpt at most.

import { randomUUID } from "node:crypto";

import { AI_MAX_TOKENS_DEFAULT, AI_MAX_TOKENS_FLOOR, type AiConfig } from "./config";
import { createGatewayStreamAccumulator } from "./gateway-stream";
import { asRecord } from "../json";
import { parseUsage, type AiUsage } from "./usage";

/** The gateway rejects requests without this header (`400 MissingSessionID`). */
export const AI_SESSION_HEADER = "x-opencode-session";

/** Jittered backoff base; one retry only, so this is the whole retry budget. */
export const AI_RETRY_BASE_MS = 250;

export type AiClientErrorCode = "AI_DISABLED" | "AI_UPSTREAM_ERROR" | "AI_TIMEOUT" | "AI_TRUNCATED";

export interface AiClientErrorOptions {
  status?: number | null;
  retryable?: boolean;
  upstreamMessage?: string | null;
}

/** Typed failure from the gateway client. Never carries the API key. */
export class AiClientError extends Error {
  readonly name = "AiClientError";
  readonly code: AiClientErrorCode;
  readonly status: number | null;
  readonly retryable: boolean;
  readonly upstreamMessage: string | null;

  constructor(code: AiClientErrorCode, message: string, options: AiClientErrorOptions = {}) {
    super(message);
    this.code = code;
    this.status = options.status ?? null;
    this.retryable = options.retryable ?? false;
    this.upstreamMessage = options.upstreamMessage ?? null;
  }
}

export interface AiTransportRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly signal: AbortSignal;
  /** True when the caller will consume an SSE body as it arrives. */
  readonly streaming?: boolean;
}

export interface AiTransportResponse {
  readonly status: number;
  /** Whole body. For a streamed response this is `""` and `stream` carries the bytes. */
  readonly body: string;
  /** Upstream `Content-Type`; a streamed turn must be `text/event-stream`. */
  readonly contentType?: string | null;
  /**
   * SSE bytes as the provider emits them. Absent means the transport buffered
   * (a deterministic test double, or a non-streaming reply); the client then
   * feeds `body` to the same parser as one fragment.
   */
  readonly stream?: ReadableStream<Uint8Array> | null;
}

/** Minimal fetch seam: tests hand in a function, production wraps global fetch. */
export type AiTransport = (request: AiTransportRequest) => Promise<AiTransportResponse>;

/** One OpenAI content part. Only the two shapes this feature uses exist. */
export type ChatContentPart =
  { type: "text"; text: string } | { type: "image_url"; image_url: { url: string } };

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  /** A string for text turns; parts only when a screenshot rides along. */
  content: string | readonly ChatContentPart[];
  tool_call_id?: string;
  name?: string;
  /** Present on an assistant message that requested tools. */
  tool_calls?: readonly ChatToolCall[];
}

export interface ChatToolCall {
  id: string;
  type: string;
  function: { name: string; arguments: string };
}

export interface ChatRequest {
  messages: readonly ChatMessage[];
  /** Clamped up to `AI_MAX_TOKENS_FLOOR`; omitted uses the 1024 default. */
  maxTokens?: number;
  /** Tool schemas are owned by the prompt module; this client only forwards. */
  tools?: readonly unknown[];
  /** Streaming responses are returned raw; the SSE parser belongs to the turn loop. */
  stream?: boolean;
  /**
   * Per-call budget. The turn loop passes what is left of the whole turn's
   * deadline, so four rounds cannot each spend the full request timeout.
   * Defaults to `config.requestTimeoutMs`.
   */
  timeoutMs?: number;
  /** Caller cancellation (client disconnect). Aborting reports `AI_TIMEOUT`. */
  signal?: AbortSignal;
}

export interface ChatCompletion {
  content: string | null;
  toolCalls: ChatToolCall[];
  finishReason: string | null;
  usage: AiUsage | null;
  model: string | null;
  /** Unparsed body when `stream` was requested; `null` for JSON responses. */
  rawBody: string | null;
}

/** One streamed round, assembled from the frames that arrived. */
export interface ChatStreamResult extends ChatCompletion {
  /** True when the provider signalled the end of the stream. */
  complete: boolean;
  /** True when a `data:` frame was not valid JSON. */
  malformed: boolean;
}

/**
 * A streamed round in progress. `read()` hands over assistant text as the
 * provider emits it; the assembled round stays readable even after a failure,
 * so the caller can bill the usage the provider already reported.
 */
export interface ChatStreamReader {
  /** Next assistant text fragment, or `null` when the round ended cleanly. */
  read(): Promise<string | null>;
  /** The round accumulated so far. Safe to call at any point. */
  result(): ChatStreamResult;
  /** Cancels the request and stops both timers. Idempotent. */
  cancel(): void;
}

export interface AiClientOptions {
  config: AiConfig;
  transport?: AiTransport;
  /** Routing id; one per process or per turn. Defaults to a fresh UUID. */
  sessionId?: string;
  /** Injectable for tests: no real waiting in the retry path. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for tests: jitter source in [0, 1). */
  random?: () => number;
}

export interface AiClient {
  /** Buffered round: the whole body, parsed once. Used by non-streaming callers. */
  chatCompletion(request: ChatRequest): Promise<ChatCompletion>;
  /** One streamed round: text fragments as they arrive, then the assembled round. */
  streamChatCompletion(request: ChatRequest): ChatStreamReader;
}

/** The production transport: one POST, no redirects (the key must not travel). */
export const fetchTransport: AiTransport = async ({ url, headers, body, signal, streaming }) => {
  const response = await fetch(url, {
    method: "POST",
    headers,
    body,
    signal,
    cache: "no-store",
    redirect: "error",
  });
  if (streaming === true && response.ok && response.body !== null) {
    // Hand the bytes over unsipped: `text()` here is the multi-second blank
    // the turn loop exists to avoid. An error status still reads as text so
    // the typed error can carry a redacted excerpt.
    return {
      status: response.status,
      body: "",
      contentType: response.headers.get("content-type"),
      stream: response.body,
    };
  }
  return {
    status: response.status,
    body: await response.text(),
    contentType: response.headers.get("content-type"),
  };
};

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** Redacts the key itself and any leaked bearer header from free text. */
export function redactSecret(text: string, apiKey: string | null): string {
  let redacted = text;
  if (apiKey !== null && apiKey !== "") {
    redacted = redacted.split(apiKey).join("[redacted]");
  }
  return redacted.replace(/Bearer\s+[^\s"',}]+/gi, "Bearer [redacted]");
}

/** One-line, bounded upstream excerpt for an error object. Never the headers. */
function excerpt(text: string, apiKey: string | null, limit = 300): string {
  const flat = redactSecret(text, apiKey).replace(/\s+/g, " ").trim();
  return flat.length > limit ? `${flat.slice(0, limit)}…` : flat;
}

/** Applies the reasoning-model floor; a caller cannot ask for fewer tokens. */
export function clampMaxTokens(maxTokens: number | undefined): number {
  if (maxTokens === undefined || !Number.isFinite(maxTokens)) return AI_MAX_TOKENS_DEFAULT;
  return Math.max(AI_MAX_TOKENS_FLOOR, Math.trunc(maxTokens));
}

function parseToolCalls(raw: unknown): ChatToolCall[] {
  if (!Array.isArray(raw)) return [];
  const calls: ChatToolCall[] = [];
  for (const entry of raw) {
    const call = asRecord(entry);
    const fn = asRecord(call?.["function"]);
    const name = fn?.["name"];
    if (call === null || typeof name !== "string" || name === "") continue;
    const args = fn?.["arguments"];
    calls.push({
      id: typeof call["id"] === "string" ? call["id"] : "",
      type: typeof call["type"] === "string" ? call["type"] : "function",
      function: {
        name,
        arguments: typeof args === "string" ? args : "",
      },
    });
  }
  return calls;
}

function buildPayload(config: AiConfig, request: ChatRequest, streamed: boolean): string {
  const payload: Record<string, unknown> = {
    model: config.model,
    messages: request.messages,
    max_tokens: clampMaxTokens(request.maxTokens),
    stream: streamed,
  };
  if (streamed) {
    // The only way to get a terminal usage block on a streamed turn, and the
    // only way to bill the budget honestly.
    payload["stream_options"] = { include_usage: true };
  }
  if (request.tools !== undefined && request.tools.length > 0) {
    payload["tools"] = request.tools;
  }
  return JSON.stringify(payload);
}

function parseCompletion(
  response: AiTransportResponse,
  config: AiConfig,
  streamed: boolean,
): ChatCompletion {
  if (streamed) {
    return {
      content: null,
      toolCalls: [],
      finishReason: null,
      usage: null,
      model: null,
      rawBody: response.body,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    throw new AiClientError(
      "AI_UPSTREAM_ERROR",
      "The AI provider returned a response that was not valid JSON.",
      {
        status: response.status,
        retryable: false,
        upstreamMessage: excerpt(response.body, config.apiKey),
      },
    );
  }
  const root = asRecord(parsed);
  if (root === null) {
    throw new AiClientError("AI_UPSTREAM_ERROR", "The AI provider returned an unexpected shape.", {
      status: response.status,
      retryable: false,
      upstreamMessage: excerpt(response.body, config.apiKey),
    });
  }
  const choices = Array.isArray(root["choices"]) ? root["choices"] : [];
  const choice = asRecord(choices[0]);
  const finishReason = choice?.["finish_reason"];
  if (finishReason === "length") {
    // A truncated answer that silently lacks its citations is the one failure
    // this feature cannot afford, so `length` never becomes a result.
    throw new AiClientError(
      "AI_TRUNCATED",
      'The AI response hit its token limit (finish_reason: "length") and was discarded.',
      { status: response.status, retryable: false },
    );
  }
  const message = asRecord(choice?.["message"]);
  const content = message?.["content"];
  const rawUsage = root["usage"];
  const model = root["model"];
  return {
    content: typeof content === "string" ? content : null,
    toolCalls: parseToolCalls(message?.["tool_calls"]),
    finishReason: typeof finishReason === "string" ? finishReason : null,
    usage: asRecord(rawUsage) === null ? null : parseUsage(rawUsage),
    model: typeof model === "string" ? model : null,
    rawBody: null,
  };
}

interface ClientContext {
  config: AiConfig;
  transport: AiTransport;
  sessionId: string;
  sleep: (ms: number) => Promise<void>;
  random: () => number;
}

/** One attempt, aborting at the configured timeout. */
async function sendOnce(
  ctx: ClientContext,
  request: Omit<AiTransportRequest, "signal">,
  retryable: boolean,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<AiTransportResponse> {
  const controller = new AbortController();
  let timedOut = false;
  let cancelled = false;
  const abort = () => controller.abort();
  if (signal !== undefined) {
    if (signal.aborted) cancelled = true;
    else signal.addEventListener("abort", abort, { once: true });
  }
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    return await ctx.transport({ ...request, signal: controller.signal });
  } catch (error) {
    if (cancelled) {
      throw new AiClientError("AI_TIMEOUT", "The AI request was cancelled.", {
        retryable: false,
        upstreamMessage: null,
      });
    }
    if (timedOut) {
      throw new AiClientError(
        "AI_TIMEOUT",
        `The AI provider did not respond within ${String(timeoutMs)} ms.`,
        { retryable, upstreamMessage: null },
      );
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new AiClientError("AI_UPSTREAM_ERROR", "The AI provider could not be reached.", {
      retryable,
      upstreamMessage: excerpt(detail, ctx.config.apiKey),
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

function upstreamFailure(
  response: AiTransportResponse,
  config: AiConfig,
  retryable: boolean,
): AiClientError {
  const detail = excerpt(response.body, config.apiKey);
  return new AiClientError(
    "AI_UPSTREAM_ERROR",
    `The AI provider returned HTTP ${response.status}.`,
    {
      status: response.status,
      retryable,
      upstreamMessage: detail === "" ? null : detail,
    },
  );
}

/**
 * Ordered hand-off between the socket reader and the turn loop. A push wakes
 * exactly one pending `next()`; a failure drains what already arrived before
 * throwing, so no token is lost behind an error that followed it.
 */
class DeltaQueue {
  private readonly items: string[] = [];
  private waiter: (() => void) | null = null;
  private closed = false;
  private failure: AiClientError | null = null;

  push(item: string): void {
    if (this.closed) return;
    this.items.push(item);
    this.wake();
  }

  close(): void {
    this.closed = true;
    this.wake();
  }

  fail(error: AiClientError): void {
    if (this.closed) return;
    this.failure = error;
    this.closed = true;
    this.wake();
  }

  async next(): Promise<string | null> {
    for (;;) {
      const item = this.items.shift();
      if (item !== undefined) return item;
      if (this.failure !== null) throw this.failure;
      if (this.closed) return null;
      await new Promise<void>((resolve) => {
        this.waiter = resolve;
      });
    }
  }

  private wake(): void {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.();
  }
}

function transportError(config: AiConfig, error: unknown): AiClientError {
  if (error instanceof AiClientError) return error;
  const detail = error instanceof Error ? error.message : String(error);
  return new AiClientError("AI_UPSTREAM_ERROR", "The AI provider could not be reached.", {
    retryable: false,
    upstreamMessage: excerpt(detail, config.apiKey),
  });
}

function streamReadError(config: AiConfig, error: unknown): AiClientError {
  if (error instanceof AiClientError) return error;
  const detail = error instanceof Error ? error.message : String(error);
  return new AiClientError("AI_UPSTREAM_ERROR", "The AI provider's stream ended unexpectedly.", {
    retryable: false,
    upstreamMessage: detail === "" ? null : excerpt(detail, config.apiKey),
  });
}

/**
 * Streams one round. `read()` resolves with each assistant text fragment as
 * the provider emits it; the assembled round is available from `result()` once
 * `read()` returns `null` or throws.
 *
 * Two timers, deliberately separate:
 *   - `timeoutMs` is the caller's remaining turn budget and covers the whole
 *     stream, not just the response headers;
 *   - the idle guard aborts when no bytes arrive for
 *     `config.streamIdleTimeoutMs`. A stream that stops mid-answer with the
 *     socket open would otherwise hang until the turn deadline.
 *
 * A streaming request is never retried: replaying a partially consumed SSE
 * body would bill the turn twice and hand the consumer two contradictory
 * streams.
 */
function streamChat(ctx: ClientContext, request: ChatRequest): ChatStreamReader {
  const config = ctx.config;
  const apiKey = config.apiKey;
  if (!config.enabled || apiKey === null) {
    throw new AiClientError(
      "AI_DISABLED",
      "The AI assistant is disabled: it is not enabled or no API key is configured.",
      { retryable: false },
    );
  }

  const timeoutMs = Math.max(1, Math.trunc(request.timeoutMs ?? config.requestTimeoutMs));
  const idleTimeoutMs = Math.max(1, Math.trunc(config.streamIdleTimeoutMs));
  const payload = buildPayload(config, request, true);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "text/event-stream",
    authorization: `Bearer ${apiKey}`,
    [AI_SESSION_HEADER]: ctx.sessionId,
  };
  const url = `${config.baseUrl}/chat/completions`;

  const accumulator = createGatewayStreamAccumulator();
  const queue = new DeltaQueue();
  const controller = new AbortController();
  let bodyReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let timedOut = false;
  let cancelled = false;
  let settled = false;

  const onPeerAbort = (): void => {
    cancelled = true;
    controller.abort();
  };
  const onAbort = (): void => {
    if (cancelled) {
      fail(new AiClientError("AI_TIMEOUT", "The AI request was cancelled."));
      return;
    }
    if (timedOut) {
      fail(
        new AiClientError(
          "AI_TIMEOUT",
          `The AI provider did not finish streaming within ${String(timeoutMs)} ms.`,
        ),
      );
      return;
    }
    fail(
      new AiClientError(
        "AI_TIMEOUT",
        `The AI provider sent nothing for ${String(idleTimeoutMs)} ms.`,
      ),
    );
  };

  const clearTimers = (): void => {
    clearTimeout(totalTimer);
    clearTimeout(idleTimer);
    request.signal?.removeEventListener("abort", onPeerAbort);
  };

  const fail = (error: AiClientError): void => {
    if (settled) return;
    settled = true;
    clearTimers();
    queue.fail(error);
    // A test double or a wedged proxy may not surface the abort as a stream
    // error; cancelling the reader makes the pending `read()` settle either way.
    if (bodyReader !== null) void bodyReader.cancel().catch(() => undefined);
  };

  const finish = (): void => {
    if (settled) return;
    for (const delta of accumulator.end()) queue.push(delta);
    settled = true;
    clearTimers();
    queue.close();
    // `[DONE]` ends the contract even when the provider keeps the socket open.
    if (bodyReader !== null) void bodyReader.cancel().catch(() => undefined);
  };

  const absorb = (text: string): boolean => {
    for (const delta of accumulator.push(text)) queue.push(delta);
    if (accumulator.snapshot().done) {
      // `[DONE]` is the end of the contract even if the socket stays open.
      finish();
      return false;
    }
    return true;
  };

  const armIdle = (): void => {
    if (settled) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      controller.abort();
    }, idleTimeoutMs);
  };

  // The total budget covers the whole stream; the idle guard covers a stall.
  const totalTimer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  let idleTimer = setTimeout(() => {
    controller.abort();
  }, idleTimeoutMs);

  controller.signal.addEventListener("abort", onAbort, { once: true });
  if (request.signal !== undefined) {
    if (request.signal.aborted) onPeerAbort();
    else request.signal.addEventListener("abort", onPeerAbort, { once: true });
  }

  const run = async (): Promise<void> => {
    let response: AiTransportResponse;
    try {
      response = await ctx.transport({
        url,
        headers,
        body: payload,
        signal: controller.signal,
        streaming: true,
      });
    } catch (error) {
      if (!settled) fail(transportError(config, error));
      return;
    }
    if (settled) return;
    if (response.status < 200 || response.status >= 300) {
      fail(upstreamFailure(response, config, false));
      return;
    }
    const contentType = response.contentType ?? null;
    // A buffered test double reports no content type; a real provider must
    // speak SSE, and a JSON 200 on a streamed turn is a protocol failure that
    // must not be misread as an empty answer.
    if (contentType !== null && !contentType.toLowerCase().includes("text/event-stream")) {
      fail(
        new AiClientError(
          "AI_UPSTREAM_ERROR",
          "The AI provider did not return an event stream for a streamed turn.",
          { status: response.status, retryable: false },
        ),
      );
      return;
    }
    if (response.stream === null || response.stream === undefined) {
      // A buffered transport is one fragment: same parser, same guarantees.
      if (response.body !== "") absorb(response.body);
      finish();
      return;
    }
    try {
      bodyReader = response.stream.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await bodyReader.read();
        if (settled) return;
        if (done) break;
        if (value === undefined) continue;
        armIdle();
        // `stream: true` holds an incomplete multi-byte character until its
        // remaining bytes arrive, so a split code point is never mangled.
        if (!absorb(decoder.decode(value, { stream: true }))) return;
      }
      absorb(decoder.decode());
      finish();
    } catch (error) {
      if (!settled) fail(streamReadError(config, error));
    }
  };
  void run();

  return {
    read: () => queue.next(),
    result: (): ChatStreamResult => {
      const parsed = accumulator.snapshot();
      return {
        content: parsed.text === "" ? null : parsed.text,
        toolCalls: parsed.toolCalls,
        finishReason: parsed.finishReason,
        usage: parsed.usage,
        model: parsed.model,
        rawBody: null,
        complete: parsed.complete,
        malformed: parsed.malformed,
      };
    },
    cancel: () => {
      cancelled = true;
      controller.abort();
    },
  };
}

async function postChat(ctx: ClientContext, request: ChatRequest): Promise<ChatCompletion> {
  const apiKey = ctx.config.apiKey;
  if (!ctx.config.enabled || apiKey === null) {
    throw new AiClientError(
      "AI_DISABLED",
      "The AI assistant is disabled: it is not enabled or no API key is configured.",
      { retryable: false },
    );
  }

  const streamed = request.stream === true;
  const timeoutMs = Math.max(1, Math.trunc(request.timeoutMs ?? ctx.config.requestTimeoutMs));
  const payload = buildPayload(ctx.config, request, streamed);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: streamed ? "text/event-stream" : "application/json",
    authorization: `Bearer ${apiKey}`,
    [AI_SESSION_HEADER]: ctx.sessionId,
  };
  const url = `${ctx.config.baseUrl}/chat/completions`;
  // Streaming has no retry: replaying a partially consumed SSE body would
  // double-bill the turn without giving the consumer a coherent stream.
  const attempts = streamed ? 1 : 2;
  let lastError: AiClientError | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) {
      const jitter = Math.min(Math.max(ctx.random(), 0), 0.999_999);
      await ctx.sleep(AI_RETRY_BASE_MS + Math.floor(jitter * AI_RETRY_BASE_MS));
    }
    try {
      const response = await sendOnce(
        ctx,
        { url, headers, body: payload },
        attempt + 1 < attempts,
        timeoutMs,
        request.signal,
      );
      if (response.status >= 200 && response.status < 300) {
        return parseCompletion(response, ctx.config, streamed);
      }
      const retryableStatus = response.status >= 500;
      const failure = upstreamFailure(
        response,
        ctx.config,
        retryableStatus && attempt + 1 < attempts,
      );
      if (!failure.retryable) throw failure;
      lastError = failure;
    } catch (error) {
      if (error instanceof AiClientError) {
        if (!error.retryable) throw error;
        lastError = error;
        continue;
      }
      lastError = new AiClientError("AI_UPSTREAM_ERROR", "The AI provider could not be reached.", {
        retryable: attempt + 1 < attempts,
      });
    }
  }

  throw (
    lastError ??
    new AiClientError("AI_UPSTREAM_ERROR", "The AI provider could not be reached.", {
      retryable: false,
    })
  );
}

/**
 * Builds the client. The session id defaults to a fresh UUID per client, which
 * is the per-turn/per-process granularity the gateway asks for; the same client
 * reuses it across attempts so a retry is the same session.
 */
export function createAiClient(options: AiClientOptions): AiClient {
  const ctx: ClientContext = {
    config: options.config,
    transport: options.transport ?? fetchTransport,
    sessionId: options.sessionId ?? randomUUID(),
    sleep: options.sleep ?? defaultSleep,
    random: options.random ?? Math.random,
  };
  return {
    chatCompletion: (request: ChatRequest) => postChat(ctx, request),
    streamChatCompletion: (request: ChatRequest) => streamChat(ctx, request),
  };
}
