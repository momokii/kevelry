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
}

export interface AiTransportResponse {
  readonly status: number;
  readonly body: string;
}

/** Minimal fetch seam: tests hand in a function, production wraps global fetch. */
export type AiTransport = (request: AiTransportRequest) => Promise<AiTransportResponse>;

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_call_id?: string;
  name?: string;
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
  chatCompletion(request: ChatRequest): Promise<ChatCompletion>;
}

/** The production transport: one POST, no redirects (the key must not travel). */
export const fetchTransport: AiTransport = async ({ url, headers, body, signal }) => {
  const response = await fetch(url, {
    method: "POST",
    headers,
    body,
    signal,
    cache: "no-store",
    redirect: "error",
  });
  return { status: response.status, body: await response.text() };
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

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
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
): Promise<AiTransportResponse> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, ctx.config.requestTimeoutMs);
  try {
    return await ctx.transport({ ...request, signal: controller.signal });
  } catch (error) {
    if (timedOut) {
      throw new AiClientError(
        "AI_TIMEOUT",
        `The AI provider did not respond within ${ctx.config.requestTimeoutMs} ms.`,
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
      const response = await sendOnce(ctx, { url, headers, body: payload }, attempt + 1 < attempts);
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
  };
}
