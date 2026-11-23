import { describe, expect, it } from "vitest";

import { AI_BASE_URL_DEFAULT, AI_MODEL_DEFAULT, type AiConfig } from "../src/lib/ai/config";
import {
  AI_SESSION_HEADER,
  AiClientError,
  type AiTransport,
  type AiTransportResponse,
  type ChatMessage,
  createAiClient,
} from "../src/lib/ai/client";

const KEY = "sentinel-key-do-not-log-9f3a";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";

const MESSAGES: readonly ChatMessage[] = [{ role: "user", content: "hello" }];

function makeConfig(overrides: Partial<AiConfig> = {}): AiConfig {
  return {
    enabled: true,
    apiKey: KEY,
    baseUrl: AI_BASE_URL_DEFAULT,
    model: AI_MODEL_DEFAULT,
    webFetchEnabled: false,
    sessionBudgetTokens: 60_000,
    dailyBudgetUsd: 5,
    maxInputChars: 2000,
    maxAnswerTokens: 4096,
    requestTimeoutMs: 45_000,
    streamIdleTimeoutMs: 20_000,
    ...overrides,
  };
}

interface CapturedCall {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  signal: AbortSignal;
}

function recordingTransport(
  handler: (call: CapturedCall, index: number) => Promise<AiTransportResponse>,
): { transport: AiTransport; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const transport: AiTransport = async (request) => {
    const call: CapturedCall = {
      url: request.url,
      headers: { ...request.headers },
      body: JSON.parse(request.body) as Record<string, unknown>,
      signal: request.signal,
    };
    calls.push(call);
    return handler(call, calls.length - 1);
  };
  return { transport, calls };
}

function firstCall(calls: readonly CapturedCall[]): CapturedCall {
  const call = calls[0];
  if (call === undefined) throw new Error("expected the transport to have been called");
  return call;
}

function completionBody(content: string, usage: Record<string, unknown> = {}): string {
  return JSON.stringify({
    id: "cmpl-test",
    model: AI_MODEL_DEFAULT,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: 10,
      completion_tokens: 5,
      reasoning_tokens: 2,
      opencode: { list_cost: 0.0000639 },
      ...usage,
    },
  });
}

function clientWith(transport: AiTransport, config: AiConfig = makeConfig()) {
  return createAiClient({
    config,
    transport,
    sessionId: SESSION_ID,
    sleep: async () => {},
    random: () => 0,
  });
}

describe("AI client gating", () => {
  it("refuses keyless and disabled configs without calling the transport", async () => {
    for (const config of [makeConfig({ apiKey: null }), makeConfig({ enabled: false })]) {
      const { transport, calls } = recordingTransport(async () => ({
        status: 200,
        body: completionBody("never"),
      }));
      const client = clientWith(transport, config);
      await expect(client.chatCompletion({ messages: MESSAGES })).rejects.toMatchObject({
        code: "AI_DISABLED",
        retryable: false,
      });
      expect(calls).toHaveLength(0);
    }
  });
});

describe("AI client request shape", () => {
  it("sends the session header, bearer auth and the configured model", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 200,
      body: completionBody("hi"),
    }));
    const client = clientWith(transport);
    await client.chatCompletion({ messages: MESSAGES });
    const call = firstCall(calls);
    expect(call.url).toBe(`${AI_BASE_URL_DEFAULT}/chat/completions`);
    expect(call.headers[AI_SESSION_HEADER]).toBe(SESSION_ID);
    expect(call.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.body["model"]).toBe(AI_MODEL_DEFAULT);
    expect(call.body["messages"]).toEqual(MESSAGES);
    expect(call.body["stream"]).toBe(false);
  });

  it("generates a UUID session id when none is injected", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 200,
      body: completionBody("hi"),
    }));
    const client = createAiClient({ config: makeConfig(), transport, sleep: async () => {} });
    await client.chatCompletion({ messages: MESSAGES });
    expect(firstCall(calls).headers[AI_SESSION_HEADER]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("clamps max_tokens up to the 512 reasoning floor and keeps larger values", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 200,
      body: completionBody("hi"),
    }));
    const client = clientWith(transport);
    await client.chatCompletion({ messages: MESSAGES, maxTokens: 8 });
    await client.chatCompletion({ messages: MESSAGES, maxTokens: 2048 });
    await client.chatCompletion({ messages: MESSAGES });
    expect(calls.map((call) => call.body["max_tokens"])).toEqual([512, 2048, 1024]);
  });

  it("returns parsed content, tool calls and the gateway usage block", async () => {
    const body = JSON.stringify({
      model: AI_MODEL_DEFAULT,
      choices: [
        {
          message: {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "call_1",
                type: "function",
                function: { name: "get_cve", arguments: '{"id":"CVE-2026-1234"}' },
              },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
      usage: {
        prompt_tokens: 298,
        completion_tokens: 40,
        reasoning_tokens: 12,
        prompt_tokens_details: { cached_tokens: 7 },
        opencode: { list_cost: 0.0000639 },
      },
    });
    const { transport } = recordingTransport(async () => ({ status: 200, body }));
    const result = await clientWith(transport).chatCompletion({ messages: MESSAGES });
    expect(result.finishReason).toBe("tool_calls");
    expect(result.toolCalls).toEqual([
      {
        id: "call_1",
        type: "function",
        function: { name: "get_cve", arguments: '{"id":"CVE-2026-1234"}' },
      },
    ]);
    expect(result.usage).toEqual({
      promptTokens: 298,
      completionTokens: 40,
      reasoningTokens: 12,
      cacheReadTokens: 7,
      listCostUsd: 0.0000639,
    });
  });
});

describe("AI client failure taxonomy", () => {
  it('maps finish_reason "length" to AI_TRUNCATED instead of returning a short answer', async () => {
    const body = JSON.stringify({
      choices: [{ message: { content: "the answer is" }, finish_reason: "length" }],
      usage: { prompt_tokens: 10, completion_tokens: 512 },
    });
    const { transport } = recordingTransport(async () => ({ status: 200, body }));
    await expect(
      clientWith(transport).chatCompletion({ messages: MESSAGES }),
    ).rejects.toMatchObject({ code: "AI_TRUNCATED", retryable: false, status: 200 });
  });

  it("aborts at the timeout and maps it to AI_TIMEOUT", async () => {
    let calls = 0;
    const transport: AiTransport = ({ signal }) => {
      calls += 1;
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
          },
          { once: true },
        );
      });
    };
    const client = clientWith(transport, makeConfig({ requestTimeoutMs: 20 }));
    await expect(client.chatCompletion({ messages: MESSAGES })).rejects.toMatchObject({
      code: "AI_TIMEOUT",
      retryable: false,
      status: null,
    });
    expect(calls).toBe(2);
  });

  it("retries a 500 once and then maps to AI_UPSTREAM_ERROR", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 500,
      body: '{"error":{"type":"upstream"}}',
    }));
    await expect(
      clientWith(transport).chatCompletion({ messages: MESSAGES }),
    ).rejects.toMatchObject({ code: "AI_UPSTREAM_ERROR", status: 500, retryable: false });
    expect(calls).toHaveLength(2);
  });

  it("recovers when the single retry succeeds", async () => {
    const { transport, calls } = recordingTransport(async (_call, index) =>
      index === 0
        ? { status: 503, body: "unavailable" }
        : { status: 200, body: completionBody("recovered") },
    );
    const result = await clientWith(transport).chatCompletion({ messages: MESSAGES });
    expect(result.content).toBe("recovered");
    expect(calls).toHaveLength(2);
  });

  it("does not retry a 400", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 400,
      body: '{"type":"MissingSessionID"}',
    }));
    await expect(
      clientWith(transport).chatCompletion({ messages: MESSAGES }),
    ).rejects.toMatchObject({ code: "AI_UPSTREAM_ERROR", status: 400, retryable: false });
    expect(calls).toHaveLength(1);
  });

  it("does not retry a streaming failure", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 502,
      body: "bad gateway",
    }));
    await expect(
      clientWith(transport).chatCompletion({ messages: MESSAGES, stream: true }),
    ).rejects.toMatchObject({ code: "AI_UPSTREAM_ERROR", status: 502 });
    expect(calls).toHaveLength(1);
  });

  it("asks for usage on a stream and hands back the raw body", async () => {
    const { transport, calls } = recordingTransport(async () => ({
      status: 200,
      body: 'data: {"choices":[]}\n\ndata: [DONE]\n\n',
    }));
    const result = await clientWith(transport).chatCompletion({
      messages: MESSAGES,
      stream: true,
    });
    expect(result.rawBody).toContain("[DONE]");
    expect(result.content).toBeNull();
    expect(firstCall(calls).body).toMatchObject({
      stream: true,
      stream_options: { include_usage: true },
    });
  });

  it("keeps the key out of every error surface", async () => {
    const leaky = JSON.stringify({
      error: {
        message: `invalid key ${KEY}`,
        authorization: `Bearer ${KEY}`,
      },
    });
    const { transport } = recordingTransport(async () => ({ status: 401, body: leaky }));
    const caught = await clientWith(transport)
      .chatCompletion({ messages: MESSAGES })
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect(caught).toBeInstanceOf(AiClientError);
    const error = caught as AiClientError;
    const serialized = [
      error.message,
      error.upstreamMessage ?? "",
      String(error),
      JSON.stringify(error),
      error.stack ?? "",
    ].join("\n");
    expect(serialized).not.toContain(KEY);
    expect(error.upstreamMessage).toContain("[redacted]");
    expect(error.status).toBe(401);
  });
});
