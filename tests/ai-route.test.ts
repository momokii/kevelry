// The assistant route's contract, tested end to end through `POST` with no
// socket: the provider is a canned SSE body handed to the transport seam, and
// the database is a temp file built by the real migrations.
//
// What this file proves (mechanical):
//   - fail-closed config, pre-stream typed errors, both rate windows, both
//     budgets, the strict body schema and the image checks — none of which reach
//     a provider;
//   - the SSE frame order (`tool` → `delta` → `citations` → `done`), the real
//     tool execution against the temp database, the 4-round cap, the mid-stream
//     error event (no second HTTP status), the redaction of an upstream failure,
//     and exactly one ledger row per completed turn.
//
// What it does not prove: that the model obeys the prompt. Every stream here is
// authored by the test.

import type Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { POST } from "../app/api/assistant/chat/route";
import {
  resetAssistantRateLimitState,
  setAssistantRateLimitClock,
} from "../app/api/assistant/_lib/rate-limit";
import { setAssistantTransport } from "../app/api/assistant/_lib/transport";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/db-handle";
import { resetHardeningState } from "../app/api/v1/_lib/guardrails";
import { utcDay } from "../src/lib/ai/usage";
import type { AiTransport, AiTransportResponse } from "../src/lib/ai/client";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const KEY = "sentinel-key-assistant-route-7b2e";
const STAMP = "2026-11-22T00:00:00.000Z";
const CVE_ID = "CVE-2099-0001";

const USAGE_ROUND_1 = {
  prompt_tokens: 400,
  completion_tokens: 30,
  reasoning_tokens: 10,
  cache_read_tokens: 0,
  opencode: { list_cost: 0.25 },
};
const USAGE_ROUND_2 = {
  prompt_tokens: 600,
  completion_tokens: 50,
  reasoning_tokens: 0,
  cache_read_tokens: 100,
  opencode: { list_cost: 0.5 },
};

const PNG_DATA_URL = `data:image/png;base64,${Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x00,
]).toString("base64")}`;
const GIF_DATA_URL = `data:image/gif;base64,${Buffer.from("GIF89a").toString("base64")}`;
const MISMATCHED_DATA_URL = `data:image/png;base64,${Buffer.from("GIF89a").toString("base64")}`;

const MANAGED_ENV = [
  "AI_ENABLED",
  "AI_API_KEY",
  "AI_DAILY_BUDGET_USD",
  "AI_SESSION_BUDGET_TOKENS",
  "AI_MAX_INPUT_CHARS",
  "AI_REQUEST_TIMEOUT_MS",
  "AI_STREAM_IDLE_TIMEOUT_MS",
  "AI_WEB_FETCH_ENABLED",
] as const;

const savedEnv = new Map<string, string | undefined>();
const tempDirs: string[] = [];
let db: CveDatabase;

function baseEnv(): void {
  for (const [name, value] of savedEnv) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  savedEnv.clear();
  process.env.AI_ENABLED = "true";
  process.env.AI_API_KEY = KEY;
  process.env.AI_DAILY_BUDGET_USD = "5";
  process.env.AI_REQUEST_TIMEOUT_MS = "5000";
  delete process.env.AI_STREAM_IDLE_TIMEOUT_MS;
  delete process.env.AI_SESSION_BUDGET_TOKENS;
  delete process.env.AI_MAX_INPUT_CHARS;
  delete process.env.AI_WEB_FETCH_ENABLED;
}

function seedDatabase(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ai-route-"));
  tempDirs.push(dir);
  const handle = openDatabase({ dataDir: dir });
  handle.runBoundedWrite(() => {
    handle.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
          "title, description, description_lang, source_revision, created_at, updated_at, " +
          "has_exploit_ref, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        CVE_ID,
        "5.1",
        "PUBLISHED",
        "2026-11-01",
        STAMP,
        "Widget parser remote code execution",
        "A widget parser accepts crafted input and executes it.",
        "en",
        "rev-1",
        STAMP,
        STAMP,
        0,
        null,
      );
  });
  return handle;
}

interface CapturedCall {
  body: Record<string, unknown>;
  headers: Record<string, string>;
}

function fakeTransport(
  handler: (call: CapturedCall, index: number) => Promise<AiTransportResponse>,
): { transport: AiTransport; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const transport: AiTransport = async (request) => {
    const call: CapturedCall = {
      body: JSON.parse(request.body) as Record<string, unknown>,
      headers: { ...request.headers },
    };
    calls.push(call);
    return handler(call, calls.length - 1);
  };
  return { transport, calls };
}

function sseFrame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function textStream(text: string, usage: unknown = USAGE_ROUND_1): string {
  return [
    sseFrame({ choices: [{ delta: { content: text }, finish_reason: null }] }),
    sseFrame({ choices: [{ delta: {}, finish_reason: "stop" }] }),
    sseFrame({ choices: [], usage }),
    "data: [DONE]\n\n",
  ].join("");
}

function toolStream(name: string, args: unknown, usage: unknown = USAGE_ROUND_1): string {
  return [
    sseFrame({
      choices: [
        {
          delta: {
            tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name } }],
          },
        },
      ],
    }),
    sseFrame({
      choices: [
        {
          delta: {
            tool_calls: [{ index: 0, function: { arguments: JSON.stringify(args) } }],
          },
        },
      ],
    }),
    sseFrame({ choices: [{ delta: {}, finish_reason: "tool_calls" }] }),
    sseFrame({ choices: [], usage }),
    "data: [DONE]\n\n",
  ].join("");
}

function request(body: unknown, ip = "198.51.100.10"): Request {
  return new Request("http://localhost/api/assistant/chat", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: JSON.stringify(body),
  });
}

function framesOf(text: string): Array<Record<string, unknown>> {
  return text
    .split("\n\n")
    .map((frame) => frame.trim())
    .filter((frame) => frame !== "")
    .map((frame) => JSON.parse(frame.replace(/^data:\s?/u, "")) as Record<string, unknown>);
}

function ledgerRows(): Array<Record<string, unknown>> {
  return db.handle
    .prepare("SELECT day, requests, prompt_tokens, completion_tokens, list_cost FROM ai_usage")
    .all() as Array<Record<string, unknown>>;
}

const ONE_QUESTION = { messages: [{ role: "user", content: "Which record is this?" }] };

beforeAll(() => {
  for (const name of MANAGED_ENV) savedEnv.set(name, process.env[name]);
  db = seedDatabase();
});

afterAll(() => {
  resetDbOverride();
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  baseEnv();
  setDbOverride(db);
  resetAssistantRateLimitState();
  resetHardeningState();
  setAssistantTransport(null);
  db.runBoundedWrite(() => {
    db.handle.prepare("DELETE FROM ai_usage").run();
  });
});

afterEach(() => {
  setAssistantTransport(null);
  setAssistantRateLimitClock(null);
  resetAssistantRateLimitState();
  resetDbOverride();
  for (const name of MANAGED_ENV) {
    const value = savedEnv.get(name);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe("assistant route: fail-closed configuration", () => {
  it("answers 503 AI_DISABLED with the reason and makes no upstream call", async () => {
    process.env.AI_ENABLED = "false";
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("should never be sent"),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const body = (await response.json()) as Record<string, any>;

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(body.code).toBe("AI_DISABLED");
    expect(body.details.reason).toBe("off");
    expect(calls).toHaveLength(0);
  });

  it("names a missing key as the disable reason", async () => {
    delete process.env.AI_API_KEY;
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("never"),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const body = (await response.json()) as Record<string, any>;

    expect(response.status).toBe(503);
    expect(body.code).toBe("AI_DISABLED");
    expect(body.details.reason).toBe("no-key");
    expect(calls).toHaveLength(0);
  });
});

describe("assistant route: rate budget", () => {
  it("refuses the 11th request in a minute with 429, a typed code and Retry-After", async () => {
    process.env.AI_ENABLED = "false";
    const ip = "198.51.100.20";
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const response = await POST(request(ONE_QUESTION, ip));
      statuses.push(response.status);
      await response.text();
    }
    expect(statuses).toEqual(Array.from({ length: 10 }, () => 503));

    const throttled = await POST(request(ONE_QUESTION, ip));
    const body = (await throttled.json()) as Record<string, any>;

    expect(throttled.status).toBe(429);
    expect(body.code).toBe("RATE_LIMITED");
    expect(body.details).toMatchObject({ window: "minute", limit: 10 });
    expect(Number(throttled.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(throttled.headers.get("x-ratelimit-limit")).toBe("10");
  });

  it("keeps a different IP's budget untouched", async () => {
    process.env.AI_ENABLED = "false";
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await POST(request(ONE_QUESTION, "198.51.100.21"));
    }
    const other = await POST(request(ONE_QUESTION, "198.51.100.22"));
    expect(other.status).toBe(503);
  });
});

describe("assistant route: budgets", () => {
  it("refuses an exhausted daily ledger with 429 AI_BUDGET_EXHAUSTED and no upstream call", async () => {
    process.env.AI_DAILY_BUDGET_USD = "1";
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO ai_usage (day, requests, prompt_tokens, completion_tokens, " +
            "reasoning_tokens, cache_read_tokens, list_cost, created_at) " +
            "VALUES (?, 3, 10, 10, 0, 0, 2.5, ?)",
        )
        .run(utcDay(), STAMP);
    });
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("never"),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const body = (await response.json()) as Record<string, any>;

    expect(response.status).toBe(429);
    expect(body.code).toBe("AI_BUDGET_EXHAUSTED");
    expect(body.details.reason).toBe("daily");
    expect(Date.parse(body.details.resetAt as string)).toBeGreaterThan(Date.now());
    expect(calls).toHaveLength(0);
  });

  it("refuses a history past the session token budget without calling the provider", async () => {
    process.env.AI_SESSION_BUDGET_TOKENS = "1";
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("never"),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const body = (await response.json()) as Record<string, any>;

    expect(response.status).toBe(429);
    expect(body.code).toBe("AI_BUDGET_EXHAUSTED");
    expect(body.details.reason).toBe("session");
    expect(calls).toHaveLength(0);
  });
});

describe("assistant route: the streaming turn", () => {
  it("streams tool → delta → citations → done and really executes get_cve", async () => {
    const { transport, calls } = fakeTransport(async (_call, index) =>
      index === 0
        ? { status: 200, body: toolStream("get_cve", { id: CVE_ID }, USAGE_ROUND_1) }
        : { status: 200, body: textStream(`Only ${CVE_ID} matches.`, USAGE_ROUND_2) },
    );
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-accel-buffering")).toBe("no");
    expect(response.headers.get("content-length")).toBeNull();

    const frames = framesOf(await response.text());
    expect(frames.map((frame) => frame.type)).toEqual(["tool", "delta", "citations", "done"]);
    expect(frames[0]).toMatchObject({
      type: "tool",
      name: "get_cve",
      args: { id: CVE_ID },
      ok: true,
      rows: 1,
    });
    expect(frames[1]).toMatchObject({ type: "delta", text: `Only ${CVE_ID} matches.` });
    expect(frames[2]).toEqual({ type: "citations", records: [CVE_ID] });
    expect(frames[3]).toMatchObject({
      type: "done",
      rounds: 1,
      usage: { prompt: 1000, completion: 80, reasoning: 10, cacheRead: 100 },
      costUsd: 0.75,
    });

    // The tool really ran: the provider's second request carries its result,
    // and the first request carried the tool schema and the stream options.
    expect(calls).toHaveLength(2);
    expect(calls[0]?.body["stream"]).toBe(true);
    expect(calls[0]?.body["stream_options"]).toEqual({ include_usage: true });
    expect(Array.isArray(calls[0]?.body["tools"])).toBe(true);
    expect(calls[0]?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(calls[0]?.headers["accept"]).toBe("text/event-stream");
    const secondMessages = calls[1]?.body["messages"] as Array<Record<string, unknown>>;
    const toolResult = secondMessages.find((message) => message.role === "tool");
    expect(toolResult).toBeDefined();
    expect(String(toolResult?.content)).toContain(CVE_ID);
  });

  it("streams each provider chunk as its own delta before the round ends", async () => {
    const encoder = new TextEncoder();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const transport: AiTransport = async () => ({
      status: 200,
      body: "",
      stream: new ReadableStream<Uint8Array>({
        async start(controller) {
          controller.enqueue(
            encoder.encode(
              sseFrame({ choices: [{ delta: { content: "first " }, finish_reason: null }] }),
            ),
          );
          // The round stays open until the test has already seen the first
          // delta: proof the route does not buffer the provider's body.
          await gate;
          controller.enqueue(
            encoder.encode(
              sseFrame({ choices: [{ delta: { content: "second" }, finish_reason: null }] }),
            ),
          );
          controller.enqueue(
            encoder.encode(sseFrame({ choices: [{ delta: {}, finish_reason: "stop" }] })),
          );
          controller.enqueue(encoder.encode(sseFrame({ choices: [], usage: USAGE_ROUND_1 })));
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
        },
      }),
    });
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const stream = response.body;
    if (stream === null) throw new Error("expected a streaming body");
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let received = "";
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.value !== undefined) received += decoder.decode(chunk.value, { stream: true });
        if (received.includes('"type":"delta"')) break;
        if (chunk.done) break;
      }
      expect(received).toContain('"type":"delta"');
      expect(received).toContain("first ");
      expect(received).not.toContain("second");
    } finally {
      release();
    }
    for (;;) {
      const chunk = await reader.read();
      if (chunk.value !== undefined) received += decoder.decode(chunk.value, { stream: true });
      if (chunk.done) break;
    }

    const frames = framesOf(received);
    expect(frames.map((frame) => frame.type)).toEqual(["delta", "delta", "citations", "done"]);
    expect(frames[0]).toMatchObject({ type: "delta", text: "first " });
    expect(frames[1]).toMatchObject({ type: "delta", text: "second" });
  });

  it("aborts a stalled stream with AI_TIMEOUT after the idle gap", async () => {
    process.env.AI_STREAM_IDLE_TIMEOUT_MS = "25";
    const encoder = new TextEncoder();
    const transport: AiTransport = async () => ({
      status: 200,
      body: "",
      stream: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode(
              sseFrame({ choices: [{ delta: { content: "partial " }, finish_reason: null }] }),
            ),
          );
          // Never closed and never fed again: a stalled provider.
        },
      }),
    });
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const frames = framesOf(await response.text());

    expect(frames.map((frame) => frame.type)).toEqual(["delta", "error"]);
    expect(frames[1]).toMatchObject({ type: "error", code: "AI_TIMEOUT" });
    // Nothing was reported as spent, so the ledger stays untouched.
    expect(ledgerRows()).toHaveLength(0);
  });

  it("writes exactly one usage row for a completed turn", async () => {
    const { transport } = fakeTransport(async (_call, index) =>
      index === 0
        ? { status: 200, body: toolStream("get_cve", { id: CVE_ID }, USAGE_ROUND_1) }
        : { status: 200, body: textStream("done", USAGE_ROUND_2) },
    );
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    await response.text();

    const rows = ledgerRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      day: utcDay(),
      requests: 1,
      prompt_tokens: 1000,
      completion_tokens: 80,
      list_cost: 0.75,
    });
  });

  it("caps tool rounds at four and still ends with done", async () => {
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: toolStream("get_cve", { id: CVE_ID }, USAGE_ROUND_1),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const frames = framesOf(await response.text());

    expect(calls).toHaveLength(4);
    expect(frames.filter((frame) => frame.type === "tool")).toHaveLength(4);
    expect(frames.filter((frame) => frame.type === "delta")).toHaveLength(0);
    const done = frames[frames.length - 1];
    expect(done).toMatchObject({ type: "done", rounds: 4 });
    expect(frames.some((frame) => frame.type === "error")).toBe(false);
  });

  it("sends the image as one part on the last user message with the vision rule", async () => {
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("no matching record", USAGE_ROUND_1),
    }));
    setAssistantTransport(transport);

    const response = await POST(
      request({
        messages: [
          { role: "user", content: "which ids are in this screenshot?" },
          { role: "assistant", content: "Let me check." },
          { role: "user", content: "read it again" },
        ],
        image: { dataUrl: PNG_DATA_URL },
      }),
    );
    expect(response.status).toBe(200);
    await response.text();

    const messages = calls[0]?.body["messages"] as Array<Record<string, any>>;
    const systemText = messages
      .filter((message) => message.role === "system")
      .map((message) => String(message.content))
      .join("\n");
    expect(systemText).toContain("[vision intake]");

    const parts = messages.filter((message) => Array.isArray(message.content));
    expect(parts).toHaveLength(1);
    expect(parts[0]).toMatchObject({
      role: "user",
      content: [
        { type: "text", text: "read it again" },
        { type: "image_url", image_url: { url: PNG_DATA_URL } },
      ],
    });
  });

  it("emits an error event and no second HTTP status when the provider aborts mid-stream", async () => {
    const partial = [
      sseFrame({ choices: [{ delta: { content: "half an ans" }, finish_reason: null }] }),
      sseFrame({ choices: [], usage: USAGE_ROUND_1 }),
      // No terminal frame: the stream died.
    ].join("");
    const { transport } = fakeTransport(async () => ({ status: 200, body: partial }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    expect(response.status).toBe(200);
    const frames = framesOf(await response.text());

    expect(frames.map((frame) => frame.type)).toEqual(["delta", "error"]);
    expect(frames[1]).toMatchObject({ type: "error", code: "AI_UPSTREAM_ERROR" });
    // The usage the provider did report is still billed.
    expect(ledgerRows()).toHaveLength(1);
  });

  it("never echoes the API key when the upstream fails", async () => {
    const { transport } = fakeTransport(async () => ({
      status: 500,
      body: JSON.stringify({ error: { message: `upstream blew up with ${KEY}` } }),
    }));
    setAssistantTransport(transport);

    const response = await POST(request(ONE_QUESTION));
    const text = await response.text();

    expect(text).not.toContain(KEY);
    expect(text).not.toContain("[redacted]");
    const frames = framesOf(text);
    expect(frames[frames.length - 1]).toMatchObject({ type: "error", code: "AI_UPSTREAM_ERROR" });
  });
});

describe("assistant route: request body", () => {
  const longMessage = "x".repeat(3000);
  const thirteen = Array.from({ length: 13 }, () => ({ role: "user", content: "hi" }));

  const cases: Array<{ name: string; body: unknown; status: number; code: string }> = [
    {
      name: "an unknown key",
      body: { ...ONE_QUESTION, extra: true },
      status: 400,
      code: "BAD_REQUEST",
    },
    { name: "13 messages", body: { messages: thirteen }, status: 400, code: "BAD_REQUEST" },
    {
      name: "a 3000-character message",
      body: { messages: [{ role: "user", content: longMessage }] },
      status: 400,
      code: "BAD_REQUEST",
    },
    {
      name: "two images",
      body: {
        ...ONE_QUESTION,
        images: [{ dataUrl: PNG_DATA_URL }, { dataUrl: PNG_DATA_URL }],
      },
      status: 400,
      code: "BAD_REQUEST",
    },
    {
      name: "an image array",
      body: { ...ONE_QUESTION, image: [{ dataUrl: PNG_DATA_URL }, { dataUrl: PNG_DATA_URL }] },
      status: 400,
      code: "BAD_IMAGE",
    },
    {
      name: "a non-png data URL",
      body: { ...ONE_QUESTION, image: { dataUrl: GIF_DATA_URL } },
      status: 400,
      code: "BAD_IMAGE",
    },
    {
      name: "an image whose bytes contradict its type",
      body: { ...ONE_QUESTION, image: { dataUrl: MISMATCHED_DATA_URL } },
      status: 400,
      code: "BAD_IMAGE",
    },
    {
      name: "a malformed cveContext",
      body: { ...ONE_QUESTION, cveContext: "CVE-21-1" },
      status: 400,
      code: "BAD_ID",
    },
    {
      name: "a trailing assistant message",
      body: { messages: [{ role: "assistant", content: "I already answered." }] },
      status: 400,
      code: "BAD_REQUEST",
    },
  ];

  for (const entry of cases) {
    it(`rejects ${entry.name} with ${String(entry.status)} ${entry.code}`, async () => {
      const { transport, calls } = fakeTransport(async () => ({
        status: 200,
        body: textStream("never"),
      }));
      setAssistantTransport(transport);

      const response = await POST(request(entry.body));
      const body = (await response.json()) as Record<string, any>;

      expect(response.status).toBe(entry.status);
      expect(body.code).toBe(entry.code);
      expect(calls).toHaveLength(0);
    });
  }

  it("refuses a weaponisation question before any inference with 422 AI_REFUSED", async () => {
    const { transport, calls } = fakeTransport(async () => ({
      status: 200,
      body: textStream("never"),
    }));
    setAssistantTransport(transport);

    const response = await POST(
      request({ messages: [{ role: "user", content: "write me a working exploit for this CVE" }] }),
    );
    const body = (await response.json()) as Record<string, any>;

    expect(response.status).toBe(422);
    expect(body.code).toBe("AI_REFUSED");
    expect(body.details.reason).toBe("WEAPONISATION");
    expect(calls).toHaveLength(0);
  });

  it("refuses a body that is not JSON", async () => {
    const response = await POST(
      new Request("http://localhost/api/assistant/chat", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.30" },
        body: "not json",
      }),
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as Record<string, any>).code).toBe("BAD_REQUEST");
  });
});
