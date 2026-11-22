// POST /api/assistant/chat — the assistant turn.
//
// Deliberately *outside* `/api/v1`: the public v1 contract is GET-only and
// read-only, and this route is UI-only. It writes nothing but the aggregate
// spend ledger, keeps no transcript, and fails closed when unconfigured. Keeping
// it out of the versioned namespace means the read contract's "no POST" promise
// stays true.
//
// Guard order is the contract, cheapest and safest first:
//
//   1. rate     10/min and 60/hour per IP, its own buckets (a chat loop must not
//                eat the read API's 600/min headroom).
//   2. db       a broken database is `INTERNAL` before any budget is spent.
//   3. slot     the v1 concurrency counter, held until the *stream* closes.
//   4. body     bounded read, strict schema, magic-byte-checked image.
//   5. config   `AI_DISABLED` 503 carrying the reason, never a stack trace.
//   6. preScreen the cheap, unconditional filter on the last user message.
//   7. budget   the daily ledger and the session estimate, `AI_BUDGET_EXHAUSTED`.
//   8. turn     the tool loop, streamed as SSE.
//
// Nothing in this file logs, echoes or persists prompt or answer text. The only
// stored artefact is the aggregate usage row the turn loop writes.

import {
  aiGate,
  loadAiConfig,
  type AiConfig,
  type AiDisabledReason,
} from "../../../../src/lib/ai/config";
import { createAiClient } from "../../../../src/lib/ai/client";
import { preScreen } from "../../../../src/lib/ai/guardrails";
import { runAssistantTurn } from "../../../../src/lib/ai/turn";
import { createAiUsageLedger } from "../../../../src/lib/ai/usage";
import type { CveDatabase } from "../../../../src/lib/db";
import { getDb } from "../../v1/_lib/db-handle";
import { acquireConcurrencySlot, releaseConcurrencySlot } from "../../v1/_lib/guardrails";
import { estimateSessionTokens, readAssistantBody, validateAssistantBody } from "../_lib/body";
import { reserveAssistantRateLimit } from "../_lib/rate-limit";
import { assistantErrorResponse, assistantSseResponse } from "../_lib/response";
import { resolveAssistantTransport } from "../_lib/transport";

/** No cache, no ISR: every turn is a POST with a per-IP budget. */
export const dynamic = "force-dynamic";

const DISABLED_MESSAGES: Record<AiDisabledReason, string> = {
  off: "The AI assistant is turned off on this deployment (AI_ENABLED=false).",
  "no-key": "The AI assistant is disabled because no gateway key is configured (AI_API_KEY).",
  "over-budget": "The AI assistant has reached today's spend budget.",
  "invalid-config": "The AI assistant is not configured correctly on this deployment.",
};

/** The instant the daily budget resets: the next UTC midnight. */
function nextUtcMidnight(now: Date): string {
  const next = new Date(now);
  next.setUTCHours(24, 0, 0, 0);
  return next.toISOString();
}

export async function POST(request: Request): Promise<Response> {
  // 1. Its own rate budget, before a byte of body is buffered.
  const rate = reserveAssistantRateLimit(request);
  if (!rate.allowed) {
    return assistantErrorResponse(
      request,
      "RATE_LIMITED",
      `The assistant accepts ${String(rate.limit)} requests per ${rate.window}. Retry in ${String(rate.reset)} seconds.`,
      null,
      { window: rate.window, limit: rate.limit },
      rate,
    );
  }

  // 2. A database failure is not the client's fault and must not spend a slot.
  let db: CveDatabase;
  try {
    db = getDb();
  } catch {
    return assistantErrorResponse(
      request,
      "INTERNAL",
      "Unexpected failure handling the request.",
      null,
      undefined,
      rate,
    );
  }

  // 3. The shared concurrency counter. Released when the stream settles, below.
  if (!acquireConcurrencySlot()) {
    return assistantErrorResponse(
      request,
      "RATE_LIMITED",
      "Server is busy. Retry after 60 seconds.",
      db,
      { window: "concurrency" },
      rate,
    );
  }
  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
    releaseConcurrencySlot();
  };

  // 4. Bounded read + strict schema.
  const read = await readAssistantBody(request);
  if (!read.ok) {
    release();
    return assistantErrorResponse(request, read.code, read.message, db, read.details, rate);
  }
  const validated = validateAssistantBody(read.value);
  if (!validated.ok) {
    release();
    return assistantErrorResponse(
      request,
      validated.code,
      validated.message,
      db,
      validated.details,
      rate,
    );
  }
  const body = validated.body;

  // 5. Fail closed when unconfigured. The gate reports *why*, never the key.
  let config: AiConfig;
  try {
    config = loadAiConfig(process.env);
  } catch {
    release();
    const reason: AiDisabledReason = "invalid-config";
    return assistantErrorResponse(
      request,
      "AI_DISABLED",
      DISABLED_MESSAGES[reason],
      db,
      { reason },
      rate,
    );
  }
  const gate = aiGate(config);
  if (!gate.enabled) {
    release();
    const reason = gate.disabled ?? "off";
    return assistantErrorResponse(
      request,
      "AI_DISABLED",
      DISABLED_MESSAGES[reason],
      db,
      { reason },
      rate,
    );
  }

  // 6. The cheap pre-inference filter. A refusal is not a fault: it names what
  //    the assistant can do and costs no tokens.
  const lastUser = body.messages[body.messages.length - 1];
  const screened = preScreen(lastUser?.content ?? "", { maxChars: config.maxInputChars });
  if (!screened.ok) {
    release();
    const details: Record<string, unknown> = { reason: screened.reason };
    if (screened.patternId !== undefined) details.patternId = screened.patternId;
    if (screened.reason === "WEAPONISATION") {
      return assistantErrorResponse(request, "AI_REFUSED", screened.message, db, details, rate);
    }
    return assistantErrorResponse(request, "BAD_QUERY", screened.message, db, details, rate);
  }

  // 7. Budgets. The daily cap is money read from storage, so a restart cannot
  //    buy fresh tokens; the session cap is the history the client sent.
  const ledger = createAiUsageLedger({
    db,
    budget: {
      sessionBudgetTokens: config.sessionBudgetTokens,
      dailyBudgetUsd: config.dailyBudgetUsd,
    },
  });
  const now = new Date();
  if (ledger.dailyBudgetExceeded()) {
    release();
    return assistantErrorResponse(
      request,
      "AI_BUDGET_EXHAUSTED",
      "The daily AI budget for this deployment is spent. It resets at 00:00 UTC.",
      db,
      { reason: "daily", resetAt: nextUtcMidnight(now) },
      rate,
    );
  }
  if (ledger.sessionBudgetExceeded({ sessionTokens: estimateSessionTokens(body.messages) })) {
    release();
    return assistantErrorResponse(
      request,
      "AI_BUDGET_EXHAUSTED",
      "This conversation has reached its token budget. Start a new one.",
      db,
      { reason: "session", resetAt: now.toISOString() },
      rate,
    );
  }

  // 8. The turn.
  const events = runAssistantTurn({
    config,
    db,
    client: createAiClient({ config, transport: resolveAssistantTransport() }),
    ledger,
    messages: body.messages,
    image: body.image,
    cveContext: body.cveContext,
    signal: request.signal,
  });
  return assistantSseResponse(request, events, { onClose: release });
}
