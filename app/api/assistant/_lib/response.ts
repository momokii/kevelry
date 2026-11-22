// Responses for the one route outside `/api/v1`.
//
// The error body is the v1 `errorResponse` — same shape, same provenance
// envelope, same `no-store` — because a second error format in the same app is
// how clients end up with two parsers. Two things are overridden here:
//
//  1. The `X-RateLimit-*` numbers: `errorResponse` reports the v1 budget (600),
//     which would be a lie on a route nobody can call 600 times a minute.
//  2. Nothing else. `Retry-After` on a 429 already comes from the reservation.
//
// The stream response sets the three headers a proxy needs to *not* buffer an
// SSE body, and nothing that would make one (no `Content-Length`). Security
// headers match the rest of the API. Once this response is returned the turn's
// status is 200 forever: later failures are `error` events, never a second
// status line, because a client that already consumed frames cannot be told
// about an HTTP status it will never read.

import type { CveDatabase } from "../../../../src/lib/db";
import type { ErrorCode } from "../../v1/_lib/errors";
import { applyCorsHeaders, applySecurityHeaders } from "../../v1/_lib/guardrails";
import { errorResponse } from "../../v1/_lib/responses";
import { encodeAssistantEvent, type AssistantEvent } from "../../../../src/lib/ai/turn";
import type { AssistantRateState } from "./rate-limit";

function applyAssistantRateHeaders(response: Response, rate: AssistantRateState): Response {
  response.headers.set("X-RateLimit-Limit", String(rate.limit));
  response.headers.set("X-RateLimit-Remaining", String(rate.remaining));
  response.headers.set("X-RateLimit-Reset", String(rate.reset));
  return response;
}

/**
 * A pre-stream failure: normal JSON, `no-store`, and the assistant's own budget
 * numbers. `Retry-After` is set by `errorResponse` from the same reservation.
 */
export function assistantErrorResponse(
  request: Request,
  code: ErrorCode,
  message: string,
  db: CveDatabase | null,
  details: Record<string, unknown> | undefined,
  rate: AssistantRateState,
): Response {
  const response = errorResponse(request, code, message, db, details, rate);
  return applyAssistantRateHeaders(response, rate);
}

export interface SseOptions {
  /** Called exactly once, when the stream closes or is cancelled. */
  onClose: () => void;
}

/**
 * Wraps an event iterable in an SSE `Response`.
 *
 * The concurrency slot is released when the *stream* settles, not when the
 * handler returns: holding it until the last frame is the whole reason this
 * response is not built by `withApiRoute`. A consumer that cancels (browser
 * closed, test skipped) triggers the iterator's `return`, so the turn's ledger
 * write in its `finally` still happens and the slot is still freed.
 */
export function assistantSseResponse(
  request: Request,
  events: AsyncGenerator<AssistantEvent>,
  options: SseOptions,
): Response {
  const encoder = new TextEncoder();
  let closed = false;
  const finish = (): void => {
    if (closed) return;
    closed = true;
    options.onClose();
  };
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        for await (const event of events) {
          if (closed) break;
          controller.enqueue(encoder.encode(encodeAssistantEvent(event)));
        }
        if (!closed) controller.close();
      } catch {
        // The turn loop yields typed errors; a throw here is a bug in the
        // plumbing, and it still must not become a silent truncation.
        if (!closed) {
          controller.enqueue(
            encoder.encode(
              encodeAssistantEvent({
                type: "error",
                code: "AI_UPSTREAM_ERROR",
                message: "The assistant stream failed unexpectedly.",
              }),
            ),
          );
          controller.close();
        }
      } finally {
        finish();
      }
    },
    cancel() {
      closed = true;
      finish();
      void events.return(undefined);
    },
  });
  const response = new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store",
      // The reverse proxy must not buffer: a buffered SSE body is a spinner.
      "X-Accel-Buffering": "no",
    },
  });
  applySecurityHeaders(response, request);
  applyCorsHeaders(request, response);
  return response;
}
