import type { CveDatabase } from "../../../../src/lib/db";
import { errorStatus, type ErrorCode } from "./errors";
import {
  applyCorsHeaders,
  applyRateHeaders,
  applySecurityHeaders,
  checkRateLimit,
  clientKeyFor,
  type RateReservation,
} from "./guardrails";
import { buildProvenance } from "./provenance";

function requestId(): string {
  return `req-${Date.now().toString(36)}${Math.floor(Math.random() * 0xffffff)
    .toString(36)
    .padStart(4, "0")}`;
}

export function errorResponse(
  request: Request,
  code: ErrorCode,
  message: string,
  db: CveDatabase | null,
  details?: Record<string, unknown>,
  reservation?: RateReservation,
): Response {
  const provenance = buildProvenance(db, new Date().toISOString());
  const status = errorStatus(code);
  const body: Record<string, unknown> = { code, message, requestId: requestId(), provenance };
  if (details !== undefined) body.details = details;
  const response = Response.json(body, { status });
  const rate = reservation ?? checkRateLimit(clientKeyFor(request));
  applyRateHeaders(response, rate);
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  if (status === 429) {
    response.headers.set("Retry-After", String(Math.max(rate.reset, 1)));
  }
  return response;
}

export function okResponse(
  request: Request,
  payload: Record<string, unknown>,
  reservation?: RateReservation,
): Response {
  const response = Response.json(payload);
  applyRateHeaders(response, reservation ?? checkRateLimit(clientKeyFor(request)));
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}

/**
 * Reserve one hit from the per-IP fixed window. Handlers call this first and
 * thread the reservation through every ok/error response so each request is
 * counted exactly once. Returns null when the budget is spent.
 */
export function reserveRateLimit(
  request: Request,
  db: CveDatabase | null,
): RateReservation | Response {
  const rate = checkRateLimit(clientKeyFor(request));
  if (!rate.allowed) {
    return errorResponse(
      request,
      "RATE_LIMITED",
      "Rate limit exceeded. Retry after 60 seconds.",
      db,
      undefined,
      rate,
    );
  }
  return rate;
}
