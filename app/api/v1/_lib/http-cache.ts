import { createHash } from "node:crypto";

import { getAggregateMeta } from "../../../../src/lib/aggregates";
import type { CveDatabase } from "../../../../src/lib/db";
import {
  applyCorsHeaders,
  applyRateHeaders,
  applySecurityHeaders,
  checkRateLimit,
  clientKeyFor,
  type RateReservation,
} from "./guardrails";
import { okResponse } from "./responses";

/** Shared cache policy for success GETs: cheap revalidation, stale shielded. */
export const CACHE_CONTROL_HEADER = "public, max-age=30, s-maxage=60, stale-while-revalidate=300";

/** Strong ETag from a revision seed (aggregate revision + request shape). */
export function etagFromSeed(seed: string): string {
  return `"${createHash("sha256").update(seed, "utf8").digest("hex")}"`;
}

/**
 * Revision seed for ETags: aggregate computed_at + source pins. Null when the
 * cache is empty (caller then skips ETag/304 but still sets Cache-Control).
 */
export function getCacheSeed(db: CveDatabase | null, extra: string[] = []): string | null {
  if (db === null) return null;
  const meta = getAggregateMeta(db);
  if (meta === null) return null;
  return [meta.computedAt, meta.sourceRevision ?? "-", meta.epssScoreDate ?? "-", ...extra].join(
    "|",
  );
}

/** True when the request's If-None-Match list contains the given strong ETag. */
export function etagMatches(request: Request, etag: string): boolean {
  const raw = request.headers.get("if-none-match");
  if (raw === null) return false;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .includes(etag);
}

/** 304 revalidation response, sharing the success cache/security/rate layer. */
function notModified(request: Request, etag: string, reservation?: RateReservation): Response {
  const response = new Response(null, { status: 304 });
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  applyRateHeaders(response, reservation ?? checkRateLimit(clientKeyFor(request)));
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}

/**
 * Success response with Cache-Control and, when the aggregate cache has a
 * revision, a strong ETag + 304 on If-None-Match. Error paths must not use
 * this helper: error responses stay uncacheable. `opts.headers` carries
 * additive headers such as an export `Content-Disposition`.
 */
export function cachedOkResponse(
  request: Request,
  db: CveDatabase | null,
  payload: Record<string, unknown>,
  reservation?: RateReservation,
  opts: { seedParts?: string[]; headers?: Record<string, string> } = {},
): Response {
  const seed = getCacheSeed(db, opts.seedParts ?? [request.url]);
  if (seed === null) {
    const fallback = okResponse(request, payload, reservation);
    fallback.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
    for (const [name, value] of Object.entries(opts.headers ?? {})) {
      fallback.headers.set(name, value);
    }
    return fallback;
  }
  const etag = etagFromSeed(seed);
  if (etagMatches(request, etag)) return notModified(request, etag, reservation);
  const response = okResponse(request, payload, reservation);
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  for (const [name, value] of Object.entries(opts.headers ?? {})) {
    response.headers.set(name, value);
  }
  return response;
}

/**
 * Non-JSON success body (the CSV export) under the same cache policy: the
 * aggregate revision plus the request shape seed the ETag, so a revalidated
 * export answers 304 exactly like the JSON routes.
 */
export function cachedTextResponse(
  request: Request,
  db: CveDatabase | null,
  body: string,
  headers: Record<string, string>,
  reservation?: RateReservation,
  opts: { seedParts?: string[] } = {},
): Response {
  const seed = getCacheSeed(db, opts.seedParts ?? [request.url]);
  if (seed === null) {
    const fallback = new Response(body, { headers });
    fallback.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
    applyRateHeaders(fallback, reservation ?? checkRateLimit(clientKeyFor(request)));
    applySecurityHeaders(fallback);
    applyCorsHeaders(request, fallback);
    return fallback;
  }
  const etag = etagFromSeed(seed);
  if (etagMatches(request, etag)) return notModified(request, etag, reservation);
  const response = new Response(body, { headers });
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  applyRateHeaders(response, reservation ?? checkRateLimit(clientKeyFor(request)));
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}
