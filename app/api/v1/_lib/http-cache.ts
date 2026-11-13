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

function etagMatches(request: Request, etag: string): boolean {
  const raw = request.headers.get("if-none-match");
  if (raw === null) return false;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .includes(etag);
}

/**
 * Success response with Cache-Control and, when the aggregate cache has a
 * revision, a strong ETag + 304 on If-None-Match. Error paths must not use
 * this helper: error responses stay uncacheable.
 */
export function cachedOkResponse(
  request: Request,
  db: CveDatabase | null,
  payload: Record<string, unknown>,
  reservation?: RateReservation,
  opts: { seedParts?: string[] } = {},
): Response {
  const seed = getCacheSeed(db, opts.seedParts ?? [request.url]);
  if (seed === null) {
    const fallback = okResponse(request, payload, reservation);
    fallback.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
    return fallback;
  }
  const etag = etagFromSeed(seed);
  if (etagMatches(request, etag)) {
    const notModified = new Response(null, { status: 304 });
    notModified.headers.set("ETag", etag);
    notModified.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
    applyRateHeaders(notModified, reservation ?? checkRateLimit(clientKeyFor(request)));
    applySecurityHeaders(notModified);
    applyCorsHeaders(request, notModified);
    return notModified;
  }
  const response = okResponse(request, payload, reservation);
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  return response;
}
