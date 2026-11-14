// RSS 2.0 change feed (v3 epic E5). Snapshot-backed: the events are exactly
// the ones GET /api/v1/radar serves from retained checkpoints, filtered with
// the same parsers, serialized with a factual item mapping. No upstream call,
// no export, no pagination cursor (feeds are bounded by `limit`).
import { RADAR_RETENTION_DAYS, listCheckpoints } from "../../../../../src/lib/radar";
import {
  buildRadarFeed,
  earliestAllowedCheckpointDate,
  rfc822Timestamp,
} from "../../../../../src/lib/radar-feed";
import { getDb } from "../../_lib/db-handle";
import {
  acquireConcurrencySlot,
  applyCorsHeaders,
  applyRateHeaders,
  applySecurityHeaders,
  assertRequestBounds,
  preflightResponse,
  releaseConcurrencySlot,
  type RateReservation,
} from "../../_lib/guardrails";
import { ApiError } from "../../_lib/errors";
import { errorResponse, reserveRateLimit } from "../../_lib/responses";
import { CACHE_CONTROL_HEADER, etagFromSeed, etagMatches } from "../../_lib/http-cache";
import { parseDay, parseLimit } from "../../_lib/params";
import { buildRadarEvents, parseCveIdParam, parseRadarKind } from "../../_lib/radar-api";

export const dynamic = "force-dynamic";

const FEED_CONTENT_TYPE = "application/rss+xml; charset=utf-8";
const FEED_PATH = "/api/v1/radar/feed.xml";
const JSON_FEED_PATH = "/api/v1/radar";

/** Canonical filter set shared by the self link and the JSON-feed link. */
function canonicalQuery(
  since: string | null,
  kind: string | null,
  cveId: string | null,
  limitRaw: string | null,
  limit: number,
): string {
  const params = new URLSearchParams();
  if (since !== null) params.set("since", since);
  if (kind !== null) params.set("kind", kind);
  if (cveId !== null) params.set("cveId", cveId);
  if (limitRaw !== null && limitRaw !== "") params.set("limit", String(limit));
  return params.toString();
}

function withQuery(origin: string, path: string, query: string): string {
  return query === "" ? `${origin}${path}` : `${origin}${path}?${query}`;
}

function feedResponse(
  request: Request,
  body: string | null,
  status: number,
  etag: string,
  lastModified: string | null,
  reservation: RateReservation,
): Response {
  const response =
    body === null
      ? new Response(null, { status })
      : new Response(body, { status, headers: { "Content-Type": FEED_CONTENT_TYPE } });
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  if (lastModified !== null) response.headers.set("Last-Modified", lastModified);
  applyRateHeaders(response, reservation);
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}

export async function OPTIONS(request: Request): Promise<Response> {
  return preflightResponse(request);
}

export async function GET(request: Request): Promise<Response> {
  let db = null;
  try {
    db = getDb();
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", null);
  }
  const rate = reserveRateLimit(request, db);
  if (rate instanceof Response) return rate;
  if (!acquireConcurrencySlot()) {
    return errorResponse(
      request,
      "RATE_LIMITED",
      "Server is busy. Retry after 60 seconds.",
      db,
      undefined,
      rate,
    );
  }
  try {
    assertRequestBounds(request);
    const url = new URL(request.url);
    const params = url.searchParams;
    const limitRaw = params.get("limit");
    const limit = parseLimit(limitRaw);
    const sinceRaw = params.get("since");
    const since = sinceRaw === null || sinceRaw === "" ? null : parseDay(sinceRaw, "since", true);
    const kind = parseRadarKind(params.get("kind"));
    const cveId = parseCveIdParam(params.get("cveId"));

    // v3 plan 15.1.4: `since` is clamped to checkpoint retention. Out-of-range
    // is an explicit error naming the earliest allowed date — an empty 200
    // would claim "no changes" for a window the service cannot look at.
    const earliestAllowed = earliestAllowedCheckpointDate(new Date());
    if (since !== null && since < earliestAllowed) {
      throw new ApiError(
        "BAD_FILTER",
        400,
        `since is older than the ${RADAR_RETENTION_DAYS}-day checkpoint retention window; the earliest allowed date is ${earliestAllowed}.`,
      );
    }

    const checkpoints = listCheckpoints(db);
    const events = buildRadarEvents(checkpoints)
      .filter((event) => {
        if (since !== null && event.checkpointDate < since) return false;
        if (kind !== null && event.kind !== kind) return false;
        if (cveId !== null && event.cveId !== cveId) return false;
        return true;
      })
      .slice(0, limit);

    const newest = checkpoints[checkpoints.length - 1] ?? null;
    const oldest = checkpoints[0] ?? null;
    // The newest checkpoint is the primary seed, but retention pruning can drop
    // old events without adding one, so the oldest date and the retained count
    // join the seed: a pruned feed must invalidate a cached one.
    const etag = etagFromSeed(
      [
        newest?.checkpointDate ?? "none",
        oldest?.checkpointDate ?? "none",
        String(checkpoints.length),
        since ?? "-",
        kind ?? "-",
        cveId ?? "-",
        String(limit),
      ].join("|"),
    );

    const query = canonicalQuery(since, kind, cveId, limitRaw, limit);
    const body = buildRadarFeed(events, {
      feedUrl: withQuery(url.origin, FEED_PATH, query),
      jsonUrl: withQuery(url.origin, JSON_FEED_PATH, query),
      lastBuildAt: newest?.observedAt ?? null,
      earliestAllowedDay: earliestAllowed,
      hasRetainedCheckpoints: checkpoints.length > 0,
    });
    const lastModified = rfc822Timestamp(newest?.observedAt ?? null);

    if (etagMatches(request, etag)) {
      return feedResponse(request, null, 304, etag, lastModified, rate);
    }
    return feedResponse(request, body, 200, etag, lastModified, rate);
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(
      request,
      "INTERNAL",
      "Unexpected failure handling the request.",
      db,
      undefined,
      rate,
    );
  } finally {
    releaseConcurrencySlot();
  }
}
