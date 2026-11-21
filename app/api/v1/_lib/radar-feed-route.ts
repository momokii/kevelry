// Shared HTTP layer for the Change Radar feeds (v3 epic E5). The RSS 2.0 and
// Atom 1.0 routes differ only in content type, feed path, ETag discriminator,
// and serializer: validation, the retention clamp, event selection and
// ordering, the ETag seed, caching, and the guardrails live here once so the
// two formats cannot drift into serving different event sets.
import { RADAR_RETENTION_DAYS, listCheckpoints } from "../../../../src/lib/radar";
import {
  earliestAllowedCheckpointDate,
  rfc822Timestamp,
  type RadarFeedEvent,
  type RadarFeedMeta,
} from "../../../../src/lib/radar-feed";
import { resolvePublicBaseUrl } from "../../../../src/lib/site-url";
import { withApiRoute } from "./api-route";
import { ApiError } from "./errors";
import {
  applyCorsHeaders,
  applyRateHeaders,
  applySecurityHeaders,
  type RateReservation,
} from "./guardrails";
import { CACHE_CONTROL_HEADER, etagFromSeed, etagMatches } from "./http-cache";
import { parseDay, parseLimit } from "./params";
import { buildRadarEvents, parseCveIdParam, parseRadarKind } from "./radar-api";

/** Per-format wiring a feed route supplies to the shared handler. */
export interface RadarFeedFormat {
  /** Response `Content-Type`, e.g. `application/atom+xml; charset=utf-8`. */
  contentType: string;
  /** Route path, used to build the feed's absolute self link and id. */
  path: string;
  /**
   * ETag discriminator. The checkpoint set and query shape seed both formats
   * identically; the tag keeps a validator minted for one representation from
   * revalidating the other.
   */
  etagTag: string;
  /** Serializes the already-filtered, already-limited events. */
  serialize: (events: readonly RadarFeedEvent[], meta: RadarFeedMeta) => string;
}

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
  format: RadarFeedFormat,
  body: string | null,
  status: number,
  etag: string,
  lastModified: string | null,
  reservation: RateReservation,
): Response {
  const response =
    body === null
      ? new Response(null, { status })
      : new Response(body, { status, headers: { "Content-Type": format.contentType } });
  response.headers.set("ETag", etag);
  response.headers.set("Cache-Control", CACHE_CONTROL_HEADER);
  if (lastModified !== null) response.headers.set("Last-Modified", lastModified);
  applyRateHeaders(response, reservation);
  applySecurityHeaders(response, request);
  applyCorsHeaders(request, response);
  return response;
}

/**
 * Serves one Change Radar feed: same query parameters, validation, retention
 * clamp, ordering, event selection, cache policy, and guards for every format.
 * The route owns only the `GET`/`OPTIONS` exports; the shared `withApiRoute`
 * wrapper owns the guard sequence and this handler owns the feed body, so the
 * 304 + cache + security header path stays exactly as it was.
 */
export const handleRadarFeed = withApiRoute<[RadarFeedFormat]>(
  async ({ request, db, rate }, format) => {
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
        format.etagTag,
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
    // `url.origin` is the bind address (0.0.0.0) under the standalone server,
    // so absolute links come from configuration or proxy headers; null means
    // the public origin is unknown and the serializer omits those links.
    const publicBase = resolvePublicBaseUrl(request.headers);
    const body = format.serialize(events, {
      feedUrl: publicBase === null ? null : withQuery(publicBase, format.path, query),
      jsonUrl: publicBase === null ? null : withQuery(publicBase, "/api/v1/radar", query),
      lastBuildAt: newest?.observedAt ?? null,
      earliestAllowedDay: earliestAllowed,
      hasRetainedCheckpoints: checkpoints.length > 0,
    });
    const lastModified = rfc822Timestamp(newest?.observedAt ?? null);

    if (etagMatches(request, etag)) {
      return feedResponse(request, format, null, 304, etag, lastModified, rate);
    }
    return feedResponse(request, format, body, 200, etag, lastModified, rate);
  },
);
