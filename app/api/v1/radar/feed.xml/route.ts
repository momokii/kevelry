// RSS 2.0 change feed (v3 epic E5). Snapshot-backed: the events are exactly
// the ones GET /api/v1/radar serves from retained checkpoints, filtered with
// the same parsers, serialized with a factual item mapping. No upstream call,
// no export, no pagination cursor (feeds are bounded by `limit`). The HTTP,
// validation, clamp, and ETag layer is shared with the Atom route in
// `_lib/radar-feed-route.ts`, so both formats select the same event set.
import { buildRadarFeed } from "../../../../../src/lib/radar-feed";
import { preflightResponse } from "../../_lib/guardrails";
import { handleRadarFeed, type RadarFeedFormat } from "../../_lib/radar-feed-route";

export const dynamic = "force-dynamic";

const RSS_FEED: RadarFeedFormat = {
  contentType: "application/rss+xml; charset=utf-8",
  path: "/api/v1/radar/feed.xml",
  etagTag: "rss",
  serialize: buildRadarFeed,
};

export async function OPTIONS(request: Request): Promise<Response> {
  return preflightResponse(request);
}

export async function GET(request: Request): Promise<Response> {
  return handleRadarFeed(request, RSS_FEED);
}
