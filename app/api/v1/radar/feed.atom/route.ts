// Atom 1.0 change feed (v3 epic E5). The same retained events, query
// parameters, retention clamp, cache validators, and guards as the RSS route,
// serialized to RFC 4287. The shared handler in `_lib/radar-feed-route.ts` owns
// selection, so this file only names the format and its serializer.
import { buildRadarAtomFeed } from "../../../../../src/lib/radar-feed";
import { apiPreflight } from "../../_lib/api-route";
import { handleRadarFeed, type RadarFeedFormat } from "../../_lib/radar-feed-route";

export const dynamic = "force-dynamic";

const ATOM_FEED: RadarFeedFormat = {
  contentType: "application/atom+xml; charset=utf-8",
  path: "/api/v1/radar/feed.atom",
  etagTag: "atom",
  serialize: buildRadarAtomFeed,
};

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export async function GET(request: Request): Promise<Response> {
  return handleRadarFeed(request, ATOM_FEED);
}
