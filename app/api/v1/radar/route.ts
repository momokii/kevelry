import { listCheckpoints } from "../../../../src/lib/radar";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { cachedOkResponse } from "../_lib/http-cache";
import { paginate, parseCursor, parseLimit, parseDay } from "../_lib/params";
import { buildProvenance } from "../_lib/provenance";
import { buildRadarEvents, parseCveIdParam, parseRadarKind } from "../_lib/radar-api";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const params = new URL(request.url).searchParams;
  const limit = parseLimit(params.get("limit"));
  const offset = parseCursor(params.get("cursor"));
  const sinceRaw = params.get("since");
  const since = sinceRaw === null || sinceRaw === "" ? null : parseDay(sinceRaw, "since", true);
  const kind = parseRadarKind(params.get("kind"));
  const cveId = parseCveIdParam(params.get("cveId"));
  const events = buildRadarEvents(listCheckpoints(db)).filter((event) => {
    if (since !== null && event.checkpointDate < since) return false;
    if (kind !== null && event.kind !== kind) return false;
    if (cveId !== null && event.cveId !== cveId) return false;
    return true;
  });
  const { page, hasMore, nextCursor } = paginate(events, offset, limit);
  const nowIso = new Date().toISOString();
  return cachedOkResponse(
    request,
    db,
    {
      data: page,
      pagination: { limit, hasMore, nextCursor },
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
