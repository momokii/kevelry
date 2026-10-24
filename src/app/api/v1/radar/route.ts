import { listCheckpoints } from "../../../../lib/radar";
import {
  ApiError,
  buildProvenance,
  buildRadarEvents,
  errorResponse,
  getDb,
  okResponse,
  paginate,
  parseCursor,
  parseCveIdParam,
  parseLimit,
  parseDay,
  parseRadarKind,
  reserveRateLimit,
} from "../_lib/shared";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  let db = null;
  try {
    db = getDb();
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", null);
  }
  const rate = reserveRateLimit(request, db);
  if (rate instanceof Response) return rate;
  try {
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
    return okResponse(
      request,
      {
        data: page,
        pagination: { limit, hasMore, nextCursor },
        provenance: buildProvenance(db, nowIso),
      },
      rate,
    );
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  }
}
