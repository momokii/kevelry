import { listCheckpoints } from "../../../../src/lib/radar";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  buildRadarEvents,
  errorResponse,
  getDb,
  cachedOkResponse,
  paginate,
  parseCursor,
  parseCveIdParam,
  parseLimit,
  parseDay,
  parseRadarKind,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
} from "../_lib/shared";

export const dynamic = "force-dynamic";

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
    return errorResponse(request, "RATE_LIMITED", "Server is busy. Retry after 60 seconds.", db, undefined, rate);
  }
  try {
    assertRequestBounds(request);
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
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  } finally {
    releaseConcurrencySlot();
  }
}
