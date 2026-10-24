import { listCheckpoints, replayCheckpoint } from "../../../../lib/radar";
import {
  ApiError,
  buildProvenance,
  coverageForSnapshots,
  errorResponse,
  getDb,
  mapReplayReason,
  okResponse,
  paginate,
  parseCursor,
  parseDay,
  parseLimit,
  reserveRateLimit,
  todayUtcDay,
  toReplayItem,
} from "../_lib/shared";

export const dynamic = "force-dynamic";

const VIEWS = ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"] as const;
type ViewName = (typeof VIEWS)[number];

const VIEW_KEYS: Record<ViewName, "knownExploited" | "highestForecast" | "newCritical" | "risingForecast"> = {
  "known-exploited": "knownExploited",
  "highest-forecast": "highestForecast",
  "new-critical": "newCritical",
  "rising-forecast": "risingForecast",
};

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
    const date = parseDay(params.get("date"), "date", true);
    const viewRaw = params.get("view");
    if (viewRaw === null || !(VIEWS as readonly string[]).includes(viewRaw)) {
      throw new ApiError("BAD_REQUEST", 400, "view must be one of known-exploited, highest-forecast, new-critical, rising-forecast.");
    }
    const view = viewRaw as ViewName;
    const limit = parseLimit(params.get("limit"));
    const offset = parseCursor(params.get("cursor"));
    const nowIso = new Date().toISOString();
    const result = replayCheckpoint(db, date, { asOfDate: todayUtcDay(nowIso) });
    if (result.status === "unavailable") {
      const checkpoints = listCheckpoints(db);
      const retainedFrom = checkpoints.length === 0 ? null : (checkpoints[0]?.checkpointDate ?? null);
      const retainedTo =
        checkpoints.length === 0 ? null : (checkpoints[checkpoints.length - 1]?.checkpointDate ?? null);
      const reason = mapReplayReason(result.reason);
      throw new ApiError("REPLAY_UNAVAILABLE", 404, `Checkpoint ${date} is ${reason}. Current data is never substituted.`, {
        reason,
        retainedFrom,
        retainedTo,
      });
    }
    const ids = result.manifest.views[VIEW_KEYS[view]] ?? [];
    const { page, hasMore, nextCursor } = paginate(ids, offset, limit);
    const data = page.map((cveId) => {
      const snapshot = result.manifest.items[cveId];
      if (snapshot === undefined) return null;
      return toReplayItem(cveId, snapshot, result.manifest.sourcePins);
    });
    return okResponse(
      request,
      {
        checkpointDate: date,
        view,
        rankingPolicyVersion: result.manifest.policyVersion,
        data: data.filter((row) => row !== null),
        pagination: { limit, hasMore, nextCursor },
        coverage: coverageForSnapshots(ids, result.manifest.items, page.length),
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
