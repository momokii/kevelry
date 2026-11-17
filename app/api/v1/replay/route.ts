import { listCheckpoints, replayCheckpoint } from "../../../../src/lib/radar";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { ApiError } from "../_lib/errors";
import { cachedOkResponse } from "../_lib/http-cache";
import { paginate, parseCursor, parseDay, parseLimit } from "../_lib/params";
import { buildProvenance } from "../_lib/provenance";
import { todayUtcDay } from "../_lib/records";
import { coverageForSnapshots, mapReplayReason, toReplayItem } from "../_lib/radar-api";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

const VIEWS = ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"] as const;
type ViewName = (typeof VIEWS)[number];

const VIEW_KEYS: Record<
  ViewName,
  "knownExploited" | "highestForecast" | "newCritical" | "risingForecast"
> = {
  "known-exploited": "knownExploited",
  "highest-forecast": "highestForecast",
  "new-critical": "newCritical",
  "rising-forecast": "risingForecast",
};

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const params = new URL(request.url).searchParams;
  const date = parseDay(params.get("date"), "date", true);
  const viewRaw = params.get("view");
  if (viewRaw === null || !(VIEWS as readonly string[]).includes(viewRaw)) {
    throw new ApiError(
      "BAD_REQUEST",
      400,
      "view must be one of known-exploited, highest-forecast, new-critical, rising-forecast.",
    );
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
      checkpoints.length === 0
        ? null
        : (checkpoints[checkpoints.length - 1]?.checkpointDate ?? null);
    const reason = mapReplayReason(result.reason);
    throw new ApiError(
      "REPLAY_UNAVAILABLE",
      404,
      `Checkpoint ${date} is ${reason}. Current data is never substituted.`,
      {
        reason,
        retainedFrom,
        retainedTo,
      },
    );
  }
  const ids = result.manifest.views[VIEW_KEYS[view]] ?? [];
  const { page, hasMore, nextCursor } = paginate(ids, offset, limit);
  const data = page.map((cveId) => {
    const snapshot = result.manifest.items[cveId];
    if (snapshot === undefined) return null;
    return toReplayItem(cveId, snapshot, result.manifest.sourcePins);
  });
  return cachedOkResponse(
    request,
    db,
    {
      checkpointDate: date,
      view,
      rankingPolicyVersion: result.manifest.policyVersion,
      boundedTopN: result.manifest.boundedTopN,
      boundedNotice:
        `Checkpoint views retain the observed top-${result.manifest.boundedTopN} entries per list ` +
        `(boundedTopN); they are bounded observed lists, not complete enumerations.`,
      data: data.filter((row) => row !== null),
      pagination: { limit, hasMore, nextCursor },
      coverage: coverageForSnapshots(ids, result.manifest.items, page.length),
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
