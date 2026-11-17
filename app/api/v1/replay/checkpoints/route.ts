import { isCheckpointExpired, listCheckpoints } from "../../../../../src/lib/radar";
import { apiPreflight, withApiRoute } from "../../_lib/api-route";
import { cachedOkResponse } from "../../_lib/http-cache";
import { paginate, parseCursor, parseLimit } from "../../_lib/params";
import { buildProvenance } from "../../_lib/provenance";
import { todayUtcDay } from "../../_lib/records";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const params = new URL(request.url).searchParams;
  const limit = parseLimit(params.get("limit"));
  const offset = parseCursor(params.get("cursor"));
  const nowIso = new Date().toISOString();
  const today = todayUtcDay(nowIso);
  const manifests = listCheckpoints(db).map((manifest) => ({
    checkpointDate: manifest.checkpointDate,
    rankingPolicyVersion: manifest.policyVersion,
    cveRevision: manifest.sourcePins.cveRevision,
    kevCatalogVersion: manifest.sourcePins.kevCatalogDate,
    epssScoreDate: manifest.sourcePins.epssScoreDate,
    epssModelVersion: manifest.sourcePins.epssModelVersion,
    eligibleCohort: manifest.cohortCount,
    boundedTopN: manifest.boundedTopN,
    expired: isCheckpointExpired(manifest.checkpointDate, today),
  }));
  const newestFirst = [...manifests].reverse();
  const { page, hasMore, nextCursor } = paginate(newestFirst, offset, limit);
  return cachedOkResponse(
    request,
    db,
    {
      retainedFrom: manifests.length === 0 ? null : (manifests[0]?.checkpointDate ?? null),
      retainedTo:
        manifests.length === 0 ? null : (manifests[manifests.length - 1]?.checkpointDate ?? null),
      data: page,
      pagination: { limit, hasMore, nextCursor },
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
