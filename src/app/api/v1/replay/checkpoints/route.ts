import { isCheckpointExpired, listCheckpoints } from "../../../../../lib/radar";
import {
  acquireConcurrencySlot,
  ApiError,
  buildProvenance,
  errorResponse,
  getDb,
  okResponse,
  paginate,
  parseCursor,
  parseLimit,
  assertRequestBounds,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  todayUtcDay,
} from "../../_lib/shared";

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
      expired: isCheckpointExpired(manifest.checkpointDate, today),
    }));
    const newestFirst = [...manifests].reverse();
    const { page, hasMore, nextCursor } = paginate(newestFirst, offset, limit);
    return okResponse(
      request,
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
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  } finally {
    releaseConcurrencySlot();
  }
}
