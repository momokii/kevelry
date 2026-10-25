import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  countRows,
  errorResponse,
  getDb,
  okResponse,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  REUSE_NOTICES,
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
    const nowIso = new Date().toISOString();
    // Bounded cohorts: the published count is exactly getDefaultPriority(db)
    // .length (every default-priority item is a PUBLISHED record and vice
    // versa), but materializing and sorting the full 395k corpus costs ~20s.
    // Indexed COUNT queries return the same numbers in ~1.5s warm.
    const published = countRows(db, "SELECT COUNT(*) AS n FROM cve_records WHERE state = ?", [
      "PUBLISHED",
    ]);
    const acceptedDate = getAcceptedEpssDate(db);
    const kevListed = countRows(db, "SELECT COUNT(*) AS n FROM kev_entries");
    const epssScored =
      acceptedDate === null
        ? 0
        : countRows(db, "SELECT COUNT(DISTINCT cve_id) AS n FROM epss_daily WHERE score_date = ?", [acceptedDate]);
    const unmatchedKev = countRows(
      db,
      "SELECT COUNT(*) AS n FROM kev_entries k LEFT JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = ? WHERE r.cve_id IS NULL",
      ["PUBLISHED"],
    );
    const unmatchedEpss =
      acceptedDate === null
        ? 0
        : countRows(
            db,
            "SELECT COUNT(DISTINCT e.cve_id) AS n FROM epss_daily e LEFT JOIN cve_records r ON r.cve_id = e.cve_id AND r.state = ? WHERE e.score_date = ? AND r.cve_id IS NULL",
            ["PUBLISHED", acceptedDate],
          );
    const provenance = buildProvenance(db, nowIso);
    return okResponse(
      request,
      {
        rankingPolicyVersion: provenance.rankingPolicyVersion,
        generatedAt: provenance.generatedAt,
        sources: provenance.sources,
        cohorts: { published, kevListed, epssScored },
        joinCoverage: { unmatchedKev, unmatchedEpss },
        notices: [...REUSE_NOTICES],
        provenance,
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
