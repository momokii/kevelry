import { getAcceptedEpssDate, getDefaultPriority } from "../../../../lib/priority";
import {
  buildProvenance,
  countRows,
  errorResponse,
  getDb,
  okResponse,
  reserveRateLimit,
  REUSE_NOTICES,
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
    const nowIso = new Date().toISOString();
    const items = getDefaultPriority(db);
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
        cohorts: { published: items.length, kevListed, epssScored },
        joinCoverage: { unmatchedKev, unmatchedEpss },
        notices: [...REUSE_NOTICES],
        provenance,
      },
      rate,
    );
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  }
}
