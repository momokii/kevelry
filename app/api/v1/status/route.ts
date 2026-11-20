import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import { readCurrentAggregates } from "../../../../src/lib/aggregates";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { cachedOkResponse } from "../_lib/http-cache";
import { buildProvenance } from "../_lib/provenance";
import { REUSE_NOTICES } from "../_lib/notices";
import { countRows } from "../_lib/coverage";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const nowIso = new Date().toISOString();
  // Cohort counts come from the aggregate cache (one point lookup) while it
  // still describes the accepted inputs; source freshness and the live
  // fallback both read the tables, so a stale snapshot is never paired with a
  // fresh revision.
  const { cached } = readCurrentAggregates(db);
  let published: number;
  let kevListed: number;
  let epssScored: number;
  let unmatchedKev: number;
  let unmatchedEpss: number;
  if (cached !== null) {
    published = cached.totals.published;
    kevListed = cached.totals.kev;
    epssScored = cached.totals.epssScored;
    unmatchedKev = cached.totals.unmatchedKev;
    unmatchedEpss = cached.totals.unmatchedEpss;
  } else {
    published = countRows(db, "SELECT COUNT(*) AS n FROM cve_records WHERE state = ?", [
      "PUBLISHED",
    ]);
    const acceptedDate = getAcceptedEpssDate(db);
    kevListed = countRows(db, "SELECT COUNT(*) AS n FROM kev_entries");
    epssScored =
      acceptedDate === null
        ? 0
        : countRows(db, "SELECT COUNT(DISTINCT cve_id) AS n FROM epss_daily WHERE score_date = ?", [
            acceptedDate,
          ]);
    unmatchedKev = countRows(
      db,
      "SELECT COUNT(*) AS n FROM kev_entries k LEFT JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = ? WHERE r.cve_id IS NULL",
      ["PUBLISHED"],
    );
    unmatchedEpss =
      acceptedDate === null
        ? 0
        : countRows(
            db,
            "SELECT COUNT(DISTINCT e.cve_id) AS n FROM epss_daily e LEFT JOIN cve_records r ON r.cve_id = e.cve_id AND r.state = ? WHERE e.score_date = ? AND r.cve_id IS NULL",
            ["PUBLISHED", acceptedDate],
          );
  }
  const provenance = buildProvenance(db, nowIso);
  return cachedOkResponse(
    request,
    db,
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
});
