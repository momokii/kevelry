import { getAggregates } from "../../../../src/lib/aggregates";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { cachedOkResponse } from "../_lib/http-cache";
import { buildProvenance } from "../_lib/provenance";
import { countRows } from "../_lib/coverage";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  // Readiness counts come from the aggregate cache; freshness stays live.
  const cached = getAggregates(db);
  const published =
    cached === null
      ? countRows(db, "SELECT COUNT(*) AS n FROM cve_records WHERE state = ?", ["PUBLISHED"])
      : cached.totals.published;
  const kev =
    cached === null ? countRows(db, "SELECT COUNT(*) AS n FROM kev_entries") : cached.totals.kev;
  const epss =
    cached === null
      ? countRows(db, "SELECT COUNT(*) AS n FROM epss_daily")
      : cached.totals.epssRows;
  const nowIso = new Date().toISOString();
  return cachedOkResponse(
    request,
    db,
    {
      status: published > 0 && kev > 0 && epss > 0 ? "ok" : "initializing",
      version: "v1",
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
