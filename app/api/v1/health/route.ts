import { readCurrentAggregates } from "../../../../src/lib/aggregates";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { cachedOkResponse } from "../_lib/http-cache";
import { buildProvenance } from "../_lib/provenance";
import { countRows } from "../_lib/coverage";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  // Readiness counts come from the aggregate cache only while it is current;
  // three cheap counts keep a stale snapshot from deciding the status.
  const { cached } = readCurrentAggregates(db);
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
  // `warming` is about the read model, not about rows existing: the corpus is
  // accepted, the precomputed snapshot is not current yet, so reads are taking
  // the slower live path (never stale numbers — that is the 3.2.0 freshness
  // rule). The container entrypoint warms the cache before the web server
  // binds, and the worker re-warms after every accepted cycle, so a served
  // `warming` is the few seconds of that rebuild, not a broken instance.
  const status =
    published > 0 && kev > 0 && epss > 0 ? (cached === null ? "warming" : "ok") : "initializing";
  return cachedOkResponse(
    request,
    db,
    {
      status,
      version: "v1",
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
