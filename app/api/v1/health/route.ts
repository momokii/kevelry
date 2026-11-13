import { getAggregates } from "../../../../src/lib/aggregates";
import { getDb } from "../_lib/db-handle";
import { acquireConcurrencySlot, assertRequestBounds, preflightResponse, releaseConcurrencySlot } from "../_lib/guardrails";
import { ApiError } from "../_lib/errors";
import { errorResponse, reserveRateLimit } from "../_lib/responses";
import { cachedOkResponse } from "../_lib/http-cache";
import { buildProvenance } from "../_lib/provenance";
import { countRows } from "../_lib/coverage";

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
    // Readiness counts come from the aggregate cache; freshness stays live.
    const cached = getAggregates(db);
    const published =
      cached === null
        ? countRows(db, "SELECT COUNT(*) AS n FROM cve_records WHERE state = ?", ["PUBLISHED"])
        : cached.totals.published;
    const kev =
      cached === null
        ? countRows(db, "SELECT COUNT(*) AS n FROM kev_entries")
        : cached.totals.kev;
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
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  } finally {
    releaseConcurrencySlot();
  }
}
