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
    const published = countRows(db, "SELECT COUNT(*) AS n FROM cve_records WHERE state = ?", ["PUBLISHED"]);
    const kev = countRows(db, "SELECT COUNT(*) AS n FROM kev_entries");
    const epss = countRows(db, "SELECT COUNT(*) AS n FROM epss_daily");
    const nowIso = new Date().toISOString();
    return okResponse(
      request,
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
