import {
  buildProvenance,
  countRows,
  errorResponse,
  getDb,
  okResponse,
  reserveRateLimit,
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
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  }
}
