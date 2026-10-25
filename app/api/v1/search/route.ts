import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import { searchCves } from "../../../../src/lib/search";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  encodeCursor,
  errorResponse,
  getDb,
  loadFullRecords,
  cachedOkResponse,
  parseCursor,
  parseDateBound,
  parseEpss,
  parseKev,
  parseLimit,
  parseQuery,
  parseSeverity,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  searchBudgetExceeded,
  toCveItem,
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
    return errorResponse(
      request,
      "RATE_LIMITED",
      "Server is busy. Retry after 60 seconds.",
      db,
      undefined,
      rate,
    );
  }
  try {
    assertRequestBounds(request);
    const params = new URL(request.url).searchParams;
    const q = parseQuery(params.get("q"));
    const limit = parseLimit(params.get("limit"));
    const offset = parseCursor(params.get("cursor"));
    const severity = parseSeverity(params.get("severity"));
    const kev = parseKev(params.get("kev"));
    const epss = parseEpss(params.get("epss"));
    const start = parseDateBound(params.get("publishedStart"), "publishedStart");
    const end = parseDateBound(params.get("publishedEnd"), "publishedEnd");
    if (start !== null && end !== null && start >= end) {
      throw new ApiError(
        "BAD_DATE_RANGE",
        400,
        "publishedStart must be earlier than publishedEnd.",
      );
    }
    // Single bounded service call: searchCves paginates in the service and
    // returns the total/coverage for the whole match set, so the route must
    // not fan out over every page. The old fan-out re-ran the full FTS scan
    // once per 100 rows (hundreds of full scans for common terms) and tripped
    // the 3s budget into a 500; it also amplified the unbounded IN clause
    // inside the service. One call keeps warm responses under 5s.
    // The wall-clock budget is still honored up front: an exhausted budget
    // (e.g. forced to 0) refuses the search with a generic 500.
    if (searchBudgetExceeded(Date.now())) {
      throw new ApiError("INTERNAL", 500, "Unexpected failure handling the request.");
    }
    const result = searchCves(db, {
      q,
      dateStart: start ?? undefined,
      dateEnd: end ?? undefined,
      severity: severity === null ? undefined : [severity],
      kev: kev === "listed" ? "only" : kev === "not-listed" ? "excluded" : "all",
      epss: epss === "scored" ? "present" : epss === "unscored" ? "absent" : "all",
      limit,
      cursor: offset === 0 ? null : encodeCursor(offset),
    });
    const total = result.total;
    const unknownSeverity = result.coverage.unknownSeverity;
    const epssKnown = result.coverage.epssKnown;
    const unknownDate = result.coverage.unknownDate;
    const page = result.items.map((item) => item.cveId);
    const hasMore = result.nextCursor !== null;
    const nextCursor = result.nextCursor;
    const records = loadFullRecords(db, page);
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const scoreDate = getAcceptedEpssDate(db);
    const data = page.map((cveId) => {
      const record = byId.get(cveId);
      if (record === undefined) return null;
      return toCveItem(record, scoreDate, null);
    });
    const nowIso = new Date().toISOString();
    return cachedOkResponse(
      request,
      db,
      {
        q,
        data: data.filter((row) => row !== null),
        pagination: { limit, hasMore, nextCursor },
        coverage: {
          eligibleCohort: total,
          returned: page.length,
          unscored: unknownSeverity,
          unknownEpss: total - epssKnown,
          unknownDate,
        },
        provenance: buildProvenance(db, nowIso),
      },
      rate,
    );
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(
      request,
      "INTERNAL",
      "Unexpected failure handling the request.",
      db,
      undefined,
      rate,
    );
  } finally {
    releaseConcurrencySlot();
  }
}
