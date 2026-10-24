import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import { searchCves } from "../../../../src/lib/search";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  errorResponse,
  getDb,
  loadFullRecords,
  okResponse,
  paginate,
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
    return errorResponse(request, "RATE_LIMITED", "Server is busy. Retry after 60 seconds.", db, undefined, rate);
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
      throw new ApiError("BAD_DATE_RANGE", 400, "publishedStart must be earlier than publishedEnd.");
    }
    const matched: string[] = [];
    let total = 0;
    let unknownSeverity = 0;
    let epssKnown = 0;
    let unknownDate = 0;
    let serviceCursor: string | null = null;
    const startedAtMs = Date.now();
    for (;;) {
      if (searchBudgetExceeded(startedAtMs)) {
        throw new ApiError("INTERNAL", 500, "Unexpected failure handling the request.");
      }
      const result = searchCves(db, {
        q,
        dateStart: start ?? undefined,
        dateEnd: end ?? undefined,
        severity: severity === null ? undefined : [severity],
        kev: kev === "listed" ? "only" : kev === "not-listed" ? "excluded" : "all",
        epss: epss === "scored" ? "present" : epss === "unscored" ? "absent" : "all",
        limit: 100,
        cursor: serviceCursor,
      });
      total = result.total;
      unknownSeverity = result.coverage.unknownSeverity;
      epssKnown = result.coverage.epssKnown;
      unknownDate = result.coverage.unknownDate;
      for (const item of result.items) matched.push(item.cveId);
      if (result.nextCursor === null) break;
      serviceCursor = result.nextCursor;
    }
    const { page, hasMore, nextCursor } = paginate(matched, offset, limit);
    const records = loadFullRecords(db, page);
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const scoreDate = getAcceptedEpssDate(db);
    const data = page.map((cveId) => {
      const record = byId.get(cveId);
      if (record === undefined) return null;
      return toCveItem(record, scoreDate, null);
    });
    const nowIso = new Date().toISOString();
    return okResponse(
      request,
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
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  } finally {
    releaseConcurrencySlot();
  }
}
