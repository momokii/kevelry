import { getDefaultPriority } from "../../../../src/lib/priority";
import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  coverageFor,
  errorResponse,
  filterPriorityItems,
  getDb,
  loadFullRecords,
  okResponse,
  paginateCapped,
  parseCursor,
  parseDateBound,
  parseEpss,
  parseKev,
  parseLimit,
  parseSeverity,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  unfilteredCohortCoverage,
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
    // Bounded fetch (plus a one-row probe for hasMore): the default-priority
    // getter orders in SQL and hydrates only the fetched rows, so a list
    // never materializes the full corpus. With filters the bound applies
    // before filtering; filtered coverage is then computed over the bounded
    // fetch (same keys, bounded cohort) instead of a full 395k scan.
    const cap = offset + limit + 1;
    const ordered = getDefaultPriority(db, cap);
    const filtered = filterPriorityItems(ordered, { severity, kev, epss, start, end });
    const { page, hasMore, nextCursor } = paginateCapped(filtered, offset, limit);
    const hasFilters =
      severity !== null || kev !== "any" || epss !== "any" || start !== null || end !== null;
    const records = loadFullRecords(
      db,
      page.map((item) => item.id),
    );
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const scoreDate = getAcceptedEpssDate(db);
    const data = page.map((item) => {
      const record = byId.get(item.id);
      if (record === undefined) return null;
      return toCveItem(record, scoreDate, null);
    });
    const nowIso = new Date().toISOString();
    return okResponse(
      request,
      {
        data: data.filter((row) => row !== null),
        pagination: { limit, hasMore, nextCursor },
        coverage: hasFilters
          ? coverageFor(filtered, page.length)
          : unfilteredCohortCoverage(db, page.length),
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
