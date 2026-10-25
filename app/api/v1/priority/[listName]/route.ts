import {
  getAcceptedEpssDate,
  getDefaultPriority,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../../../../../src/lib/priority";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  coverageFor,
  encodeCursor,
  errorResponse,
  getDb,
  loadFullRecords,
  cachedOkResponse,
  parseCursor,
  parseLimit,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  paginateCapped,
  toCveItem,
} from "../../_lib/shared";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return preflightResponse(request);
}

const LISTS = ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"] as const;
type ListName = (typeof LISTS)[number];

const ORDERINGS: Record<ListName, string[]> = {
  "known-exploited": ["kev-dateAdded-desc", "cveId-asc"],
  "highest-forecast": ["epss-raw-desc", "published-desc", "cveId-asc"],
  "new-critical": ["published-desc", "cveId-asc"],
  "rising-forecast": ["delta-pp-desc", "epss-raw-desc", "cveId-asc"],
};

export async function GET(
  request: Request,
  context: { params: Promise<{ listName: string }> },
): Promise<Response> {
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
    const { listName } = await context.params;
    if (!(LISTS as readonly string[]).includes(listName)) {
      const safe = /^[a-z-]{1,64}$/.test(listName) ? listName : "?";
      throw new ApiError("LIST_NOT_FOUND", 404, `Unknown priority list "${safe}".`);
    }
    const list = listName as ListName;
    const params = new URL(request.url).searchParams;
    const limit = parseLimit(params.get("limit"));
    const offset = parseCursor(params.get("cursor"));
    const nowIso = new Date().toISOString();
    const scoreDate = getAcceptedEpssDate(db);
    // Bounded fetch: one extra row probes whether a next page exists, so the
    // getters never materialize the full corpus. Coverage is computed over
    // the bounded fetch, not a full scan (same keys, bounded cohort).
    const cap = offset + limit + 1;

    if (list === "rising-forecast") {
      const view = getRisingForecast(db, undefined, cap);
      const { page, hasMore, nextCursor } = paginateCapped(view, offset, limit);
      const records = loadFullRecords(
        db,
        page.map((row) => row.item.id),
      );
      const byId = new Map(records.map((record) => [record.cveId, record]));
      const data = page.map((row) => {
        const record = byId.get(row.item.id);
        if (record === undefined) return null;
        return toCveItem(record, scoreDate, null);
      });
      return cachedOkResponse(
        request,
        db,
        {
          list,
          ordering: ORDERINGS[list],
          data: data.filter((row) => row !== null),
          deltaPp: page.map((row) => Number(row.deltaPp)),
          pagination: { limit, hasMore, nextCursor },
          coverage: coverageFor(
            view.map((row) => row.item),
            page.length,
          ),
          provenance: buildProvenance(db, nowIso),
        },
        rate,
      );
    }

    const items =
      list === "known-exploited"
        ? getKnownExploited(db, cap)
        : list === "highest-forecast"
          ? getHighestForecast(db, cap)
          : list === "new-critical"
            ? getNewCritical(db, nowIso, cap)
            : getDefaultPriority(db, cap);
    const { page, hasMore, nextCursor } = paginateCapped(items, offset, limit);
    const records = loadFullRecords(
      db,
      page.map((item) => item.id),
    );
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const data = page.map((item) => {
      const record = byId.get(item.id);
      if (record === undefined) return null;
      return toCveItem(record, scoreDate, null);
    });
    return cachedOkResponse(
      request,
      db,
      {
        list,
        ordering: ORDERINGS[list],
        data: data.filter((row) => row !== null),
        deltaPp: null,
        pagination: { limit, hasMore, nextCursor },
        coverage: coverageFor(items, page.length),
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
