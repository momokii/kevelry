import { getDefaultPriority } from "../../../../src/lib/priority";
import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { ApiError } from "../_lib/errors";
import { cachedOkResponse } from "../_lib/http-cache";
import {
  paginateCapped,
  parseCursor,
  parseDateBound,
  parseEpss,
  parseKev,
  parseLimit,
  parseSeverity,
} from "../_lib/params";
import { buildProvenance } from "../_lib/provenance";
import { coverageFor, filterPriorityItems, loadFullRecords, toCveItem } from "../_lib/records";
import { unfilteredCohortCoverage } from "../_lib/coverage";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const params = new URL(request.url).searchParams;
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
  return cachedOkResponse(
    request,
    db,
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
});
