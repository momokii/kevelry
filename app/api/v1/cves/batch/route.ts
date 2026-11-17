import { getAcceptedEpssDate } from "../../../../../src/lib/priority";
import { apiPreflight, withApiRoute } from "../../_lib/api-route";
import { ApiError } from "../../_lib/errors";
import { cachedOkResponse } from "../../_lib/http-cache";
import { CVE_ID_RE } from "../../_lib/params";
import { buildProvenance } from "../../_lib/provenance";
import { loadFullRecords, toCveItem } from "../../_lib/records";

export const dynamic = "force-dynamic";

/**
 * Unique-id cap for one bulk request. Bounded well under the URL budget
 * (4096 chars), the SQLite IN-clause batch (500), and a 50-item response.
 */
const MAX_BULK_IDS = 50;

/**
 * Params that carry meaning on other v1 routes. A caller mixing them into a
 * bulk request is asking for something this route does not do (filtering,
 * paging, search), so the request is rejected by name instead of silently
 * returning an unfiltered set. Any other unknown param is ignored.
 */
const CONFLICTING_PARAMS = [
  "cursor",
  "limit",
  "severity",
  "kev",
  "epss",
  "exploit",
  "publishedStart",
  "publishedEnd",
  "vendor",
  "q",
] as const;

/** Reject filter/pagination params that belong to the list and search routes. */
function rejectConflictingParams(params: URLSearchParams): void {
  for (const name of CONFLICTING_PARAMS) {
    if (params.has(name)) {
      throw new ApiError(
        "BAD_REQUEST",
        400,
        `${name} is not accepted on the bulk route; supply ids only.`,
      );
    }
  }
}

/**
 * Parse `ids` into the requested order: trimmed, empties dropped, duplicates
 * removed preserving first-seen order. Repeated `ids` is rejected because the
 * route takes exactly one canonical encoding (comma-separated).
 */
function parseBulkIds(params: URLSearchParams): string[] {
  if (params.getAll("ids").length > 1) {
    throw new ApiError("BAD_REQUEST", 400, "ids must be supplied once as a comma-separated list.");
  }
  const raw = params.get("ids");
  if (raw === null) {
    throw new ApiError("BAD_REQUEST", 400, "ids is required as a comma-separated list of CVE IDs.");
  }
  const elements = raw
    .split(",")
    .map((element) => element.trim())
    .filter((element) => element !== "");
  if (elements.length === 0) {
    throw new ApiError("BAD_REQUEST", 400, "ids must contain at least one CVE ID.");
  }
  for (const element of elements) {
    if (!CVE_ID_RE.test(element)) {
      throw new ApiError(
        "BAD_ID",
        400,
        "ids contains an element that is not shaped CVE-YYYY-NNNN+.",
      );
    }
  }
  const unique = [...new Set(elements)];
  if (unique.length > MAX_BULK_IDS) {
    throw new ApiError(
      "BAD_REQUEST",
      400,
      `ids accepts at most ${MAX_BULK_IDS} unique CVE IDs per request (received ${unique.length}).`,
    );
  }
  return unique;
}

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute(async ({ request, db, rate }) => {
  const params = new URL(request.url).searchParams;
  rejectConflictingParams(params);
  const requested = parseBulkIds(params);
  const records = loadFullRecords(db, requested);
  const byId = new Map(records.map((record) => [record.cveId, record]));
  const scoreDate = getAcceptedEpssDate(db);
  const data: Array<Record<string, unknown>> = [];
  const missingIds: string[] = [];
  for (const cveId of requested) {
    const record = byId.get(cveId);
    // Absent and not-publicly-visible ids are reported, never fabricated and
    // never a 404 for the whole request: one stale id must not sink 49 good ones.
    if (record === undefined || record.state !== "PUBLISHED") {
      missingIds.push(cveId);
      continue;
    }
    data.push(toCveItem(record, scoreDate, null));
  }
  const nowIso = new Date().toISOString();
  // The seed carries the aggregate revision (added by getCacheSeed) plus the
  // canonical sorted id set, so the same set in any order/deduping revalidates.
  const canonicalIds = [...requested].sort().join(",");
  return cachedOkResponse(
    request,
    db,
    {
      data,
      // Requested/returned/missing only. The list route's `coverage` key keeps
      // its single meaning (eligible cohort) and is deliberately not reused here.
      resolution: { requested: requested.length, returned: data.length, missingIds },
      provenance: buildProvenance(db, nowIso),
    },
    rate,
    { seedParts: [canonicalIds] },
  );
});
