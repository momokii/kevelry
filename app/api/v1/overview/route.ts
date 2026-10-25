import { getAggregates, monthCountsFromDays } from "../../../../src/lib/aggregates";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  cachedOkResponse,
  countRows,
  errorResponse,
  getDb,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
  unfilteredCohortCoverage,
} from "../_lib/shared";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return preflightResponse(request);
}

function monthKey(year: number, month: number): string {
  return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}`;
}

function trailingMonths(anchor: string, count: number): string[] {
  const [yearText, monthText] = anchor.split("-");
  let year = Number(yearText);
  let month = Number(monthText);
  const keys: string[] = [];
  for (let index = 0; index < count; index += 1) {
    keys.unshift(monthKey(year, month));
    month -= 1;
    if (month < 1) {
      month = 12;
      year -= 1;
    }
  }
  return keys;
}

function trailingDays(anchor: string, count: number): string[] {
  const base = Date.parse(`${anchor}T00:00:00.000Z`);
  const keys: string[] = [];
  for (let index = count - 1; index >= 0; index -= 1) {
    keys.push(new Date(base - index * 86_400_000).toISOString().slice(0, 10));
  }
  return keys;
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
    const bucketRaw = params.get("bucket");
    const bucket = bucketRaw === null || bucketRaw === "" ? "month" : bucketRaw;
    if (bucket !== "day" && bucket !== "month") {
      throw new ApiError("BAD_FILTER", 400, "bucket must be day or month.");
    }
    const monthsRaw = params.get("months");
    let months = 24;
    if (monthsRaw !== null && monthsRaw !== "") {
      if (!/^[0-9]+$/.test(monthsRaw)) {
        throw new ApiError("BAD_FILTER", 400, "months must be an integer between 1 and 120.");
      }
      months = Number(monthsRaw);
      if (!Number.isSafeInteger(months) || months < 1 || months > 120) {
        throw new ApiError("BAD_FILTER", 400, "months must be an integer between 1 and 120.");
      }
    }
    const nowIso = new Date().toISOString();
    // Hot path reads the precomputed aggregate cache (one point lookup) instead
    // of GROUP BY / COUNT scans; identical shapes, live fallback when empty.
    const cached = getAggregates(db);
    const prefixLen = bucket === "month" ? 7 : 10;
    let counts: Map<string, number>;
    let unknownDateCount: number;
    let tombstones: number;
    if (cached !== null) {
      const source = bucket === "month" ? monthCountsFromDays(cached.dayCounts) : cached.dayCounts;
      counts = new Map<string, number>();
      for (const [key, value] of Object.entries(source)) {
        if (key.length >= prefixLen) counts.set(key.slice(0, prefixLen), value);
      }
      unknownDateCount = cached.unknownDateCount;
      tombstones = cached.tombstones;
    } else {
      const dayRows = db.handle
        .prepare(
          "SELECT substr(date_published, 1, ?) AS day, COUNT(*) AS n FROM cve_records " +
            "WHERE state = ? AND date_published IS NOT NULL GROUP BY day",
        )
        .all(prefixLen, "PUBLISHED") as Array<{ day: string; n: number }>;
      counts = new Map<string, number>();
      for (const row of dayRows) counts.set(row.day, row.n);
      const totals = db.handle
        .prepare(
          "SELECT COUNT(*) AS n, SUM(CASE WHEN date_published IS NULL THEN 1 ELSE 0 END) AS u " +
            "FROM cve_records WHERE state = ?",
        )
        .get("PUBLISHED") as { n: number; u: number };
      unknownDateCount = totals.u ?? 0;
      tombstones = countRows(db, "SELECT COUNT(*) AS n FROM cve_tombstones");
    }
    const anchor = bucket === "month" ? nowIso.slice(0, 7) : nowIso.slice(0, 10);
    const keys = bucket === "month" ? trailingMonths(anchor, months) : trailingDays(anchor, months);
    const buckets = keys.map((bucketStart) => ({
      bucketStart,
      count: counts.get(bucketStart) ?? 0,
    }));
    const correctionNotes =
      tombstones > 0
        ? [
            `${tombstones} removed or rejected record(s) retained as tombstones; history reflects the accepted corpus.`,
          ]
        : [];
    const coverage =
      cached === null
        ? unfilteredCohortCoverage(db, buckets.length)
        : {
            eligibleCohort: cached.publishedTotal,
            returned: buckets.length,
            unscored: cached.totals.unscored,
            unknownEpss: cached.totals.unknownEpss,
            unknownDate: cached.unknownDateCount,
          };
    return cachedOkResponse(
      request,
      db,
      {
        bucket,
        dateBasis: "publishedAt-utc",
        buckets,
        unknownDateCount,
        correctionNotes,
        coverage,
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
