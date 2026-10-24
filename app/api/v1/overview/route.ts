import { getDefaultPriority } from "../../../../src/lib/priority";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  countRows,
  coverageFor,
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
    return errorResponse(request, "RATE_LIMITED", "Server is busy. Retry after 60 seconds.", db, undefined, rate);
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
    const items = getDefaultPriority(db);
    const counts = new Map<string, number>();
    let unknownDateCount = 0;
    for (const item of items) {
      if (item.publishedAt === null) {
        unknownDateCount += 1;
        continue;
      }
      const key = bucket === "month" ? item.publishedAt.slice(0, 7) : item.publishedAt.slice(0, 10);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const anchor = bucket === "month" ? nowIso.slice(0, 7) : nowIso.slice(0, 10);
    const keys = bucket === "month" ? trailingMonths(anchor, months) : trailingDays(anchor, months);
    const buckets = keys.map((bucketStart) => ({ bucketStart, count: counts.get(bucketStart) ?? 0 }));
    const tombstones = countRows(db, "SELECT COUNT(*) AS n FROM cve_tombstones");
    const correctionNotes =
      tombstones > 0
        ? [
            `${tombstones} removed or rejected record(s) retained as tombstones; history reflects the accepted corpus.`,
          ]
        : [];
    return okResponse(
      request,
      {
        bucket,
        dateBasis: "publishedAt-utc",
        buckets,
        unknownDateCount,
        correctionNotes,
        coverage: coverageFor(items, buckets.length),
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
