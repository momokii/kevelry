// The KEV rhythm's monthly series, densified.
//
// `kev_entries` only has rows for months where CISA added something, so a
// GROUP BY over it is sparse: a quiet month is absent rather than zero. The
// chart's window is "the last twelve UTC months", which means twelve calendar
// buckets — an absent month must be drawn as `0`, not skipped, or the window
// silently stretches past twelve months and the zero-bar rendering in
// `KevRhythm` is unreachable. Both loaders (cached snapshot and live fallback)
// build the bucket spine here and left-join the counts onto it, so they cannot
// disagree about the window.

import type { CveDatabase } from "./db";

/** One UTC calendar month and the KEV additions recorded in it. */
export interface KevMonthBucket {
  month: string;
  count: number;
}

const MONTH_KEY = /^(\d{4})-(\d{2})$/;

/**
 * `YYYY-MM` keys for the `count` UTC months ending at `anchorMonth` (inclusive),
 * oldest first. Empty when the anchor is not a valid `YYYY-MM` month key.
 */
export function trailingUtcMonths(anchorMonth: string, count: number): string[] {
  const match = MONTH_KEY.exec(anchorMonth);
  if (match === null || count <= 0) return [];
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) return [];
  const months: string[] = [];
  for (let offset = count - 1; offset >= 0; offset -= 1) {
    months.push(new Date(Date.UTC(year, month - 1 - offset, 1)).toISOString().slice(0, 7));
  }
  return months;
}

function anchorMonthOf(anchorIso: string): string | null {
  const key = anchorIso.slice(0, 7);
  if (MONTH_KEY.test(key)) return key;
  const parsed = new Date(anchorIso);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString().slice(0, 7);
}

/**
 * Left-join sparse month counts onto the trailing window. Months with no row
 * become `count: 0`; counts outside the window are dropped. The sum of the
 * result is exactly the additions recorded in those twelve UTC months — the
 * number the panel caption prints.
 */
export function densifyKevMonths(
  counts: ReadonlyArray<KevMonthBucket>,
  anchorIso: string,
  months = 12,
): KevMonthBucket[] {
  const anchorMonth = anchorMonthOf(anchorIso);
  if (anchorMonth === null) return [];
  const byMonth = new Map(counts.map((entry) => [entry.month, entry.count]));
  return trailingUtcMonths(anchorMonth, months).map((month) => ({
    month,
    count: byMonth.get(month) ?? 0,
  }));
}

/**
 * KEV additions per UTC month for the trailing window ending in the current
 * UTC month, dense and ascending. Reads every month with rows (a few hundred
 * buckets, not rows) and picks the window in `densifyKevMonths`.
 */
export function readKevByMonth(db: CveDatabase, anchorIso: string, months = 12): KevMonthBucket[] {
  const rows = db.handle
    .prepare(
      "SELECT substr(date_added, 1, 7) AS month, COUNT(*) AS n FROM kev_entries " +
        "WHERE date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]*' GROUP BY month",
    )
    .all() as Array<{ month: string; n: number }>;
  return densifyKevMonths(
    rows.map((row) => ({ month: row.month, count: row.n })),
    anchorIso,
    months,
  );
}
