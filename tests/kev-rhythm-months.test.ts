// The KEV rhythm claims "twelve months", so it must hand the chart twelve
// calendar buckets — including months where CISA added nothing. The sparse
// source query (`GROUP BY month ... LIMIT 12`) only returns months that have
// rows, so a gap month silently vanished and the window could span more than
// twelve months. These tests pin the dense spine on the loader, in both the
// cached-snapshot path and the live fallback, and prove the caption total (the
// sum of the bars) is the real count inside the window.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { loadOverviewData } from "../src/components/overview/loadOverview";
import { getAggregates, refreshAggregates } from "../src/lib/aggregates";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const ANCHOR = "2026-10-24T00:00:00.000Z";
const STAMP = "2026-10-24T00:00:00.000Z";

/** The twelve UTC months ending in the anchor month, oldest first. */
const WINDOW = [
  "2025-11",
  "2025-12",
  "2026-01",
  "2026-02",
  "2026-03",
  "2026-04",
  "2026-05",
  "2026-06",
  "2026-07",
  "2026-08",
  "2026-09",
  "2026-10",
];

/**
 * Additions in window months 1, 3 and 12 (gaps at 2 and 4-11), plus one month
 * before the window and one after it. The out-of-window rows prove the spine
 * bounds the sum instead of telling the whole table's story.
 */
const ADDITIONS: Array<{ month: string; rows: number }> = [
  { month: "2025-10", rows: 4 },
  { month: "2025-11", rows: 2 },
  { month: "2026-01", rows: 5 },
  { month: "2026-10", rows: 3 },
  { month: "2026-11", rows: 1 },
];

const EXPECTED_COUNTS = [2, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 3];
/** Only the additions inside the trailing window: 2 + 5 + 3. */
const WINDOW_TOTAL = 10;

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): { db: CveDatabase; dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-kev-months-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return { db, dir };
}

function seedKevMonths(db: CveDatabase): void {
  let id = 0;
  db.runBoundedWrite(() => {
    for (const { month, rows } of ADDITIONS) {
      for (let index = 0; index < rows; index += 1) {
        id += 1;
        const cveId = `CVE-2099-${String(1000 + id)}`;
        db.handle
          .prepare(
            "INSERT INTO cve_records (cve_id, data_version, state, date_published, created_at, updated_at) " +
              "VALUES (?, '5.1', 'PUBLISHED', ?, ?, ?)",
          )
          .run(cveId, `${month}-05T00:00:00.000Z`, STAMP, STAMP);
        db.handle
          .prepare(
            "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) " +
              "VALUES (?, ?, ?, ?)",
          )
          .run(cveId, `${month}-0${(index % 9) + 1}T00:00:00.000Z`, STAMP, STAMP);
      }
    }
  });
}

/** Direct-SQL truth for the window, using the same date predicate as the loader. */
function windowCount(db: CveDatabase): number {
  return (
    db.handle
      .prepare(
        "SELECT COUNT(*) AS n FROM kev_entries WHERE date_added GLOB " +
          "'[0-9][0-9][0-9][0-9]-[0-9][0-9]*' AND substr(date_added, 1, 7) BETWEEN ? AND ?",
      )
      .get(WINDOW[0], WINDOW[WINDOW.length - 1]) as { n: number }
  ).n;
}

afterEach(() => {
  while (openDbs.length > 0) {
    try {
      (openDbs.pop() as CveDatabase).close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

describe("KEV rhythm months", () => {
  it("emits twelve dense UTC buckets with zeros for gap months", () => {
    const { db } = makeDb();
    seedKevMonths(db);
    const snapshot = refreshAggregates(db, ANCHOR);

    expect(snapshot.kevByMonth.map((entry) => entry.month)).toEqual(WINDOW);
    expect(snapshot.kevByMonth.map((entry) => entry.count)).toEqual(EXPECTED_COUNTS);
    // Gap months are real zero buckets, not omitted rows.
    expect(snapshot.kevByMonth.filter((entry) => entry.count === 0)).toHaveLength(9);

    // The caption total ("N catalog additions in twelve months") is the sum of
    // the twelve bars, and it equals the SQL count inside the window — not the
    // whole table, which also holds the out-of-window rows.
    const captionTotal = snapshot.kevByMonth.reduce((sum, entry) => sum + entry.count, 0);
    expect(captionTotal).toBe(WINDOW_TOTAL);
    expect(captionTotal).toBe(windowCount(db));
    const tableTotal = (
      db.handle.prepare("SELECT COUNT(*) AS n FROM kev_entries").get() as { n: number }
    ).n;
    expect(tableTotal).toBe(WINDOW_TOTAL + 5);
    expect(snapshot.totals.kev).toBe(tableTotal);
  });

  it("keeps the cached snapshot dense and window-bounded", () => {
    const { db } = makeDb();
    seedKevMonths(db);
    refreshAggregates(db, ANCHOR);

    const cached = getAggregates(db);
    expect(cached?.kevByMonth.map((entry) => entry.month)).toEqual(WINDOW);
    expect(cached?.kevByMonth.map((entry) => entry.count)).toEqual(EXPECTED_COUNTS);
  });

  it("densifies the live fallback series identically", () => {
    const { db, dir } = makeDb();
    seedKevMonths(db);
    // No aggregate cache written: this forces loadOverviewData's live path.
    db.close();
    openDbs.pop();

    const data = loadOverviewData(dir, ANCHOR);
    expect(data?.kevByMonth.map((entry) => entry.month)).toEqual(WINDOW);
    expect(data?.kevByMonth.map((entry) => entry.count)).toEqual(EXPECTED_COUNTS);
    expect(data?.kevByMonth.reduce((sum, entry) => sum + entry.count, 0)).toBe(WINDOW_TOTAL);
  });
});
