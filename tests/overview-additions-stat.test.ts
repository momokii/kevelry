// The KEV stat on the overview used to report the newest month *with
// additions* under the label "in the latest month". Early in a month the dense
// spine's last bucket is `0`, so the number and the label described two
// different months. These tests pin the honest version: the month travels with
// the count, "latest" only appears when the month really is the newest bucket,
// and an empty window says so instead of printing `+0`.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { additionsStatNote, latestMonthWithAdditions } from "../src/components/overview/chartData";
import { loadOverviewData } from "../src/components/overview/loadOverview";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const ANCHOR = "2026-10-24T00:00:00.000Z";
const STAMP = "2026-10-24T00:00:00.000Z";

/** Twelve dense buckets ending in the anchor month, as the loader emits them. */
const WINDOW_MONTHS = [
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

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): { db: CveDatabase; dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-additions-stat-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return { db, dir };
}

/** Two additions in August 2026 and nothing in September or October: the
 *  newest bucket is legitimately empty, exactly like the first days of a month. */
function seedTrailingEmptyMonth(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    for (let index = 0; index < 2; index += 1) {
      const cveId = `CVE-2099-${2000 + index}`;
      db.handle
        .prepare(
          "INSERT INTO cve_records (cve_id, data_version, state, date_published, created_at, updated_at) " +
            "VALUES (?, '5.1', 'PUBLISHED', ?, ?, ?)",
        )
        .run(cveId, `2026-08-0${index + 1}T00:00:00.000Z`, STAMP, STAMP);
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) " +
            "VALUES (?, ?, ?, ?)",
        )
        .run(cveId, `2026-08-0${index + 1}T00:00:00.000Z`, STAMP, STAMP);
    }
  });
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

function buckets(counts: number[]): Array<{ month: string; count: number }> {
  return WINDOW_MONTHS.map((month, index) => ({ month, count: counts[index] ?? 0 }));
}

describe("latestMonthWithAdditions", () => {
  it("names the newest non-empty month and flags that it is not the newest bucket", () => {
    const counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0];
    const stat = latestMonthWithAdditions(buckets(counts));
    expect(stat).toEqual({ month: "2026-08", count: 2, isLatestBucket: false });
  });

  it("marks the newest bucket as latest when it holds the additions", () => {
    const counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 3];
    expect(latestMonthWithAdditions(buckets(counts))).toEqual({
      month: "2026-10",
      count: 3,
      isLatestBucket: true,
    });
  });

  it("returns null for an empty window rather than a zero with no month", () => {
    expect(latestMonthWithAdditions(buckets([]))).toBeNull();
    expect(latestMonthWithAdditions([])).toBeNull();
  });
});

describe("additionsStatNote", () => {
  it("never calls an older month the latest", () => {
    const note = additionsStatNote(
      latestMonthWithAdditions(buckets([0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0])),
    );
    expect(note).toBe("+12 additions in August 2026 (last month with additions)");
    expect(note).not.toContain("latest month");
  });

  it("names the month without a qualifier when it is the newest bucket", () => {
    const note = additionsStatNote(
      latestMonthWithAdditions(buckets([0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 7])),
    );
    expect(note).toBe("+7 additions in October 2026");
    expect(note).not.toContain("latest month");
  });

  it("states an empty window in words", () => {
    expect(additionsStatNote(null)).toBe("no additions in this window");
  });
});

describe("overview additions stat from the loader", () => {
  it("reports the month it measures when the newest month is empty", () => {
    const { db, dir } = makeDb();
    seedTrailingEmptyMonth(db);
    // No aggregate cache: this is the live path, which still densifies the spine.
    const data = loadOverviewData(dir, ANCHOR);
    expect(data).not.toBeNull();
    const byMonth = data?.kevByMonth ?? [];
    expect(byMonth.map((entry) => entry.month)).toEqual(WINDOW_MONTHS);
    // The calendar's last bucket really is empty, so a "latest month" label
    // would have been a lie about the count that followed it.
    expect(byMonth.at(-1)).toEqual({ month: "2026-10", count: 0 });
    expect(byMonth.at(-2)).toEqual({ month: "2026-09", count: 0 });

    const stat = latestMonthWithAdditions(byMonth);
    expect(stat).toEqual({ month: "2026-08", count: 2, isLatestBucket: false });
    expect(additionsStatNote(stat)).toBe("+2 additions in August 2026 (last month with additions)");
  });
});
