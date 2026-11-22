// Cache-first ranked heads + the EPSS invariants the SQL fast paths rely on.
//
// The two forecast views used to re-sort ~410k eligible rows per request. They
// now read the head the aggregate refresh already stores (`topHighest`,
// `topRising`) whenever that snapshot is current, and fall back to the live
// getter otherwise. Three things must hold, and each is proven here against the
// real SQLite layer:
//
//   1. The cached head is byte-identical to the live getter's output — ids,
//      order, and every hydrated display field — for any limit inside the
//      stored head, including a limit shorter than the head.
//   2. A stale snapshot never answers: the reader returns null so the caller
//      runs the live query (the 3.2.0 freshness rule, not a new exception).
//   3. The SQL fast paths are only valid because of two data invariants: one
//      `model_version` per (score_date, cve_id), and stored EPSS decimals
//      short enough that `CAST(epss AS REAL)` orders them exactly like the
//      BigInt comparator. The duplicate case has a runtime fallback and is
//      tested here; the decimal-shape invariant is asserted on the corpus, so a
//      non-canonical value (one whose double collides with another stored
//      value) fails the suite instead of silently reordering a view.
//
// Fixtures use invented CVE-2099 ids and never touch the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { refreshAggregates, TOP_LIST_LIMIT } from "../src/lib/aggregates";
import {
  getAcceptedEpssDate,
  getHighestForecast,
  getRisingForecast,
  type PriorityItem,
} from "../src/lib/priority";
import { readHighestForecastHead, readRisingForecastHead } from "../src/lib/ranked-heads";
import { compareDecimalStrings, isValidEpss } from "../src/lib/ranking";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ranked-heads-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return db;
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

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const DAY = "2026-10-24";
const DAY_MINUS_7 = "2026-10-17";

function seedRecord(
  db: CveDatabase,
  cveId: string,
  published: string | null = "2026-10-20T00:00:00.000Z",
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(cveId, "5.1", "PUBLISHED", published, `Description for ${cveId}`, STAMP, STAMP);
  });
}

function seedKev(db: CveDatabase, cveId: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run(cveId, "2026-10-18", STAMP, STAMP);
  });
}

function seedCvss(db: CveDatabase, cveId: string, baseScore: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, 'CNA', '3.1', ?, 'CVSS:3.1/AV:N', 0)",
      )
      .run(cveId, baseScore);
  });
}

function seedEpss(
  db: CveDatabase,
  cveId: string,
  scoreDate: string,
  epss: string,
  model: string = MODEL,
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, '0.80000')",
      )
      .run(cveId, scoreDate, model, epss);
  });
}

/**
 * 130 published records: 120 scored on both dates (a deterministic staggered
 * gain so the rising list is long enough to need its head), 10 scored only
 * today, plus KEV membership and CVSS on a few so hydration has real fields to
 * reproduce.
 */
function seedCorpus(db: CveDatabase): void {
  for (let index = 0; index < 130; index += 1) {
    const cveId = `CVE-2099-${String(index + 1).padStart(4, "0")}`;
    seedRecord(db, cveId, index % 7 === 0 ? null : "2026-10-20T00:00:00.000Z");
  }
  for (let index = 0; index < 120; index += 1) {
    const cveId = `CVE-2099-${String(index + 1).padStart(4, "0")}`;
    // Ascending current scores with a staggered previous value: every one of
    // them gains probability, so the rising cohort (120) exceeds the head.
    const current = (0.1 + index / 200).toFixed(6);
    const previous = (0.1 + index / 200 - 0.01 - index / 20000).toFixed(6);
    seedEpss(db, cveId, DAY, current);
    seedEpss(db, cveId, DAY_MINUS_7, previous);
  }
  for (let index = 120; index < 130; index += 1) {
    const cveId = `CVE-2099-${String(index + 1).padStart(4, "0")}`;
    seedEpss(db, cveId, DAY, (0.9 + (index - 120) / 1000).toFixed(6));
  }
  for (const cveId of ["CVE-2099-0001", "CVE-2099-0010", "CVE-2099-0120"]) {
    seedKev(db, cveId);
    seedCvss(db, cveId, "9.8");
  }
}

function highestIds(rows: readonly PriorityItem[]): string[] {
  return rows.map((row) => row.id);
}

describe("cache-first ranked heads", () => {
  it("returns the live getter's exact rows and order for both forecast views", () => {
    const db = makeDb();
    seedCorpus(db);
    const snapshot = refreshAggregates(db, STAMP);
    expect(snapshot.topHighest).toHaveLength(TOP_LIST_LIMIT);
    expect(snapshot.topRising).toHaveLength(TOP_LIST_LIMIT);

    const highestHead = readHighestForecastHead(db, TOP_LIST_LIMIT);
    const highestLive = getHighestForecast(db, TOP_LIST_LIMIT);
    expect(highestHead).not.toBeNull();
    expect(highestHead).toEqual(highestLive);

    const risingHead = readRisingForecastHead(db, TOP_LIST_LIMIT);
    const risingLive = getRisingForecast(db, undefined, TOP_LIST_LIMIT);
    expect(risingHead).not.toBeNull();
    expect(risingHead).toEqual(risingLive);

    // A shorter display cap is a prefix of the same head, not a different list.
    expect(readHighestForecastHead(db, 5)).toEqual(highestLive.slice(0, 5));
    expect(readRisingForecastHead(db, 5)).toEqual(risingLive.slice(0, 5));
    expect(highestIds(readHighestForecastHead(db, 5) ?? [])).toEqual(
      highestIds(highestLive.slice(0, 5)),
    );
  });

  it("refuses a request wider than the stored head instead of truncating it", () => {
    const db = makeDb();
    seedCorpus(db);
    refreshAggregates(db, STAMP);
    expect(readHighestForecastHead(db, TOP_LIST_LIMIT + 1)).toBeNull();
    expect(readHighestForecastHead(db)).toBeNull();
    expect(readRisingForecastHead(db, TOP_LIST_LIMIT + 1)).toBeNull();
    expect(readRisingForecastHead(db)).toBeNull();
  });

  it("never answers from a snapshot that stopped describing the accepted data", () => {
    const db = makeDb();
    seedCorpus(db);
    refreshAggregates(db, STAMP);
    expect(readHighestForecastHead(db, 10)).not.toBeNull();

    // A newer accepted EPSS date is exactly the change 3.2.0 guards: the stored
    // head now describes yesterday's corpus under a fresh revision.
    seedEpss(db, "CVE-2099-0001", "2026-10-25", "0.5");
    expect(readHighestForecastHead(db, 10)).toBeNull();
    expect(readRisingForecastHead(db, 10)).toBeNull();
    // The live getters still answer, so a caller falls back instead of failing.
    expect(getHighestForecast(db, 10).length).toBeGreaterThan(0);

    // Once the refresh lands, the head is served again and matches the live list.
    refreshAggregates(db, "2026-10-25T00:00:00.000Z");
    const head = readHighestForecastHead(db, 10);
    expect(head).toEqual(getHighestForecast(db, 10));
  });
});

describe("EPSS model-version invariant behind the regroup removal", () => {
  it("falls back to the per-CVE regroup when one score date mixes model versions", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    // 0001 only exists under v1 on this date; 0002 carries v1 and v2.
    seedEpss(db, "CVE-2099-0001", DAY, "0.400000", "v2026.01.01");
    seedEpss(db, "CVE-2099-0002", DAY, "0.100000", "v2026.01.01");
    seedEpss(db, "CVE-2099-0002", DAY, "0.900000", "v2026.06.15");

    // MAX(model_version) per CVE: 0001 -> 0.4 (v1), 0002 -> 0.9 (v2).
    const head = getHighestForecast(db, 10);
    expect(highestIds(head)).toEqual(["CVE-2099-0002", "CVE-2099-0001"]);
    expect(head.map((row) => row.epss)).toEqual(["0.900000", "0.400000"]);
    // The mixed date must not be treated as single-version: the fast path would
    // have dropped 0001 entirely while the full-order path keeps it.
    expect(highestIds(getHighestForecast(db))).toEqual(highestIds(head));
  });

  it("keeps a single-version date on the fast path and the same rows as the full order", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedEpss(db, "CVE-2099-0001", DAY, "0.400000");
    seedEpss(db, "CVE-2099-0002", DAY, "0.900000");
    expect(highestIds(getHighestForecast(db, 1))).toEqual(
      highestIds(getHighestForecast(db)).slice(0, 1),
    );
    expect(highestIds(getHighestForecast(db, 10))).toEqual(highestIds(getHighestForecast(db)));
  });
});

describe("stored EPSS decimal invariant behind the SQL ordering", () => {
  it("keeps every stored value canonical: valid, and distinct as text and as a double", () => {
    const db = makeDb();
    seedCorpus(db);
    const rows = db.handle
      .prepare("SELECT DISTINCT epss FROM epss_daily ORDER BY epss")
      .all() as Array<{ epss: string }>;
    expect(rows.length).toBeGreaterThan(100);
    for (const row of rows) {
      // Plain decimal literal in [0, 1] — the predicate the SQL fast paths use.
      expect(isValidEpss(row.epss), `non-canonical stored EPSS ${JSON.stringify(row.epss)}`).toBe(
        true,
      );
    }
    const collisions = db.handle
      .prepare(
        "SELECT COUNT(*) AS n FROM (SELECT CAST(epss AS REAL) AS r FROM epss_daily " +
          "GROUP BY r HAVING COUNT(DISTINCT epss) > 1)",
      )
      .get() as { n: number };
    // A collision would let the numeric ORDER BY tie two textually different
    // scores and let the id tiebreak decide what the exact comparator decided.
    expect(collisions.n).toBe(0);
  });

  it("orders width-varying decimals exactly like the decimal comparator", () => {
    const db = makeDb();
    const values: Array<[string, string]> = [
      ["CVE-2099-0001", "0.9"],
      ["CVE-2099-0002", "0.8999999"],
      ["CVE-2099-0003", "0.1000000000000000"],
      ["CVE-2099-0004", "0.00043000000000000"],
      ["CVE-2099-0005", "1"],
      ["CVE-2099-0006", "0.0000001"],
    ];
    for (const [cveId, value] of values) {
      seedRecord(db, cveId);
      seedEpss(db, cveId, DAY, value);
    }
    const bounded = getHighestForecast(db, values.length).map((row) => row.id);
    const expected = [...values]
      .sort((a, b) => (compareDecimalStrings(b[1], a[1]) ?? 0) || (a[0] < b[0] ? -1 : 1))
      .map(([cveId]) => cveId);
    expect(bounded).toEqual(expected);
    expect(getAcceptedEpssDate(db)).toBe(DAY);
  });
});
