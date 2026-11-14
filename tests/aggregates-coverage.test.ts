// v3 E1 (step 2): the unscored cohort split — `secondaryOnly` + `noMetric`.
//
// Proves against the real SQLite store (fixture corpus, no network) that the
// two new aggregate counters come from the same stated rules as the existing
// severity bands:
//
// - `unscored` (band `unknown`) counts PUBLISHED records with no valid CNA
//   metric, using the same predicate as `selectPrimaryCvss`.
// - `secondaryOnly` adds the ADP predicate: no valid CNA, at least one valid
//   ADP metric. The reader has secondary context to inspect, never a primary.
// - `noMetric` is the rest: no valid CNA and no valid ADP metric at all.
//
// They must partition `unscored` exactly, and a cached snapshot written by an
// older aggregate version must be rejected rather than read with missing keys.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AGGREGATE_KEY,
  AGGREGATE_VERSION,
  getAggregates,
  refreshAggregates,
  secondaryCoverageSql,
} from "../src/lib/aggregates";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-aggregate-coverage-test-"));
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

interface Metric {
  origin: "CNA" | "ADP";
  version: string;
  baseScore: string;
}

function seedRecord(
  db: CveDatabase,
  cveId: string,
  options: { state?: string; metrics?: Metric[] } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, " +
          "description_lang, source_revision, created_at, updated_at) " +
          "VALUES (?, '5.1', ?, '2026-10-20T00:00:00.000Z', ?, ?, 'en', 'rev-fixture', ?, ?)",
      )
      .run(
        cveId,
        options.state ?? "PUBLISHED",
        `Title ${cveId}`,
        `Description ${cveId}`,
        STAMP,
        STAMP,
      );
    const insert = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) " +
        "VALUES (?, ?, ?, ?, 'CVSS:3.1/AV:N', ?)",
    );
    for (const [index, metric] of (options.metrics ?? []).entries()) {
      insert.run(cveId, metric.origin, metric.version, metric.baseScore, index);
    }
  });
}

/**
 * Every case the split has to separate, including the two that only an
 * invalid-metric reader would get wrong:
 *
 * 0001 valid CNA                     -> scored (critical), outside the cohort
 * 0002 ADP only                      -> secondaryOnly
 * 0003 nothing                       -> noMetric
 * 0004 invalid CNA + valid ADP       -> secondaryOnly (the CNA metric is junk)
 * 0005 invalid CNA + invalid ADP     -> noMetric
 * 0006 REJECTED with an ADP metric   -> outside every denominator
 */
function seedFixture(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0001", {
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8" }],
  });
  seedRecord(db, "CVE-2099-0002", {
    metrics: [{ origin: "ADP", version: "4.0", baseScore: "8.1" }],
  });
  seedRecord(db, "CVE-2099-0003");
  seedRecord(db, "CVE-2099-0004", {
    metrics: [
      { origin: "CNA", version: "3.1", baseScore: "11.5" },
      { origin: "ADP", version: "3.1", baseScore: "9.0" },
    ],
  });
  seedRecord(db, "CVE-2099-0005", {
    metrics: [
      { origin: "CNA", version: "3.1", baseScore: "n/a" },
      { origin: "ADP", version: "3.1", baseScore: "not-a-score" },
    ],
  });
  seedRecord(db, "CVE-2099-0006", {
    state: "REJECTED",
    metrics: [{ origin: "ADP", version: "3.1", baseScore: "7.0" }],
  });
}

describe("unscored cohort split", () => {
  it("counts the two cases from SQL rules, not from raw_json", () => {
    const db = makeDb();
    seedFixture(db);

    const snapshot = refreshAggregates(db, "2026-10-24T00:00:00.000Z");

    expect(snapshot.totals.published).toBe(5);
    expect(snapshot.severityBands.critical).toBe(1);
    expect(snapshot.totals.unscored).toBe(4);
    expect(snapshot.totals.secondaryOnly).toBe(2);
    expect(snapshot.totals.noMetric).toBe(2);
    // The live query and the snapshot agree: the cache is a speed layer, not a
    // second definition.
    expect(secondaryCoverageSql(db)).toEqual({ secondaryOnly: 2, noMetric: 2 });
  });

  it("partitions the unscored cohort exactly", () => {
    const db = makeDb();
    seedFixture(db);
    const snapshot = refreshAggregates(db);

    expect(snapshot.totals.secondaryOnly + snapshot.totals.noMetric).toBe(
      snapshot.totals.unscored,
    );
    // `unscored` is the `unknown` band by definition; both readings must hold
    // or the UI subnote would not add up to the number above it.
    expect(snapshot.severityBands.unknown).toBe(snapshot.totals.unscored);
  });

  it("rejects a snapshot written by an older aggregate version", () => {
    const db = makeDb();
    seedFixture(db);
    refreshAggregates(db);
    expect(getAggregates(db)?.version).toBe(AGGREGATE_VERSION);
    expect(AGGREGATE_VERSION).toBe(6);

    // Simulate the pre-step-2 snapshot: same key, version 5, no split counters.
    const stale = { ...(getAggregates(db) ?? {}), version: 5 };
    delete (stale as { totals?: unknown }).totals;
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO aggregate_cache (key, value_json, computed_at, source_revision, epss_score_date) " +
          "VALUES (?, ?, ?, ?, ?)",
      )
      .run(AGGREGATE_KEY, JSON.stringify(stale), STAMP, null, null);

    // A version mismatch reads as "no cache", so readers rebuild instead of
    // serving a payload whose counters would silently be undefined.
    expect(getAggregates(db)).toBeNull();

    const refreshed = refreshAggregates(db);
    expect(refreshed.version).toBe(AGGREGATE_VERSION);
    expect(refreshed.totals.secondaryOnly + refreshed.totals.noMetric).toBe(
      refreshed.totals.unscored,
    );
    expect(getAggregates(db)?.totals.secondaryOnly).toBe(2);
  });
});
