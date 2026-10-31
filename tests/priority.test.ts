// New-test justification (plan todo 11): the priority services are the first
// code that turns accepted SQLite snapshots into the five deterministic
// ranked views, so tests must prove against the real SQLite layer (not the
// pure ranking unit tests) that each view orders fixture corpora per
// docs/DATA_WORKFLOW.md, that ADP-only and v2-only records stay out of
// new-critical, that a display-rounding pair still sorts by raw probability,
// that unknown/missing values degrade to unknown (never zero), and that an
// empty corpus returns empty lists instead of errors. Fixtures use invented
// CVE-2099 IDs; nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  getAcceptedEpssDate,
  getDefaultPriority,
  getHighestForecast,
  getKevDueSoon,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../src/lib/priority";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-priority-test-"));
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
  opts: { datePublished?: string | null; state?: string } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        opts.state ?? "PUBLISHED",
        opts.datePublished === undefined ? "2026-10-20T00:00:00.000Z" : opts.datePublished,
        `Description for ${cveId}`,
        STAMP,
        STAMP,
      );
  });
}

function seedKev(db: CveDatabase, cveId: string, dateAdded = "2026-10-18"): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run(cveId, dateAdded, STAMP, STAMP);
  });
}

function seedKevRaw(db: CveDatabase, cveId: string, dateAdded: string): void {
  seedKev(db, cveId, dateAdded);
}

function seedEpss(
  db: CveDatabase,
  cveId: string,
  scoreDate: string,
  epss: string,
  model: string = MODEL,
  percentile = "0.80000",
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run(cveId, scoreDate, model, epss, percentile);
  });
}

function seedCvss(
  db: CveDatabase,
  cveId: string,
  opts: {
    origin?: string;
    version?: string;
    baseScore?: string;
    vector?: string;
    sourceOrder?: number;
  } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        opts.origin ?? "CNA",
        opts.version ?? "3.1",
        opts.baseScore ?? "9.8",
        opts.vector ?? "CVSS:3.1/AV:N",
        opts.sourceOrder ?? 0,
      );
  });
}

function ids(rows: ReadonlyArray<{ id: string }>): string[] {
  return rows.map((row) => row.id);
}

describe("priority services on SQLite (todo 11)", () => {
  it("default priority: KEV tier beats a higher scored nonmember", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedKev(db, "CVE-2099-0001");
    seedEpss(db, "CVE-2099-0002", DAY, "0.99");
    expect(ids(getDefaultPriority(db))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("default priority: actual zero outranks unknown (never coerced to 0)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0003");
    seedRecord(db, "CVE-2099-0004");
    seedEpss(db, "CVE-2099-0003", DAY, "0");
    expect(ids(getDefaultPriority(db))).toEqual(["CVE-2099-0003", "CVE-2099-0004"]);
  });

  it("default priority: equal display values sort by raw probability (regression)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0005");
    seedRecord(db, "CVE-2099-0006");
    seedEpss(db, "CVE-2099-0005", DAY, "0.12344");
    seedEpss(db, "CVE-2099-0006", DAY, "0.12341");
    expect(ids(getDefaultPriority(db))).toEqual(["CVE-2099-0005", "CVE-2099-0006"]);
  });

  it("default priority: known publication date beats unknown at equal tier/probability", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0010", { datePublished: "2026-10-20T00:00:00.000Z" });
    seedRecord(db, "CVE-2099-0011", { datePublished: null });
    seedEpss(db, "CVE-2099-0010", DAY, "0.5");
    seedEpss(db, "CVE-2099-0011", DAY, "0.5");
    expect(ids(getDefaultPriority(db))).toEqual(["CVE-2099-0010", "CVE-2099-0011"]);
  });

  it("known-exploited: newer dateAdded first; nonmembers excluded; bad dates last", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedRecord(db, "CVE-2099-0004");
    seedKev(db, "CVE-2099-0001", "2026-10-22");
    seedKev(db, "CVE-2099-0002", "2026-10-23");
    seedKevRaw(db, "CVE-2099-0004", "garbage-date");
    expect(ids(getKnownExploited(db))).toEqual([
      "CVE-2099-0002",
      "CVE-2099-0001",
      "CVE-2099-0004",
    ]);
  });

  it("kev-due-soon: due ascending with overdue first; missing/malformed excluded", () => {
    const db = makeDb();
    for (const id of ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"]) {
      seedRecord(db, id);
    }
    const stamp = "2026-10-24T00:00:00.000Z";
    db.runBoundedWrite(() => {
      const insert = db.handle.prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, due_date, recorded_at) VALUES (?, ?, ?, ?, ?)",
      );
      insert.run("CVE-2099-0001", "2026-10-20", stamp, "2026-10-25", stamp);
      insert.run("CVE-2099-0002", "2026-10-21", stamp, "2027-01-15", stamp);
      insert.run("CVE-2099-0003", "2026-10-22", stamp, null, stamp);
      insert.run("CVE-2099-0004", "2026-10-23", stamp, "not-a-date", stamp);
    });
    const items = getKevDueSoon(db);
    expect(items.map((row) => row.id)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(items[0]?.kevDueDate).toBe("2026-10-25");
    expect(getKevDueSoon(db, 1).map((row) => row.id)).toEqual(["CVE-2099-0001"]);
    expect(getKevDueSoon(db, 0)).toEqual([]);
  });

  it("highest-forecast: raw probability desc; unknown excluded; KEV is not a sort key", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedKev(db, "CVE-2099-0002");
    seedEpss(db, "CVE-2099-0001", DAY, "0.90");
    seedEpss(db, "CVE-2099-0002", DAY, "0.10");
    expect(ids(getHighestForecast(db))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("new-critical: trailing 30d window with primary modern CVSS >= 9.0, newer first", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { datePublished: "2026-10-20T00:00:00.000Z" });
    seedRecord(db, "CVE-2099-0002", { datePublished: "2026-10-22T00:00:00.000Z" });
    seedRecord(db, "CVE-2099-0003", { datePublished: "2026-09-01T00:00:00.000Z" });
    seedCvss(db, "CVE-2099-0001", { version: "3.1", baseScore: "10.0" });
    seedCvss(db, "CVE-2099-0002", { version: "3.1", baseScore: "9.1" });
    seedCvss(db, "CVE-2099-0003", { version: "3.1", baseScore: "9.8" });
    expect(ids(getNewCritical(db, "2026-10-24T00:00:00.000Z"))).toEqual([
      "CVE-2099-0002",
      "CVE-2099-0001",
    ]);
  });

  it("new-critical: T-30d inclusive, exactly T excluded", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { datePublished: "2026-09-24T00:00:00.000Z" });
    seedRecord(db, "CVE-2099-0002", { datePublished: "2026-10-24T00:00:00.000Z" });
    seedCvss(db, "CVE-2099-0001", { version: "3.1", baseScore: "9.8" });
    seedCvss(db, "CVE-2099-0002", { version: "3.1", baseScore: "9.8" });
    expect(ids(getNewCritical(db, "2026-10-24T00:00:00.000Z"))).toEqual(["CVE-2099-0001"]);
  });

  it("new-critical: ADP-only records are ineligible (secondary metrics never promoted)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { datePublished: "2026-10-20T00:00:00.000Z" });
    seedCvss(db, "CVE-2099-0001", {
      origin: "ADP",
      version: "4.0",
      baseScore: "10.0",
      vector: "CVSS:4.0/AV:N",
    });
    expect(getNewCritical(db, "2026-10-24T00:00:00.000Z")).toEqual([]);
  });

  it("new-critical: v2-only records are legacy-scored and ineligible", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { datePublished: "2026-10-20T00:00:00.000Z" });
    seedCvss(db, "CVE-2099-0001", {
      origin: "CNA",
      version: "2.0",
      baseScore: "10.0",
      vector: "AV:N/AC:L",
    });
    expect(getNewCritical(db, "2026-10-24T00:00:00.000Z")).toEqual([]);
  });

  it("rising-forecast: exact d/d-7 same-model positive deltas, delta desc then current p", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedEpss(db, "CVE-2099-0001", DAY_MINUS_7, "0.10");
    seedEpss(db, "CVE-2099-0001", DAY, "0.18");
    seedEpss(db, "CVE-2099-0002", DAY_MINUS_7, "0.20");
    seedEpss(db, "CVE-2099-0002", DAY, "0.28");
    const rows = getRisingForecast(db, DAY);
    expect(rows.map((row) => row.item.id)).toEqual(["CVE-2099-0002", "CVE-2099-0001"]);
    expect(rows[0]?.deltaPp).toBe("8");
  });

  it("rising-forecast: model transitions and missing history are ineligible, never interpolated", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedEpss(db, "CVE-2099-0001", DAY_MINUS_7, "0.10", "model-a");
    seedEpss(db, "CVE-2099-0001", DAY, "0.80", "model-b");
    seedEpss(db, "CVE-2099-0002", DAY, "0.50");
    seedEpss(db, "CVE-2099-0003", DAY_MINUS_7, "0.10");
    seedEpss(db, "CVE-2099-0003", DAY, "0.05");
    expect(getRisingForecast(db, DAY)).toEqual([]);
  });

  it("rising-forecast: defaults to the accepted EPSS date when no date is passed", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedEpss(db, "CVE-2099-0001", DAY_MINUS_7, "0.10");
    seedEpss(db, "CVE-2099-0001", DAY, "0.18");
    expect(getAcceptedEpssDate(db)).toBe(DAY);
    const rows = getRisingForecast(db);
    expect(rows.map((row) => row.item.id)).toEqual(["CVE-2099-0001"]);
  });

  it("adversarial: malformed values degrade to unknown buckets, never zero, never throw", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { datePublished: "not-a-date" });
    seedRecord(db, "CVE-2099-0002", { datePublished: null });
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
        )
        .run("CVE-2099-0001", DAY, MODEL, "NaN", "0.5");
    });
    let ordered: Array<{ id: string }> = [];
    let forecast: Array<{ id: string }> = [];
    let exploited: Array<{ id: string }> = [];
    expect(() => {
      ordered = getDefaultPriority(db);
    }).not.toThrow();
    expect(() => {
      forecast = getHighestForecast(db);
    }).not.toThrow();
    expect(() => {
      exploited = getKnownExploited(db);
    }).not.toThrow();
    // The malformed EPSS row is unknown: a real zero still outranks it.
    seedRecord(db, "CVE-2099-0003", { datePublished: null });
    seedEpss(db, "CVE-2099-0003", DAY, "0");
    expect(ids(getDefaultPriority(db))[0]).toBe("CVE-2099-0003");
    expect(ordered).toHaveLength(2);
    expect(forecast).toEqual([]);
    expect(exploited).toEqual([]);
  });

  it("adversarial: empty corpus returns empty lists, not errors", () => {
    const db = makeDb();
    expect(getDefaultPriority(db)).toEqual([]);
    expect(getKnownExploited(db)).toEqual([]);
    expect(getHighestForecast(db)).toEqual([]);
    expect(getNewCritical(db, "2026-10-24T00:00:00.000Z")).toEqual([]);
    expect(getRisingForecast(db, DAY)).toEqual([]);
    expect(getRisingForecast(db)).toEqual([]);
    expect(getAcceptedEpssDate(db)).toBeNull();
  });

  it("adversarial: REJECTED records never appear in any view", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", { state: "REJECTED" });
    seedKev(db, "CVE-2099-0001", "2026-10-23");
    seedEpss(db, "CVE-2099-0001", DAY, "0.99");
    seedEpss(db, "CVE-2099-0001", DAY_MINUS_7, "0.01");
    seedCvss(db, "CVE-2099-0001", { version: "3.1", baseScore: "10.0" });
    expect(getDefaultPriority(db)).toEqual([]);
    expect(getKnownExploited(db)).toEqual([]);
    expect(getHighestForecast(db)).toEqual([]);
    expect(getNewCritical(db, "2026-10-24T00:00:00.000Z")).toEqual([]);
    expect(getRisingForecast(db, DAY)).toEqual([]);
  });
});
