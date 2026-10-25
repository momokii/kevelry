// Regression test (task 36): the overview page blocked the event loop on a
// ~395k-row corpus because toSummaryItems built one 395k-placeholder IN (...)
// query (SqliteError: too many SQL variables) plus a huge per-request
// allocation. Seeds a synthetic 50,000-row scored corpus in a temp DB (no
// network, invented CVE-2099 IDs) and proves: (a) the overview summary builds
// without a SqliteError, (b) readTitles stays chunked for multi-thousand id
// lists, (c) the summary build stays within a generous 5s ceiling, and
// (d) the limit param preserves exact ordering semantics.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { getHighestForecast } from "../src/lib/priority";
import {
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../src/lib/priority";
import {
  loadOverviewData,
  OVERVIEW_SUMMARY_LIMIT,
  readTitles,
} from "../src/components/overview/loadOverview";

const tempDirs: string[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const DAY = "2026-10-24";
const DAY_MINUS_7 = "2026-10-17";
const MODEL = "v2026.06.15";
const ROWS = 50_000;

function epssFor(index: number): string {
  if (index % 5000 === 0) return "0.99999";
  return (0.00001 + ((index * 7919) % 99999) / 100000).toFixed(5);
}

function makeDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-overview-scale-"));
  tempDirs.push(dir);
  return dir;
}

function seedScaleCorpus(dir: string): void {
  const db = openDatabase({ dataDir: dir });
  try {
    const insertRecord = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const insertEpss = db.handle.prepare(
      "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    );
    const insertCvss = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
    );
    const insertKev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    );
    const tx = db.handle.transaction(() => {
      for (let index = 0; index < ROWS; index += 1) {
        const cveId = `CVE-2099-${String(index).padStart(5, "0")}`;
        insertRecord.run(
          cveId,
          "5.1",
          "PUBLISHED",
          index % 7000 === 0 ? null : "2026-10-20T00:00:00.000Z",
          `Title for ${cveId}`,
          `Description for ${cveId}`,
          STAMP,
          STAMP,
        );
        insertEpss.run(cveId, DAY, MODEL, epssFor(index), "0.80000");
        if (index < 100) {
          insertCvss.run(cveId, "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
        }
        if (index < 2000) {
          insertEpss.run(
            cveId,
            DAY_MINUS_7,
            MODEL,
            (Number(epssFor(index)) - 0.01).toFixed(5),
            "0.80000",
          );
        }
      }
      for (let index = 1; index <= 9; index += 1) {
        insertKev.run(
          cveIdAt(index),
          `2026-10-${String(10 + index).padStart(2, "0")}`,
          STAMP,
          STAMP,
        );
      }
      insertKev.run(cveIdAt(11), "not-a-date", STAMP, STAMP);
      insertCvss.run(cveIdAt(150), "ADP", "3.1", "9.9", "CVSS:3.1/AV:N", 0);
      insertCvss.run(cveIdAt(151), "CNA", "2.0", "9.8", "AV:N", 0);
      for (let index = 2000; index < 2010; index += 1) {
        insertEpss.run(cveIdAt(index), DAY_MINUS_7, "v1999.01.01", "0.90000", "0.80000");
      }
      insertEpss.run(cveIdAt(3000), DAY, "v2099", "0.00001", "0.80000");
      insertEpss.run(cveIdAt(3000), DAY_MINUS_7, "v2099", "0.00000", "0.80000");
      insertEpss.run(cveIdAt(ROWS - 1), DAY, "v2099", "garbage", "0.80000");
    });
    tx();
  } finally {
    db.close();
  }
}

function cveIdAt(index: number): string {
  return `CVE-2099-${String(index).padStart(5, "0")}`;
}

let sharedDir = "";

beforeAll(() => {
  sharedDir = makeDir();
  seedScaleCorpus(sharedDir);
}, 60000);

afterAll(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

describe("overview at production scale (task 36)", () => {
  it("builds the summary over 50k scored rows without SqliteError and under 5s", () => {
    const dir = sharedDir;
    const started = performance.now();
    const data = loadOverviewData(dir, STAMP);
    const elapsedMs = performance.now() - started;
    expect(data).not.toBeNull();
    expect(data?.publishedTotal).toBe(ROWS);
    for (const summary of data?.summaries ?? []) {
      expect(summary.items.length).toBeLessThanOrEqual(OVERVIEW_SUMMARY_LIMIT);
    }
    const highest = (data?.summaries ?? []).find((s) => s.key === "highest-forecast");
    expect(highest?.items.length).toBe(OVERVIEW_SUMMARY_LIMIT);
    expect(elapsedMs).toBeLessThan(5000);
  });

  it("readTitles stays chunked for a 5,000-id call", () => {
    const dir = sharedDir;
    const db: CveDatabase = openDatabase({ dataDir: dir });
    try {
      const ids = Array.from({ length: 5000 }, (_, index) => cveIdAt(index));
      ids.push("CVE-2099-99999");
      const titles = readTitles(db, ids);
      expect(titles.size).toBe(5001);
      expect(titles.get(cveIdAt(0))).toBe(`Title for ${cveIdAt(0)}`);
      expect(titles.get(cveIdAt(4999))).toBe(`Title for ${cveIdAt(4999)}`);
      expect(titles.get("CVE-2099-99999")).toBe("CVE-2099-99999");
    } finally {
      db.close();
    }
  });

  it("limit param matches slice-after-full-order exactly", () => {
    const dir = sharedDir;
    const db: CveDatabase = openDatabase({ dataDir: dir });
    try {
      const fullHighest = getHighestForecast(db);
      expect(fullHighest.length).toBeGreaterThan(ROWS - 10);
      expect(getHighestForecast(db, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullHighest.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      const fullKev = getKnownExploited(db);
      expect(fullKev.length).toBe(10);
      expect(fullKev[fullKev.length - 1]?.id).toBe(cveIdAt(11));
      expect(getKnownExploited(db, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullKev.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      const fullCritical = getNewCritical(db, STAMP);
      expect(fullCritical.length).toBeGreaterThan(0);
      expect(getNewCritical(db, STAMP, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullCritical.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      expect(fullCritical.map((row) => row.id)).not.toContain(cveIdAt(150));
      expect(fullCritical.map((row) => row.id)).not.toContain(cveIdAt(151));
      const fullRising = getRisingForecast(db);
      expect(fullRising.length).toBeGreaterThan(0);
      const cappedRising = getRisingForecast(db, undefined, OVERVIEW_SUMMARY_LIMIT);
      expect(cappedRising.map((row) => row.item.id)).toEqual(
        fullRising.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.item.id),
      );
      expect(cappedRising.map((row) => row.deltaPp)).toEqual(
        fullRising.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.deltaPp),
      );
    } finally {
      db.close();
    }
  }, 120000);
});
